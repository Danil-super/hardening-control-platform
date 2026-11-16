# Резервирование и восстановление HCP

Инструкция для основного `docker-compose.yml` на Ubuntu. Все команды выполняются в **Bash из каталога проекта на Ubuntu**, если не сказано иное. В примерах используется `sudo docker`; сами команды не запускаются на Astra.

| Что сохраняется | Где находится | Назначение |
| --- | --- | --- |
| Данные HCP | Volume, смонтированный в `/var/lib/hcp` | SQLite, история, отчёты, SBOM, политики источников/профилей, рабочий inventory, known_hosts, **индивидуальные приватные ключи в `ssh-host-keys/`**, cache Trivy |
| Настройки и прежний ключ | `.env`, `secrets/`, начальный `ansible/inventory.ini` | Вход, подпись журнала, исходная конфигурация; старый общий ключ, если он использовался |
| Образ и версия HCP | Образ запущенного контейнера, commit Git | Восстановление той же программы без повторной сборки из сети |
| Firewall-транзакции Astra | `/var/lib/hcp-backups` **на каждой Astra** | Архив конфигурации firewall и метаданные для отката конкретного изменения |
| Полная Astra | Снимок/резервная копия ВМ или диска | Восстановление ОС и приложений; средствами HCP не создаётся |

Индивидуальные ключи целиком входят в `runtime.tar.gz`; архив `settings.tar.gz` их не заменяет. Приватные ключи не защищены отдельной парольной фразой: храните архивы с правами `600` в защищённом хранилище. После восстановления каталоги ключей должны иметь права `700`, приватные файлы — `600`; пересоздавать пары нельзя.

Рабочий inventory хранится в volume; одного файла `ansible/inventory.ini` из Git-каталога недостаточно. Фактическое имя volume может содержать префикс Compose-проекта: следующие команды используют сервис и точку монтирования, а не предполагаемое имя volume.

## 1. Согласованная копия HCP

Дождитесь окончания настройки SSH-ключей, ручных аудитов и изменений. На время копирования панель будет остановлена. Каталог копии должен находиться **вне Git-репозитория**, на диске с местом под runtime и Docker-образ. Он содержит секреты; перенесите его в своё защищённое хранилище вне Ubuntu после проверки.

Замените путь в первой строке на свой; родительский каталог должен существовать, а каталог новой копии — ещё нет. Блок выполняется целиком; при ошибке он останавливается. Если ошибка произошла после остановки HCP, причина разбирается до объявления копии готовой; команды запуска приведены отдельно ниже. После любой неуспешной попытки восстановите состояние таймеров по её `active-timers.txt` перед новой попыткой.

```bash
HCP_BACKUP_DIR="/полный/путь/вне/репозитория/hcp-$(date -u +%Y%m%dT%H%M%SZ)"
export HCP_BACKUP_DIR
(
  set -euo pipefail
  umask 077
  mkdir -m 700 "$HCP_BACKUP_DIR"
  git diff --quiet
  git diff --cached --quiet
  git rev-parse HEAD > "$HCP_BACKUP_DIR/commit.txt"
  uname -m > "$HCP_BACKUP_DIR/architecture.txt"
  : > "$HCP_BACKUP_DIR/active-timers.txt"
  for unit in hcp-scheduled-audit.timer hcp-deep-audit.timer; do
    if systemctl is-active --quiet "$unit"; then
      printf '%s\n' "$unit" >> "$HCP_BACKUP_DIR/active-timers.txt"
      sudo systemctl stop "$unit"
    fi
  done
  for unit in hcp-scheduled-audit.service hcp-deep-audit.service; do
    if systemctl is-active --quiet "$unit"; then
      echo "Дождитесь завершения $unit и повторите копирование в новый каталог." >&2
      exit 1
    fi
  done
  HCP_CONTAINER_ID=$(sudo docker compose ps -q hcp)
  test -n "$HCP_CONTAINER_ID"
  sudo docker inspect --format '{{.Image}}' "$HCP_CONTAINER_ID" > "$HCP_BACKUP_DIR/image-id.txt"
  HCP_IMAGE_COMMIT=$(sudo docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$(cat "$HCP_BACKUP_DIR/image-id.txt")")
  if [[ "$HCP_IMAGE_COMMIT" =~ ^[a-f0-9]{40}$ ]]; then
    git cat-file -e "$HCP_IMAGE_COMMIT^{commit}"
    printf '%s\n' "$HCP_IMAGE_COMMIT" > "$HCP_BACKUP_DIR/commit.txt"
  fi
  sudo docker compose stop --timeout 60 hcp
  sudo docker run --rm -i --network none --user node \
    --volumes-from "$HCP_CONTAINER_ID" --entrypoint python3 \
    "$(cat "$HCP_BACKUP_DIR/image-id.txt")" - <<'PY'
from pathlib import Path
import sqlite3
root = Path('/var/lib/hcp')
db_path = root / 'hcp.sqlite'
assert db_path.is_file() and not db_path.is_symlink()
db = sqlite3.connect(str(db_path))
try:
    assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    assert db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
finally:
    db.close()
assert not (root / 'hcp.sqlite-wal').exists()
assert not (root / 'hcp.sqlite-shm').exists()
PY
  sudo docker run --rm --network none --user 0 \
    --volumes-from "$HCP_CONTAINER_ID:ro" --entrypoint tar \
    "$(cat "$HCP_BACKUP_DIR/image-id.txt")" \
    -C /var/lib/hcp -czf - . > "$HCP_BACKUP_DIR/runtime.tar.gz"
  tar -czf "$HCP_BACKUP_DIR/settings.tar.gz" .env secrets ansible/inventory.ini
  sudo docker image save "$(cat "$HCP_BACKUP_DIR/image-id.txt")" | gzip > "$HCP_BACKUP_DIR/image.tar.gz"
  gzip -t "$HCP_BACKUP_DIR/runtime.tar.gz" "$HCP_BACKUP_DIR/image.tar.gz"
  tar -tzf "$HCP_BACKUP_DIR/settings.tar.gz" >/dev/null
  (
    cd "$HCP_BACKUP_DIR"
    sha256sum runtime.tar.gz settings.tar.gz image.tar.gz commit.txt image-id.txt architecture.txt active-timers.txt > SHA256SUMS
    sha256sum -c SHA256SUMS
  )
)
```

`git diff` требует сохранённых изменений отслеживаемого кода. `.env` и `secrets` не входят в Git, но попадают в отдельный архив. Образ сохраняется по ID фактически запущенного контейнера. Не обновляйте код/образ и не редактируйте настройки во время копирования. Если ранее меняли параметры установки или использовали Compose override, отдельно сохраните эти файлы и настройку systemd.

Возобновите работу после успешной копии или после разбора ошибки. Используйте `HCP_BACKUP_DIR` именно той попытки, которая остановила таймеры:

```bash
sudo docker compose up -d --no-build --wait --wait-timeout 180 hcp
while IFS= read -r unit; do
  sudo systemctl start "$unit"
done < "$HCP_BACKUP_DIR/active-timers.txt"
sudo docker compose ps
```

Убедитесь в `healthy` и наличии прежних отчётов. Копирование tar проверяет формат/байты; пригодность резервной копии подтверждает пробное восстановление по следующему разделу.

## 1.1. Автоматическая проверка архивов до восстановления

Если образ содержит `org.opencontainers.image.revision`, `commit.txt` фиксирует
именно её, а не более новый локальный коммит документации. Для образа без этой
метки кодовый commit нужно сверить вручную с процедурой сборки: чистое рабочее
дерево не доказывает, что запущен образ этого HEAD. Метка revision сама по себе
не заменяет проверку содержимого и происхождения образа.

Остановка приложения сама по себе не гарантирует отсутствие SQLite WAL.
Checkpoint выше переносит зафиксированные транзакции в основной файл и закрывает
последнее соединение. При busy, повреждении или оставшихся sidecar-файлах
копирование прекращается: **нельзя удалять WAL/SHM вручную**, открывать только
основной файл как immutable или ослаблять проверку восстановления. Исходные
DB/WAL можно дополнительно сохранить отдельно перед обслуживанием. В фактическом
прогоне RC `1306a2a` до и после checkpoint совпали логические данные всех 14 таблиц.

После сохранения копии и **до запуска восстановления** проверяйте отдельным
read-only инструментом полный набор архивов, список контрольных сумм и пути
внутри TAR. Это закрывает важный этап проверки резервных файлов, но не заменяет
реальный прогон резервирования/восстановления.

```bash
python3 deployment/tests/verify_backup_bundle.py \
  --backup-dir "$HCP_BACKUP_DIR"
```

Проверяющий инструмент:

- Требует существующий приватный каталог с правами без доступа group/other.
  Не следует symlink на каталог и отдельные файлы.
- Требует **ровно семь** записей `SHA256SUMS` для
  `runtime.tar.gz`, `settings.tar.gz`, `image.tar.gz`,
  `commit.txt`, `image-id.txt`, `architecture.txt`,
  `active-timers.txt`. Допускается пустой `active-timers.txt`, как в
  штатной инструкции. Проверяются полные хеши, а не только имена.
- Анализирует **без распаковки** TAR: запрещает абсолютные пути, `..`,
  опасные link-targets, специальные файлы, повторяющиеся пути и чрезмерно
  большие архивные записи. В runtime ожидаются фактическая `hcp.sqlite`,
  рабочие `inventory.ini`, `known_hosts`; в settings — `.env`,
  `ansible/inventory.ini` и каталог `secrets`.
- Проверяет сохранённый Git commit, ID Docker-образа и список активных таймеров
  в ограниченных текстовых файлах. Не запускает Docker, SSH, SQL,
  восстановление, запросы к сети или команды на Astra.
- Возвращает статус `structurally-verified-not-restored` и выводит только
  хеши, метаданные и статистику архива — **не содержимое секретов,
  inventory, приватные SSH-ключи и данные отчётов**. Отказ завершает
  программу кодом 1 без изменения копии.

`SHA256SUMS` лежит рядом с архивами и может быть подменён вместе с ними.
Для защиты от одновременной подмены храните **отдельно** заранее проверенный
полный SHA-256 файла `SHA256SUMS`. Тогда используйте:

```bash
python3 deployment/tests/verify_backup_bundle.py \
  --backup-dir "$HCP_BACKUP_DIR" \
  --expected-manifest-sha256 ВАШ_НЕЗАВИСИМО_СОХРАНЁННЫЙ_SHA256 \
  --output /отдельный/закрытый/каталог/new-preflight.json
```

Файл `new-preflight.json` создаётся впервые с правами `0600`; нельзя
перезаписывать существующий протокол. Сам успешный SHA-256 не подтверждает
подпись владельца или фактическое восстановление SQLite. Если база SQLite
повреждена внутри архива, формат TAR может оставаться корректным — это
выявляется **только дополнительной проверкой восстановленного экземпляра**,
включая `PRAGMA integrity_check`, HMAC-цепочку журнала, ключи SSH, старые
отчёты, сессии, а также отдельный новый аудит.

Не размещайте резервные копии или приватные протоколы в GitHub, CI или чатах.

После распаковки исходного runtime **до запуска** восстановленного HCP выполните [побайтовую сверку критичных данных и независимую read-only проверку SQLite](post-restore-acceptance.md). Для этой проверки нужна другая изолированная Ubuntu и подтверждённо остановленная восстановленная панель. Это не проверка входа, HMAC-цепочки, отзывов старых сессий или удалённого firewall.

## Единый read-only контроль перед включением восстановленной панели

На **новой изолированной Ubuntu** после распаковки и при остановленном HCP
можно выполнить [одну сводную проверку резервного архива, восстановленных
критичных байтов, SQLite и HMAC](operator-restore-readiness.md).
Для доверенного вывода нужны **внешне сохранённые** SHA-256 манифеста,
HMAC последнего события и число событий оригинального журнала.
Положительный локальный preflight не заменяет новый вход, SSH и firewall
rollback на реальном стенде.

## 2. Восстановление HCP на отдельной Ubuntu

Для первого испытания используйте **другую Ubuntu-ВМ той же архитектуры**, с Docker и Git, без существующего HCP и его volume. Исходную установку сохраняйте. Этот порядок не затирает данные работающего HCP. Сеть восстановленной ВМ должна достигать Astra, когда вы перейдёте к проверке SSH.

Перенесите каталог резервной копии. До установки секретов убедитесь, что это ваша доверенная копия, затем задайте её абсолютный путь и проверьте контрольные суммы:

```bash
HCP_BACKUP_DIR="/полный/путь/к/сохранённой/копии"
export HCP_BACKUP_DIR
(cd "$HCP_BACKUP_DIR" && sha256sum -c SHA256SUMS)
cat "$HCP_BACKUP_DIR/architecture.txt"
uname -m
```

При несовпадении суммы или архитектуры остановитесь. Следующий блок требует интернета только для клонирования Git-репозитория. В изолированную сеть заранее перенесите checkout указанного commit. Сам образ берётся из копии:

```bash
git clone https://github.com/Danil-super/hardening-control-platform.git
cd hardening-control-platform
git checkout --detach "$(cat "$HCP_BACKUP_DIR/commit.txt")"
tar -xzf "$HCP_BACKUP_DIR/settings.tar.gz"
chmod 700 secrets
chmod 600 .env secrets/known_hosts
if [ -f secrets/hcp-control ]; then chmod 600 secrets/hcp-control; fi
sudo docker image load -i "$HCP_BACKUP_DIR/image.tar.gz"
sudo docker image tag "$(cat "$HCP_BACKUP_DIR/image-id.txt")" hcp-restored:local
cat > compose.restore.yml <<'YAML'
services:
  hcp:
    image: hcp-restored:local
YAML
sudo docker compose -f docker-compose.yml -f compose.restore.yml config --quiet
```

При переносе между разными Docker image stores команда `image tag` может не
найти прежний ID: classic store использует config digest, а containerd store
может показывать digest OCI-манифеста. Это наблюдалось при восстановлении на
Docker 29. **Не выбирайте произвольный образ по имени или только по revision label.**
В проверенном архиве сверьте SHA metadata blobs и связь `manifest.config.digest`
с исходным config digest; затем сравните конфигурацию исполнения и весь список
`rootfs.diff_ids` с `Config` / `RootFS.Layers` загруженного образа. Только после
подтверждения этой связи присваивайте ему `hcp-restored:local` и продолжайте.
Оба digest должны остаться в протоколе. Формат цепочки описан в
[документации Docker](https://docs.docker.com/build/metadata/annotations/).

Проверьте `.env`: панель должна оставаться на нужном локальном адресе; при новом IP Ubuntu обновите `HCP_CONTROL_IPS`. **Сохраните прежние ключ подписи журнала, пароль, секреты и все SSH-ключи.** Генерация новых значений не является восстановлением.

Загрузите runtime в новый volume. Проверка перед распаковкой откажет, если в нём уже есть файлы или ссылки; пустые каталоги из образа допустимы:

```bash
sudo docker compose -f docker-compose.yml -f compose.restore.yml run --rm -T \
  --no-deps --pull never --user 0 --entrypoint sh hcp -ec '
    if [ -n "$(find /var/lib/hcp -mindepth 1 ! -type d -print -quit)" ]; then
      echo "Volume уже содержит данные: восстановление остановлено." >&2
      exit 1
    fi
    tar -C /var/lib/hcp -xzf -
    find -P /var/lib/hcp -type d -exec chmod u+rwx,go-rwx {} +
    find -P /var/lib/hcp -type f -exec chmod go-rwx {} +
  ' < "$HCP_BACKUP_DIR/runtime.tar.gz"
```

Права закрываются только в новом восстановленном volume; символьные ссылки
`find -P` не обходит. Это не меняет байты JSON, SSH-ключей или журнала. Среди
реальных исторических отчётов встречались файлы с режимом `0644`: побайтовое
совпадение не отменяет отдельного требования приватных прав.

До запуска обязательны [read-only preflight с внешними pins](operator-restore-readiness.md)
и [отзыв скопированных сессий](restored-admin-session-revocation.md). Исходный контроллер
должен быть изолирован либо восстановленная копия должна быть отсечена от рабочей
сети, чтобы две установки с теми же ключами не управляли одним хостом одновременно.
Доступ к Astra открывается отдельно для согласованной SSH/rollback-приёмки.
Продолжайте только при успешных проверках и коде завершения `0`:

```bash
sudo docker compose -f docker-compose.yml -f compose.restore.yml up -d --no-build --wait --wait-timeout 180 hcp
sudo docker compose -f docker-compose.yml -f compose.restore.yml ps
sudo docker compose -f docker-compose.yml -f compose.restore.yml logs --tail=80 hcp
```

Проверьте вход, список хостов, старые отчёты, журнал, политики OVAL/OpenSCAP и отпечатки индивидуальных ключей в настройках хостов. Проверьте SSH каждого восстановленного подключения и новый аудит одной Astra. Обнаруженные firewall-архивы должны по-прежнему находиться на исходной Astra; восстановление Ubuntu не восстанавливает их автоматически.

Для этой восстановленной установки продолжайте использовать оба `-f` до отдельного обновления: override выбирает сохранённый образ. `git checkout --detach` фиксирует код из копии; перед будущим обновлением сначала сделайте новую копию, перейдите на `main`, получите актуальные изменения и соберите новый образ обычным Compose без `compose.restore.yml`. Расписание на новой машине восстановите отдельно по [инструкции systemd](../deployment/README.md#периодический-аудит-через-systemd), после ручного прогона и проверки `WorkingDirectory`.

## 3. Резервирование Astra и дополнительных сервисов

Архив HCP выше не включает `/var/lib/hcp-backups`, OVAL XML и системные файлы удалённых хостов. Сохраняйте их через резервирование самой Astra. Снимок ВМ нужен до контролируемых изменений; способ его создания и восстановления зависит от гипервизора. Копия firewall не заменяет снимок ОС и не восстанавливает пакеты или данные приложений.

Для отката firewall через HCP нужны одновременно запись транзакции в SQLite, исходная SSH-идентичность хоста и архив с `metadata.json` на этой Astra. Проверяются machine-id, ID транзакции, backend и SHA-256. При потере SSH используйте консоль/резервную копию ВМ; автоматического восстановления связи по таймеру нет.

При включённом Dependency-Track отдельно резервируйте согласованное состояние PostgreSQL и `dependency-track-data` с ключами шифрования. Greenbone и его feeds/БД также резервируются отдельно. **Команды разделов 1–2 проверяют и восстанавливают только HCP**, они не являются полной копией дополнительных сервисов.

Основа Docker-процедуры: [одноразовые команды Compose](https://docs.docker.com/reference/cli/docker/compose/run/) и [резервирование volumes](https://docs.docker.com/engine/storage/volumes/#back-up-restore-or-migrate-data-volumes). Локальный разбор команд не заменяет реального испытания восстановления; его нужно выполнить на своём стенде до использования копии как единственного способа восстановления.

Исторический контроль 11 сентября 2026 года проверил синтаксис Bash, пути и tar
на временном наборе SQLite-файлов; Docker в нём не запускался. 6 ноября для
`1306a2a` выполнено восстановление настоящего HCP в отдельную Ubuntu KVM-ВМ,
включая byte/HMAC-проверки, сессии, PDF и архивы. Выявлены необходимость checkpoint,
приватных прав старых файлов и сопоставления config/manifest digest. Это проверка
описанных компонентов, не аттестация всех команд для любой установки. Точные
границы и открытые пункты: [текущий статус](release-status.md).
