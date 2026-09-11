# Резервирование и восстановление HCP

Инструкция для основного `docker-compose.yml` на Ubuntu. Все команды выполняются в **Bash из каталога проекта на Ubuntu**, если не сказано иное. В примерах используется `sudo docker`; сами команды не запускаются на Astra.

| Что сохраняется | Где находится | Назначение |
| --- | --- | --- |
| Данные HCP | Volume, смонтированный в `/var/lib/hcp` | SQLite, история, отчёты, SBOM, политики источников/профилей, рабочий inventory, known_hosts, cache Trivy |
| Настройки и ключ | `.env`, `secrets/`, начальный `ansible/inventory.ini` | Вход, подпись журнала, SSH-идентичность, исходная конфигурация |
| Образ и версия HCP | Образ запущенного контейнера, commit Git | Восстановление той же программы без повторной сборки из сети |
| Firewall-транзакции Astra | `/var/lib/hcp-backups` **на каждой Astra** | Архив конфигурации firewall и метаданные для отката конкретного изменения |
| Полная Astra | Снимок/резервная копия ВМ или диска | Восстановление ОС и приложений; средствами HCP не создаётся |

Рабочий inventory хранится в volume; одного файла `ansible/inventory.ini` из Git-каталога недостаточно. Фактическое имя volume может содержать префикс Compose-проекта: следующие команды используют сервис и точку монтирования, а не предполагаемое имя volume.

## 1. Согласованная копия HCP

Дождитесь окончания ручных аудитов и изменений. На время копирования панель будет остановлена. Каталог копии должен находиться **вне Git-репозитория**, на диске с местом под runtime и Docker-образ. Он содержит секреты; перенесите его в своё защищённое хранилище вне Ubuntu после проверки.

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
  sudo docker compose stop --timeout 60 hcp
  sudo docker compose run --rm -T --no-deps --pull never --user 0 --entrypoint tar \
    hcp -C /var/lib/hcp -czf - . > "$HCP_BACKUP_DIR/runtime.tar.gz"
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
chmod 600 .env secrets/hcp-control secrets/known_hosts
sudo docker image load -i "$HCP_BACKUP_DIR/image.tar.gz"
sudo docker image tag "$(cat "$HCP_BACKUP_DIR/image-id.txt")" hcp-restored:local
cat > compose.restore.yml <<'YAML'
services:
  hcp:
    image: hcp-restored:local
YAML
sudo docker compose -f docker-compose.yml -f compose.restore.yml config --quiet
```

Проверьте `.env`: панель должна оставаться на нужном локальном адресе; при новом IP Ubuntu обновите `HCP_CONTROL_IPS`. **Сохраните прежние ключ подписи журнала, пароль, секреты и SSH-ключ.** Генерация новых значений не является восстановлением.

Загрузите runtime в новый volume. Проверка перед распаковкой откажет, если в нём уже есть файлы или ссылки; пустые каталоги из образа допустимы:

```bash
sudo docker compose -f docker-compose.yml -f compose.restore.yml run --rm -T \
  --no-deps --pull never --user 0 --entrypoint sh hcp -ec '
    if [ -n "$(find /var/lib/hcp -mindepth 1 ! -type d -print -quit)" ]; then
      echo "Volume уже содержит данные: восстановление остановлено." >&2
      exit 1
    fi
    exec tar -C /var/lib/hcp -xzf -
  ' < "$HCP_BACKUP_DIR/runtime.tar.gz"
```

Продолжайте только при коде завершения `0`:

```bash
sudo docker compose -f docker-compose.yml -f compose.restore.yml up -d --no-build --wait --wait-timeout 180 hcp
sudo docker compose -f docker-compose.yml -f compose.restore.yml ps
sudo docker compose -f docker-compose.yml -f compose.restore.yml logs --tail=80 hcp
```

Проверьте вход, список хостов, старые отчёты, журнал, политики OVAL/OpenSCAP и fingerprint публичного ключа HCP. Затем выполните только проверку SSH и новый аудит одной Astra. Обнаруженные firewall-архивы должны по-прежнему находиться на исходной Astra; восстановление Ubuntu не восстанавливает их автоматически.

Для этой восстановленной установки продолжайте использовать оба `-f` до отдельного обновления: override выбирает сохранённый образ. `git checkout --detach` фиксирует код из копии; перед будущим обновлением сначала сделайте новую копию, перейдите на `main`, получите актуальные изменения и соберите новый образ обычным Compose без `compose.restore.yml`. Расписание на новой машине восстановите отдельно по [инструкции systemd](../deployment/README.md#периодический-аудит-через-systemd), после ручного прогона и проверки `WorkingDirectory`.

## 3. Резервирование Astra и дополнительных сервисов

Архив HCP выше не включает `/var/lib/hcp-backups`, OVAL XML и системные файлы удалённых хостов. Сохраняйте их через резервирование самой Astra. Снимок ВМ нужен до контролируемых изменений; способ его создания и восстановления зависит от гипервизора. Копия firewall не заменяет снимок ОС и не восстанавливает пакеты или данные приложений.

Для отката firewall через HCP нужны одновременно запись транзакции в SQLite, исходная SSH-идентичность хоста и архив с `metadata.json` на этой Astra. Проверяются machine-id, ID транзакции, backend и SHA-256. При потере SSH используйте консоль/резервную копию ВМ; автоматического восстановления связи по таймеру нет.

При включённом Dependency-Track отдельно резервируйте согласованное состояние PostgreSQL и `dependency-track-data` с ключами шифрования. Greenbone и его feeds/БД также резервируются отдельно. **Команды разделов 1–2 проверяют и восстанавливают только HCP**, они не являются полной копией дополнительных сервисов.

Основа Docker-процедуры: [одноразовые команды Compose](https://docs.docker.com/reference/cli/docker/compose/run/) и [резервирование volumes](https://docs.docker.com/engine/storage/volumes/#back-up-restore-or-migrate-data-volumes). Локальный разбор команд не заменяет реального испытания восстановления; его нужно выполнить на своём стенде до использования копии как единственного способа восстановления.

11 сентября 2026 года проверены синтаксис Bash-блоков, соответствие путей конфигурации проекта и передача tar через stdin/stdout на временном наборе файлов с SQLite. После распаковки совпали хэши файлов, содержимое таблицы и `PRAGMA integrity_check=ok`. Этот контроль не запускал Docker и не восстанавливал настоящую рабочую установку HCP; полный цикл Docker-восстановления по этой новой инструкции пока не подтверждён.
