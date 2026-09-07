# Точный аудит: OpenSCAP, Trivy, Greenbone и Dependency-Track

Эти четыре контура дополняют SSH-проверки Ansible, а не заменяют друг друга. Платформа хранит их раздельными JSON-отчётами с источником, временем и техническими доказательствами. Одинаковые CVE из разных баз не суммируются в один «риск-скор»: это предотвращает ложное завышение приоритета.

| Контур | Что подтверждает | Где выполняется | Результат в HCP |
| --- | --- | --- | --- |
| OpenSCAP + SSG | Соответствие конкретному базовому профилю | На подготовленной целевой ВМ | Правила profile: pass/fail/manual |
| Trivy | CVE по инвентарю пакетов и CycloneDX SBOM | В контейнере control node | CVE, версия пакета, фиксированная версия и статус поставщика |
| Greenbone / OpenVAS | Сетевая поверхность и уязвимости сервисов | На отдельном сетевом scanner | Импорт XML-отчёта по одному хосту |
| OWASP Dependency-Track | Независимый анализ компонентов, SBOM и VEX | В отдельном Docker profile | Подтверждение передачи SBOM; verdict — в D-Track |

## 1. Trivy: основной CVE-контур

Контейнер HCP содержит закреплённый Trivy. После кнопки «Проверить пакеты и CVE» платформа создаёт CycloneDX 1.5 SBOM из фактического инвентаря пакетов, запускает `trivy sbom` и сохраняет и CVE-отчёт, и SBOM в persistent volume.

Для сети с выходом оставьте Trivy в online-режиме:

```env
HCP_TRIVY_MODE=online
```

Для изолированной сети сначала регулярно импортируйте базы Trivy в доступный только внутри сети OCI-registry. Затем задайте зеркала и включите offline-режим:

```env
HCP_TRIVY_MODE=offline
HCP_TRIVY_DB_REPOSITORY=registry.security.intra/trivy-db
HCP_TRIVY_JAVA_DB_REPOSITORY=registry.security.intra/trivy-java-db
```

`offline` запрещает обновление базы и сетевой запрос. Если локальной базы нет или она устарела, HCP создаёт запись `manual` «Trivy не выполнил CVE-сопоставление». Отсутствие CVE тогда не считается результатом проверки.

Для каждой находки HCP сохраняет `vendor_status`, `vendor_severity` и источник данных Trivy. Статусы `not affected` и `fixed` отображаются как пройденные с сохранённым evidence, а `will not fix`, `end of life` и неизвестный статус требуют ручной оценки. Это учитывает дистрибутивные backport-исправления; RPM epoch также сохраняется в инвентаре и SBOM.

## 2. OpenSCAP и SCAP Security Guide

OpenSCAP даёт сильное доказательство только при точном соответствии ОС, datastream и профиля. Поэтому HCP не выбирает «похожий» файл автоматически и не устанавливает scanner на рабочую ВМ.

На каждом хосте, который будет оцениваться, администратор один раз подготавливает OpenSCAP и контент SSG средствами утверждённого образа ОС. Для Debian-подобного хоста это обычно:

```bash
sudo apt update
sudo apt install openscap-scanner ssg-debderived
oscap info /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
```

Проверьте точный идентификатор профиля через `oscap info`, после чего задайте единый, действительно применимый к целевым системам набор в `.env` control node:

```env
HCP_OPENSCAP_DATASTREAM=/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
HCP_OPENSCAP_PROFILE=xccdf_org.ssgproject.content_profile_cis_server_l1
```

Перезапустите HCP и в «Дополнительных проверках» выберите `Проверить SSG-профиль OpenSCAP`. На ВМ создаётся только временный каталог с ARF-результатом; он удаляется в блоке `always`. HCP сохраняет нормализованный отчёт с ID правила, исходной severity и результатом. Если `oscap`, datastream или переменные не готовы, результат отмечается `manual`, а не `passed`.

Не применяйте один CIS/STIG-профиль ко всем ролям без исключений и протокола утверждения. Результат OpenSCAP — доказательство состояния, а не разрешение автоматически менять систему.

## 3. Greenbone / OpenVAS

Greenbone требует существенно больше ресурсов и сетевых прав, чем HCP. Разворачивайте его отдельным сканером в выделенном VLAN/VM по официальной инструкции Greenbone Community Containers; не добавляйте его к `docker-compose.yml` control node и не передавайте ему SSH-ключ HCP. Ограничьте доступ к интерфейсу Greenbone, настройте актуализацию VT-feeds и создайте отдельную задачу для согласованного диапазона адресов.

После завершения задачи экспортируйте именно XML-отчёт, в HCP выберите нужный inventory-host, откройте «Импорт сетевого отчёта Greenbone / OpenVAS» и загрузите файл. Исходный XML не сохраняется: он обрабатывается во временном каталоге и удаляется. В отчёт HCP попадают OID, CVE, адрес, порт, threat, CVSS severity, описание и рекомендация Greenbone.

Так связка не хранит учётные данные Greenbone в HCP и не даёт UI HCP запускать широкие сетевые сканы. Перед импортом убедитесь, что цель задачи Greenbone соответствует выбранному alias: это обязательная операционная проверка.

## 4. OWASP Dependency-Track

Dependency-Track включён в отдельный Compose profile. Заполните секреты в `.env`, затем запустите его вместе с HCP:

```bash
docker compose --profile dependency-track up -d --build
```

Интерфейс D-Track по умолчанию слушает только `127.0.0.1:8080`; API — `127.0.0.1:8081`. После первоначальной безопасной настройки в его UI создайте API key с правом загружать BOM и поместите его только в `.env` HCP:

```env
HCP_DEPENDENCY_TRACK_URL=http://dependency-track-api:8080
HCP_DEPENDENCY_TRACK_API_KEY=replace-with-upload-only-api-key
```

После следующей проверки пакетов Trivy HCP автоматически отправит созданный SBOM в проект с именем inventory alias. Dependency-Track анализирует BOM асинхронно, поэтому его результаты не подменяют отчёт Trivy в момент загрузки. После завершения обработки проверяйте состояние проекта в D-Track, включая policy violations, VEX и актуальность его vulnerability intelligence.

Перед эксплуатацией закрепите образы Dependency-Track и PostgreSQL проверенными digest в `docker-compose.yml`, а не оставляйте mutable tag `latest`.

## Как принимать итоговый отчёт

1. Сначала убедитесь, что каждый источник свежий и не отмечен `manual`/`partial`.
2. Для CVE сверяйте пакет, установленную версию, fixed version и vendor security tracker: дистрибутивы могут backport-ить исправления без смены upstream-версии.
3. Подтверждайте сетевые находки Greenbone с владельцем сервиса и Nmap/фактической конфигурацией firewall.
4. По OpenSCAP фиксируйте профиль, версию SSG и допустимые исключения.
5. Приоритет исправления давайте по подтверждённой комбинации: эксплуатируемость, доступность из сети, роль сервера и наличие исправления, а не только по CVSS.

## Регулярный запуск и корреляция

`hcp-scheduled-audit.timer` выполняет лёгкий Ansible-аудит каждые 15 минут. `hcp-deep-audit.timer` ежедневно запускает инвентаризацию пакетов и Trivy; для этого в `.env` нужен отдельный `HCP_SCHEDULE_API_KEY`. OpenSCAP включается в глубокий запуск только через systemd override после подготовки SSG и отдельной inventory-группы.

В «Сводке» HCP берёт только последние свежие отчёты по хосту, сопоставляет точные CVE, сетевые порты, OpenSCAP rules и Greenbone OID. Совпадение двух разных источников повышает уверенность, но CVSS не суммируются. Срок свежести задаёт `HCP_CORRELATION_MAX_AGE_HOURS` (по умолчанию 168).

Исходные спецификации: [Trivy air-gap](https://trivy.dev/docs/latest/advanced/air-gap/), [SCAP Security Guide](https://www.open-scap.org/security-policies/scap-security-guide/), [Greenbone Community Containers](https://greenbone.github.io/docs/latest/22.4/container/index.html), [Dependency-Track](https://docs.dependencytrack.org/).
