# Универсализация Linux: реализация и проверка — 31 октября 2026

Первый этап развивает общую систему аудита Linux и контролируемого применения
исправлений. Полная поддержка всех дистрибутивов, архитектур и CVE не заявляется.
Настройка описана в [Linux setup](linux-setup.md), кодовые маршруты и ограничения —
в [матрице поддержки](linux-support.md).

**Итог: все 10 workflows проверенного кандидата завершились успешно.**
Исходный commit —
[`df226003d641db493ff28cc9cd311351455e1bab`](https://github.com/Danil-super/hardening-control-platform/commit/df226003d641db493ff28cc9cd311351455e1bab),
Git tree — `71e7b7de7651be56506a0d64ad52405ac9707256`.
Дерево фактического PR checkout
[`1d52a976`](https://github.com/Danil-super/hardening-control-platform/commit/1d52a976ed58af674e70b064a386b1d22f4b0390)
совпадает с ним. Этот итоговый документ и
[машиночитаемый протокол](evidence/linux-platform-2026-10-31.json)
добавлены отдельным изменением документации после проверки исходного кода.

Числа ниже получены из новых артефактов именно этого запуска. Для lab, RPM,
Alpine, Astra, OpenSCAP и обоих firewall-стендов независимо проверены SHA-256
скачанных архивов и их привязка к workflow/head. Успешный тест означает, что
проверяемый сценарий сработал правильно; проверяемый хост при этом может иметь
нарушения, `manual` и `partial`. Продуктивные серверы не изменялись.

## Что реализовано


- Точный `ID`/`VERSION_ID`, приоритет `/etc/os-release` и безопасный разбор без
  исполнения содержимого. `ID_LIKE` выбирает сборщик, но не advisory другой ОС.
- Отдельные dpkg/RPM/APK-сборщики, сохранение версии, архитектуры, source/epoch/
  release и доступных сведений о происхождении. CentOS Stream и Astra не получают
  автоматически CVE-оценку родительского дистрибутива.
- systemd, подтверждённый OpenRC и ограниченный SysV/LSB; алиасы служб,
  неопределённые состояния и явная неполнота при недоступных источниках событий.
- Настроенный целевой Python используется согласованно; Ansible выбирается по
  фактической установленной версии и совместимости с целями. Docker содержит
  отдельные modern и legacy runtime.
- RPM-ключи отделены от программных пакетов в счётчиках CVE; сохранена проверка
  полного прохождения инвентаря через SBOM и detector.
- Крупный native JSON Trivy передаётся через приватный файл с проверкой размера,
  SHA-256, типа и целостности. Предел stdout — 64 МиБ, stderr — 1 МиБ;
  превышение даёт явный неполный отчёт без обрезания списка находок.
- SELinux/PDPL-метки сохраняются в firewall backup и проверяются при восстановлении.
  Автоматические транзакционные изменения остаются ограничены UFW/firewalld на
  systemd. nftables и OpenRC требуют отдельных адаптеров.

## Исправленные ошибки

1. Пространства имён RPM PURL не всегда совпадали с ожидаемыми Trivy:
   `almalinux → alma`, `ol → oracle`, `amzn → amazon`, `sles → suse` и другие.
2. Изменение служебных SQLite WAL/SHM при чтении RPM ошибочно выглядело как
   изменение пакетов. Используется read-only `data_version` с контролем пути/inode.
3. Проверялась стандартная RPM-база, хотя native-настройки могли указывать другую.
   `_dbpath`/`_db_backend` проверяются и закрепляются в запросе.
4. `gpg-pubkey` увеличивали число проверенных программных пакетов. Теперь ключи
   сохранены отдельно; произвольное исключение обычного пакета не принимается.
5. Реальный результат Rocky превышал прежний предел stdout 16 МиБ. Новый путь
   сохраняет все находки и выявляет повреждение/подмену временного файла.
6. Предположения о systemd, именах служб и полноте журналов давали слишком
   уверенные выводы. Неизвестность теперь остаётся явной в результате.
7. Откат должен восстанавливать security metadata вместе с содержимым и правами.
   Потеря меток или несовместимость архива останавливают замену рабочей конфигурации.
8. Плановые agentless/packages напрямую вызывали Ansible из PATH и обходили
   общий выбор runtime и публикацию привязанных отчётов. Обе задачи переведены
   на общий API и `runAnsiblePlaybook`.
9. Пакетный batch только по `reportRunId` не знал ожидаемый состав целей и мог
   не заметить отсутствующий отчёт. `limit` обязателен; результат каждого хоста
   учитывается отдельно. Старые отчёты не подставляются вместо новых.
10. Общая проверка отчётов могла назвать пустой результат полным. Отсутствие run
    ID, Linux-целей, ID ожидаемого отчёта и недоступность scanner теперь дают
    `partial`. Успешный `ping` сохраняет намеренный контракт без отчёта.

## Планировщик

Для всех задач нужен `HCP_SCHEDULE_API_KEY` и работающий HCP. Состав целей
фиксируется перед началом, каждый сервер выполняется отдельно со своим runtime,
аутентифицированной идентичностью и frozen inventory. Проверяется свежий отчёт
точного запуска: alias, тип, время, доступность и полнота. Разовый sudo-пароль
в расписание не передаётся. Отказ возвращает `sudo_password_required`.

CLI валидирует конфигурацию до работы, выводит JSON также при partial, выполняет
остальные валидные задачи и возвращает ненулевой итог при любой неполноте/ошибке.
HTTP 207 не считается полным успехом. Ответ со списком результатов ограничен
4 МиБ, один запрос — шестью часами; сохранённые scanner reports имеют свои лимиты.

Новый lab использует отдельный заранее подготовленный NOPASSWD-хост с собственными
SSH host keys и machine-id. Два enrolled on-demand хоста не изменяются. Проверяются
отказ без пароля, настоящий CLI → API → SSH, выбор modern Ansible, сохранение
asset binding, native dpkg-сравнение и честный exit code. Образ Debian фактически
использует Python 3.11; тест не объявляется нативной проверкой Python 3.14.
Процедура — в [инструкции лаборатории](../deployment/lab/README.md#автоматический-протокол).

## Подтверждённый путь планового запуска

Docker/SSH lab выполнил установленный CLI → production API → реальный SSH →
сборщики → сохранение и нормализацию отчётов → повторное чтение после restart.
Отдельный хост — Debian 12 с Python 3.11.2; фактически выбран modern Ansible
2.21.5. Независимый `sudo -n` подтвердил UID 0.

| Проверка | Фактический результат |
| --- | --- |
| Agentless/packages на on-demand хостах | Оба вернули `sudo_password_required`, exit 1, без ID отчёта |
| Подготовленный scheduled agentless | 17 findings: 4 failed, 4 passed, 9 manual; partial, exit 1 |
| Scheduled package inventory | 139 dpkg-записей, partial=false; имена, версии, архитектуры и число совпали с native query |
| Scheduled Trivy | 139 inventory / decoded / eligible / scanned / checked |
| Происхождение | 121 metadata-consistent, 18 unknown, 0 third-party; криптографического attestation нет |
| CVE-отчёт | 468 findings: 464 failed и 4 manual; partial=true, exit 1 |
| Публикация | Все три отчёта имеют одинаковую verified asset binding в raw и normalized JSON |
| Перезапуск | Сохранность 11 отчётов, host associations, выбора базы и enrollment keys подтверждена |

Причины неполноты agentless: `failed_logins`, `firewall_active`, `service_auditd`,
`service_fail2ban`. Заданные нарушения `PermitRootLogin=yes` и `MaxAuthTries=8`
обнаружены. Trivy работал offline со свежей базой возрастом 4,6 часа. Все 468 ID,
статусов, уровней риска и evidence сохранены; нормализатор добавил поясняющие
severity-поля для пяти находок с неопределённой критичностью. Все три отчёта
сохранили `score=null`.

Отдельный cold-cache контроль с отсутствующей DB дал 0 проверенных пакетов и
неполный manual-отчёт. Synthetic Ubuntu cases для CVE-2023-0286 проверили
уязвимые amd64/i386, исправленный backport, source epoch и неизвестного поставщика.

**Граница:** systemd timer внутри Docker lab не запускался; проверен вызываемый
им CLI и дальнейший путь. Native dpkg comparison выполнен внутри успешного CI
gate; отдельный stdout запроса не включён в артефакт. 18 unknown не означают 18
уязвимостей либо доказанно сторонних пакетов.

## Регрессионные проверки

Следующие результаты получены в CI на указанном исходном commit; основные
web/Python/deployment/build проверки также прошли локально.

| Проверка | Результат |
| --- | --- |
| Web | 401/401, без пропусков |
| Production HTTP smoke | 69/69, изолированные fixtures |
| Python | 278 собрано: 276 успешно, 2 native OpenSCAP tests пропущены |
| Deployment | 29/29 |
| Ansible syntax | 14 playbooks |
| TypeScript | Успешно |
| Штатная production-сборка | Next.js 16.4.1 / Turbopack, успешно |
| Docker image | Успешно; modern Ansible 2.21.5 / Python 3.13.18, legacy Ansible 2.14.18 |
| Legacy Python | 8/8 на настоящем Python 3.5.10, без сети и capabilities, read-only root FS |

Два пропуска относятся к наличию native OpenSCAP в обычном Python job; они не
считаются выполненными. Полные нативные Astra/OpenSCAP workflows отдельно
приведены ниже. Targeted scheduled/API/CLI регрессии дополнительно проверяют
настоящий shell, loopback HTTP, native `ansible-inventory` и выбор runtime.

## Нативный RPM, большие отчёты и SELinux

| Показатель | AlmaLinux 9.8 x86_64 | Rocky Linux 9.8 x86_64 |
| --- | ---: | ---: |
| Native inventory / decoded records | 397 / 397 | 433 / 433 |
| Пакеты ПО / проверено | 396 / 396 | 432 / 432 |
| Отдельно сохранённые RPM-ключи | 1 | 1 |
| Trivy → HCP → normalized, CVE×пакет | 518 → 518 → 518 | 2755 → 2755 → 2755 |
| Уникальные CVE | 113 | 589 |
| Исходный JSON Trivy, байт | 4 157 078 | 23 794 302 |
| SELinux-метки после аварийного отката | 10 / 10 | 10 / 10 |

Совпали полные мультимножества `(VulnerabilityID, PURL, InstalledVersion)`, включая
повторы. Нормализация сохранила все `(id, status, risk)`. Native RPM query совпал
с инвентарём, включая EVR, архитектуру и source RPM; база `/var/lib/rpm` / SQLite
выбрана через `native-macros-pinned`, ошибок и неполноты инвентаря нет.

У CVE-прохода `coverage.complete=true` в границах выбранного источника и
maintainer/vendor-эвристики, `score=null`. Это не аттестация происхождения всех
установленных пакетов и не доказательство полноты мировой базы CVE.
Контрольные synthetic metadata для CVE-2023-0286 дали 1 совпадение у уязвимой
версии и 0 у исправленной; добавление trust record не увеличило число пакетов ПО.

На обеих VM SELinux оставался Enforcing. Проверены preview без изменений, защита
SSH, реальная блокировка входящего IPv4 HTTP, сохранение блокировки после reload,
повторный apply, настоящий SIGKILL в rollback `move_old_intent`, восстановление
конфигурации/runtime/трафика и всех 10 проверяемых SELinux-меток. Повторный
завершённый rollback не изменял состояние. Отдельно пройдены четыре сценария
сохранения security metadata и восстановления файловой системы.

**Ограничение системного аудита:** `basic_linux` на обеих VM имеет
`partial=true`, `score=null`, `incompleteChecks=["firewall_active"]`.
Контроль `world_writable_dirs` дал passed → failed → passed; исходное и
восстановленное состояния содержат 6 passed / 4 failed / 7 manual, нарушенное —
5 passed / 5 failed / 7 manual. Успех отдельного firewalld-стенда не делает
этот системный источник полным.

## Alpine / OpenRC / APK

Реальная VM: Alpine 3.22.6 x86_64, kernel 6.12.110-0-virt, Python 3.12.14,
OpenRC. Проверены официальный образ по SHA-512, SSH и production-сборщик 152 APK.

- `crond` и логический `cron`: active → inactive → active.
- `world_writable_dirs`: passed → failed → passed после изменения и восстановления
  sticky bit. Во всех трёх отчётах 17 findings, partial=true, score=null.
- Auth marker найден в syslog; неполнота `authentication_log_routing_unverified`
  сохранена, полнота всех журналов не заявлена.
- 152 записи прошли inventory → SBOM → native Trivy. Все 50 записей CVE×пакет
  (16 уникальных CVE) совпали с HCP; нормализатор сохранил findings и raw JSON.
  Итог: 50 failed + 1 manual, partial=true.
- Происхождение 99 пакетов соответствует metadata-эвристике, 53 остаётся unknown.
- Synthetic control libcrypto3/origin openssl: CVE-2025-9230 присутствует для
  3.5.1-r0 и отсутствует для исправленной 3.5.4-r0. Другие CVE при этом допустимы.

Оба machine-id файла в данном cloud image отсутствовали;
`onboardingEvaluated=false`. Сборщик проверил это read-only. Перед регистрацией
такого хоста нужен штатный постоянный ID по [инструкции](linux-setup.md).
Этот gate доказывает работу сборщиков через подготовленный SSH, не onboarding
неподготовленного образа и не автоматическое firewall remediation на OpenRC.

## Astra OVAL и baseline

Проверены две настоящие base VM amd64 с официальным vendor OVAL.

| Показатель | Astra 1.8.1 | Astra 1.8.6 |
| --- | ---: | ---: |
| Пакеты | 622 | 595 |
| Definitions — всего / оценено | 8284 / 8284 | 8284 / 8284 |
| OVAL true / false | 460 / 7824 | 45 / 8239 |
| Контроль CVE-2024-5535 | true, 1 finding | false, 0 findings |
| Native / normalized findings | 461 / 461 | 46 / 46 |
| Исходный JSON, байт | 75 820 814 | 74 727 479 |
| Опубликованный JSON, байт | 75 821 338 | 74 728 003 |
| Web-normalized JSON, байт | 81 741 645 | 79 543 227 |

Числа OVAL true относятся к definitions, не к уникальным CVE. Во всех проходах
8284 definitions оценены, unknown отсутствуют, partial=false. Полный проход
выбранного OVAL сохраняет `fullCveCoverage=false`: неизвестные источнику CVE
этим не исключаются.

Оба 18-rule baseline дали 14 pass / 4 fail → 13 pass / 5 fail → 14 pass / 4 fail.
Контроль прав `/etc/passwd` прошёл pass → fail → pass; результаты независимо
сверены с ARF. Native JSON, опубликованный JSON и `normalized.raw` разобраны
и сравнены целиком: исходные поля не потеряны, публикация добавила verified asset
binding. Этот путь использует собственные лимиты и не является stdout Trivy.

## OpenSCAP и отдельные firewall-стенды

На Ubuntu 24.04 OpenSCAP 1.3.9 выполнил неизменённый официальный профиль
CIS Level 1 Server из ComplianceAsCode/content 0.1.79: **405 выбранных правил**,
из них 222 pass, 120 fail, 63 notapplicable. Ещё 234 правила не выбраны.
Счётчики normalizer совпали с raw ARF; partial=false. Exit 2 соответствует
найденным нарушениям в этом успешно проверенном сценарии.

Отдельный контрольный профиль из шести правил дал 5 pass / 1 fail после изменения прав
`/etc/passwd`, затем 6 pass после восстановления. Проверены исключения:
исходный статус, риск, evidence и итоги сохраняются; просроченное и постороннее
исключения игнорируются. Cleanup восстановил 0644 и не изменил содержимое файла.
Чувствительность намеренно проверялась одним правилом, не всеми 405.

Отдельные native gates: firewalld — **21/21**, UFW — **12/12**. Оба подтверждают
настоящий SIGKILL с returncode -9, `move_old_intent`, `posix-security-v2`, повторный
откат и восстановление исходной конфигурации и состояния. В firewalld проверялись
свежие SSH-подключения; временные ключи удалены после завершения.

## Все workflows проверенного кандидата

| Workflow | Run | Итог |
| --- | --- | --- |
| Verify hardening platform | [41225904564](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904564) | success |
| OpenSCAP full-profile acceptance | [41225904572](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904572) | success |
| Native RPM VM hardening and SELinux acceptance | [41225904654](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904654) | success |
| Dependency-Track ingestion acceptance | [41225904656](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904656) | success |
| Real firewalld SSH apply and rollback acceptance | [41225904674](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904674) | success |
| Real Astra VM scanner acceptance | [41225904686](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904686) | success |
| Legacy target Python compatibility | [41225904721](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904721) | success |
| Real UFW apply and rollback acceptance | [41225904742](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904742) | success |
| HCP Astra baseline engine acceptance | [41225904779](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904779) | success |
| Real Alpine OpenRC and APK acceptance | [41225904904](https://github.com/Danil-super/hardening-control-platform/actions/runs/41225904904) | success |

Digest, размеры артефактов, точные счётчики, source SHA и ограничения сохранены
в [JSON-протоколе](evidence/linux-platform-2026-10-31.json). Полные CI-артефакты
имеют установленный workflow срок хранения. Повторный запуск может получить
новую advisory DB и другие числа находок; это не повод подменять старые итоги.

Предыдущий нативный этап
[`c5306bf4`](https://github.com/Danil-super/hardening-control-platform/commit/c5306bf42df0773d46523dd94f553431cc286ba5)
прошёл 30 октября, но не подменяет нынешнюю проверку исправленного планировщика.
Более ранний промежуточный
[RPM/SELinux evidence](evidence/native-rpm-selinux-2026-10-30.json) сохраняет
исторический неуспешный поздний CVE-этап Rocky. Он не переименован в финальный успех.

## Оставшиеся ограничения и следующие этапы

1. Довести системные источники `firewall_active`, package updates и журналов до
   проверяемой полноты на каждой целевой платформе. Пока неизвестность остаётся
   видимой в partial/manual; отсутствие наблюдения не превращается в passed.
2. Расширить native VM-матрицу: полные Debian/Ubuntu systemd-хосты, SLES/openSUSE,
   ALT/РЕД ОС и aarch64. Docker/SSH lab не заменяет все проверки ядра и init-системы.
3. Добавлять vendor advisory по точному ID и выпуску и усиливать подтверждение
   происхождения пакетов. ID_LIKE и configured repositories недостаточны.
4. Увеличить размеченный корпус реальных уязвимых/исправленных состояний, включая
   backport, epoch, сторонние репозитории и конфликты источников; только тогда
   измерять false positive/false negative. Native/HCP equality доказывает
   сохранность и корректность интеграции, не общую precision/recall сканера.
5. Развивать самостоятельные транзакционные адаптеры remediation: nftables,
   OpenRC и IPv6 с собственными аварийными проверками. Сейчас автоматические
   firewall-изменения ограничены проверенными UFW/firewalld на systemd.
6. Для immutable/декларативных ОС использовать их штатные механизмы изменений.
   SELinux штатных тестовых образов не доказывает восстановление любых MLS/MCS
   или PDPL-политик; для них нужны отдельные стенды.

Результат этого этапа — проверяемая основа универсальной платформы с явными
границами каждого источника и действия. Он не является сертификатом полного
соответствия CIS и не даёт гарантии обнаружения всех уязвимостей Linux.
