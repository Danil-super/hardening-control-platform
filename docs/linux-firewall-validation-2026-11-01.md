# Точность проверки firewall и нативное восстановление — 1 ноября 2026

Этот этап уточняет правило `firewall_active` в общей системе Linux-аудита.
Он устраняет воспроизведённые ложные положительные результаты, поддерживает
стандартный ruleset firewalld и проверяет сохранность результата в отчёте.
Общая настройка находится в [Linux setup](linux-setup.md), смысл статусов —
в [инструкции firewall](linux-firewall-audit.md), границы платформы —
в [матрице поддержки](linux-support.md).

**Все 8 workflows исправленного кандидата завершились успешно.**
Проверенный source commit —
[`0df309c9990a585f776ea707c209cc330f156f89`](https://github.com/Danil-super/hardening-control-platform/commit/0df309c9990a585f776ea707c209cc330f156f89),
Git tree — `99a658912ed0e03478c2f77c8103f80adf8f0b30`.
Дерево фактического PR checkout
[`f09c3b18`](https://github.com/Danil-super/hardening-control-platform/commit/f09c3b18d3df81c123782c27a320230a93b4a1a8)
совпало с ним. [PR №7](https://github.com/Danil-super/hardening-control-platform/pull/7)
слит в `main` коммитом
[`f224f370`](https://github.com/Danil-super/hardening-control-platform/commit/f224f370d0d5b07ed8da993f7bcf796866fc4d96)
с тем же деревом.

Этот итоговый документ и [машиночитаемые доказательства](evidence/linux-firewall-2026-11-01.json)
добавлены отдельным изменением документации после проверки кода.
Результаты ниже относятся к указанному кандидату; продуктивные серверы
пользователя не использовались.

## Найденные и исправленные ошибки

| Ошибка | Почему результат был неверным | Исправление |
| --- | --- | --- |
| Обычный firewalld на Alma/Rocky оставался `manual` | Не учитывались `goto`, отсутствие DNAT в выбранной модели и зависимость ICMPv6 payload от протокола | Поддержаны эти конструкции; `jump`, `goto`, `return` имеют разные правила возврата |
| Изменение пакета в другой INPUT-цепочке могло дать ложный `passed` | Поздняя цепочка проверялась с исходным портом, хотя ранняя могла переписать его | Достижимое неподдержанное изменение пакета сохраняет `manual` до выбора свидетельства запрета |
| Результат iptables мог скрыть неизвестность nftables, и наоборот | Положительный результат одного источника перекрывал ошибку чтения или неподдержанное действие другого | Неопределённость наблюдаемого packet filter нельзя скрыть другим backend; отсутствующая утилита учитывается отдельно |

Независимый review воспроизвёл сценарии изменения TCP-порта между цепочками
и обхода неизвестности через другой backend. Исправленный код возвращает
`manual`, сохраняя `firewall_active` в `incompleteChecks`. Достижимые
неподдержанные действия сохраняют неопределённость; неизвестные условия
проверяются по обеим возможным ветвям.

Дополнительно разделены поиск конкретного deny и доказательство свободного
INPUT. Для `failed` нужен символический проход по всем возможным портам
модели; отсутствие deny на конечном наборе примеров не считается доказательством.

Положительный результат теперь содержит конкретное свидетельство:
семейство IP, протокол, порт, запрещающую цепочку и рассмотренные INPUT-цепочки.
Полный JSON `nft -j list ruleset` сохраняется в evidence. Версия алгоритма
записывается в `agentless.evaluatorVersion=1.2.0`; `agentless.version` остаётся
версией профиля правил. Исторические отчёты не изменяются.

## Что означает доказательство

Модель — **NEW TCP/UDP, non-loopback, без DNAT**, в наблюдаемом локальном INPUT.
Отсутствие DNAT задаётся отдельно: состояние NEW само по себе его не исключает.

- `passed`: найден доказанный запрет для конкретного пакета объявленной модели.
- `failed`: в рамках модели доказан свободный проход всех портов TCP/UDP либо
  INPUT-фильтрация отсутствует.
- `manual`: наблюдений или поддержанных конструкций недостаточно для вывода.

Шесть конкретных портов используются только для поиска положительного
свидетельства deny. Успешная проверка не подтверждает защиту всех портов,
обоих семейств IP, ICMP, DNAT, установленных соединений, FORWARD, контейнерных
или облачных сетей. Она также не подтверждает внешний сетевой путь или
соответствие политики роли сервера.

## Нативный контроль

Стенд запускает настоящий production playbook по SSH внутри принадлежащих CI
одноразовых AlmaLinux/Rocky VM. Проверяются три состояния:

1. Исходный ограничивающий ruleset — ожидается `passed`.
2. Через штатный firewalld API добавляется собственное runtime rich rule
   `rule priority="-32768" accept` в public zone — ожидается `failed`.
3. Удаляется только это правило — ожидается `passed` и точное восстановление.

Firewalld остаётся запущенным; SELinux — Enforcing. Флаги таблицы `owner,persist`
не отключаются. До изменения проверяется отсутствие точного правила в runtime
и permanent-конфигурации. Приватный root-owned маркер фиксирует владение перед
добавлением; `finally` выполняет удаление также при потере ответа после add.

Допустимое изменение ядра — ровно один безусловный accept в
`filter_IN_public_pre`. После удаления сравниваются kernel ruleset, runtime,
постоянная конфигурация и SELinux labels. Из семантического сравнения исключены
только handles и значения счётчиков; порядок правил и остальные поля сохраняются.

Свежий [RPM VM run 41297007616](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007616)
подтвердил контроль на обеих x86_64 VM:

| Система | Исходное состояние | Временный allow-all | После удаления | Восстановление |
| --- | --- | --- | --- | --- |
| AlmaLinux 9.8 | `passed`, score 67 | `failed`, score 60 | `passed`, score 67 | Kernel/runtime/config/SELinux labels совпали |
| Rocky Linux 9.8 | `passed`, score 67 | `failed`, score 60 | `passed`, score 67 | Kernel/runtime/config/SELinux labels совпали |

Во всех шести отчётах `evaluatorVersion=1.2.0`, 17 findings,
`partial=false`, `incompleteChecks=[]`. Положительное свидетельство —
IPv4, TCP/1, `inet/firewalld/filter_INPUT`. Firewalld работал, SELinux оставался
Enforcing; `owner,persist` сохранены. Исходный и восстановленный nft JSON
совпали даже побайтово. Дополнительно проверено отсутствие изменений runtime,
постоянных файлов и SELinux labels после удаления правила. В фазе allow-all
с исходными совпали постоянная конфигурация и SELinux labels; runtime содержал
собственное временное правило стенда.

Числа 67 и 60 — оценка конфигурационного профиля, а не доля защищённости хоста.
В исходном и восстановленном состояниях сохранились 4 `failed`, 7 `passed`
и 6 `manual`. При allow-all изменилось только решение firewall:
5 `failed`, 6 `passed`, 6 `manual`. Успех стенда не означает отсутствия
нарушений на проверяемой VM.

## Сохранность отчёта

Каждый из трёх настоящих отчётов проходит production `readAnsibleReport`.
Контроль проверяет полное сохранение raw JSON, числа находок, всех
`id/status/risk/evidence`, признака `partial` и причин `incompleteChecks`.
Неполный отчёт сохраняет `score=null`. Подтверждение firewall не снимает
остальные причины неполноты.

Эта проверка удостоверяет чтение и нормализацию VM-отчётов. Регистрация актива
и полный интерфейс пользователя остаются отдельными маршрутами; сохранность
raw evidence не является самостоятельным доказательством нативного выполнения.

## Применение, резервирование и откат

Новый трёхфазный контроль проверяет оценку firewall. Существующий native gate
отдельно проверяет настоящее закрытие тестового HTTP-порта, сохранение SSH,
preview без изменений, повторное применение, сохранение правила после reload
и восстановление трафика после rollback.

Отдельно остаётся аварийный контроль: процесс отката получает SIGKILL в точке,
где рабочая директория уже перемещена. Повторный запуск должен восстановить
конфигурацию, runtime и SELinux labels из сохранённого журнала; повтор готового
отката должен иметь `changed=0`.

На обеих RPM VM этот контроль прошёл: восстановлены 10 реальных
SELinux-меток firewall, трафик и конфигурация; повтор отката не изменил
состояние. Отдельные стенды [UFW](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007641)
и [firewalld](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007626)
также прошли 12/12 и 21/21 проверок соответственно, включая SIGKILL,
восстановление и финальную очистку.

Границы автоматических изменений не расширены: транзакционные UFW/firewalld
на systemd. Самостоятельный nftables backend и автоматическое исправление
на OpenRC требуют отдельных адаптеров и испытаний. Инструкция резервирования —
[backup/restore](backup-restore.md).

## Ошибка, обнаруженная интеграционным CI

Первый кандидат `c72039a974492ebe9d94b4b3460baced4946a643` не прошёл native
запуски: Ansible пытался разбить встроенный Python heredoc на аргументы и
отклонял апостроф в комментарии как незакрытую кавычку. Ошибка возникала до
исполнения аудита; новый runtime firewall control ещё не запускался.

Исправление передаёт команду через явный `ansible.builtin.shell.cmd`.
Независимая проверка подтвердила побайтовое равенство декодированной команды
и остальных настроек задачи: 64 413 bytes, SHA-256
`860958ca39fdb0136219dd0874802509039872455e6cbfc88fb334d3a6f5a607`.
Добавлен тест настоящего Ansible parser с положительным и отрицательным
контролем; извлечение Python heredoc в legacy gate больше не зависит от отступов.

Неуспешные запуски, исправление и результаты нового кандидата сохраняются
в истории PR.

## Проверки и воспроизводимость

На исправленном кандидате CI подтвердил:

| Проверка | Результат |
| --- | --- |
| Web | 401/401 |
| Production HTTP smoke | 69/69 |
| Python | 293 tests: 291 успешно, 2 явных пропуска native OpenSCAP |
| Agentless/parser regressions, входят в Python suite | 56/56 |
| Deployment | 38/38 |
| Native firewall normalizer regressions | 3/3 |
| Настоящий Ansible syntax-check | 14/14 playbooks |
| Реальное выполнение target-кода на Python 3.5.10 | 8/8 |
| TypeScript, production build и Docker build | Успешно |

Пропуски unit-тестов OpenSCAP не заменяют отдельную нативную приёмку:
[полный OpenSCAP workflow](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007597)
успешно выполнил неизменённый CIS Ubuntu 24.04 L1 Server из SSG 0.1.79:
405 выбранных правил, из них 222 pass, 120 fail и 63 notapplicable.
`partial=false`, scanner exit 2 означает найденные нарушения. Отдельный
размеченный контроль дал 5 pass / 1 fail, после восстановления — 6 pass.
Преднамеренно изменялось только правило `file_permissions_etc_passwd`;
наличие результатов всего профиля не измеряет точность каждого его правила.

На [Alpine 3.22.6](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007591)
подтверждены настоящий OpenRC, `crond active → inactive → active` и
sticky-bit `passed → failed → passed`. Неполнота системного аудита из-за
недоступных firewall-инструментов и других источников осталась явной,
`score=null`. Для APK сохранены 152 записи и ограничение происхождения:
53 unknown; это не означает 53 уязвимости.

На [Astra 1.8.1 и 1.8.6](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007622)
успешны 7/7 контрольных этапов каждого образа. В обоих случаях вычислены
8 284 OVAL definitions; контроль CVE-2024-5535 присутствует в отчёте 1.8.1
и отсутствует в 1.8.6. `fullCveCoverage=false` сохранён. Контрольное baseline
правило прошло `pass → fail → pass`, при этом весь профиль из 18 правил
сохранил исходные 14 pass / 4 fail. Полное отсутствие нарушений не заявляется.

Общий [Docker/SSH lab](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007696)
прошёл 20/20 проверок, включая обычный и плановый agentless-аудит,
публикацию и повторное чтение отчётов. Scheduled agentless сохранил 17 findings,
версию evaluator, verified asset binding, evidence и `partial=true`;
CLI вернул exit 1. Проверки отказа без сохранённого sudo-доступа, отсутствующей
Trivy DB, пакетного инвентаря, размеченных Ubuntu cases и сохранности после
перезапуска также прошли.

Локально также выполнены 56 agentless/parser tests на закреплённом
ansible-core 2.21.5, все 14 syntax-check, 38 deployment tests,
3 normalization tests и 8 target-script smoke tests на Python 3.12.
Первоначальный полный Python-прогон до добавления parser regression:
292 tests, 290 успешных и 2 явных пропуска OpenSCAP.

Полный набор запущенных workflows кандидата:

| Workflow | Результат |
| --- | --- |
| [Verify hardening platform](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007696) | success |
| [Native RPM VM / SELinux](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007616) | success |
| [Alpine OpenRC / APK](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007591) | success |
| [Astra VM](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007622) | success |
| [OpenSCAP full profile](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007597) | success |
| [Firewalld apply / rollback](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007626) | success |
| [UFW apply / rollback](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007641) | success |
| [Python 3.5 compatibility](https://github.com/Danil-super/hardening-control-platform/actions/runs/41297007636) | success |

В артефактах RPM сохраняются `firewall-audit-protocol.json`, три nft/state
snapshot, три исходных отчёта и `firewall-audit-normalized/protocol.json`.
Подлинность использованных архивов проверяется по SHA-256, а происхождение —
по workflow и точному head SHA. Набор исходных артефактов имеет ограниченный
срок хранения GitHub; ключевые выводы и контрольные суммы фиксируются в
машиночитаемом протоколе репозитория.

## Что остаётся следующим этапом

1. Расширить нативную матрицу: Debian/Ubuntu VM, SLES/openSUSE, ALT/РЕД ОС,
   архитектура aarch64. Каждый новый маршрут должен иметь размеченный
   нарушающий и исправленный контроль, проверку отчёта и безопасный откат.
2. Отделить наличие ограничивающего INPUT от соответствия политике роли:
   какие сервисы разрешены, на каких адресах и интерфейсах. Добавить отдельные
   IPv4/IPv6 проверки внешнего трафика.
3. Развивать адаптеры CVE и происхождения пакетов с собственными vendor
   advisory и контролями false positive/false negative. Успех firewall-аудита
   не измеряет полноту обнаружения уязвимостей пакетов.
4. Добавлять новые автоматические исправления только вместе с preview,
   проверкой достигнутого состояния, метаданными backup и испытанием аварийного
   восстановления на соответствующей ОС.

Исторический результат первого этапа универсализации находится в
[протоколе 31 октября](linux-validation-2026-10-31.md); его показатели не
переписываются результатами этого этапа.
