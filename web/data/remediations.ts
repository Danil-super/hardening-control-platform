import type { Remediation } from "@/types";

export const remediations: Remediation[] = [
  {
    id: "disable_ssh_root_login",
    title: "Отключить прямой вход root по SSH",
    description: "Изменяет PermitRootLogin на no и валидирует конфигурацию SSH перед перезагрузкой сервиса.",
    findingIds: ["ssh_root_login"],
    riskOfBreaking: "medium",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    targetFiles: ["/etc/ssh/sshd_config"],
    backupRequired: true,
    rollbackAvailable: true,
    demoSteps: [
      "Создать резервную копию /etc/ssh/sshd_config",
      "Установить PermitRootLogin no",
      "Проверить конфигурацию командой sshd -t",
      "Перезагрузить службу SSH",
      "Запустить аудит повторно",
    ],
    realModeNotes:
      "Перед применением нужно убедиться, что администратор имеет доступ через обычного пользователя с sudo.",
  },
  {
    id: "disable_ssh_password_auth",
    title: "Отключить вход по паролю SSH",
    description: "Отключает PasswordAuthentication при наличии ключевого доступа.",
    findingIds: ["ssh_password_auth"],
    riskOfBreaking: "high",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    targetFiles: ["/etc/ssh/sshd_config"],
    backupRequired: true,
    rollbackAvailable: true,
    demoSteps: [
      "Проверить наличие authorized_keys у администратора",
      "Создать резервную копию /etc/ssh/sshd_config",
      "Установить PasswordAuthentication no",
      "Проверить конфигурацию командой sshd -t",
      "Перезагрузить службу SSH",
    ],
    realModeNotes:
      "В реальном режиме агент должен отказать в действии, если не подтвержден рабочий ключевой доступ.",
  },
  {
    id: "enable_ufw",
    title: "Включить UFW и разрешить SSH",
    description: "Создает безопасный базовый набор правил и включает межсетевой экран.",
    findingIds: ["ufw_disabled"],
    riskOfBreaking: "medium",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    targetFiles: ["набор правил UFW", "/etc/ufw/ufw.conf"],
    backupRequired: true,
    rollbackAvailable: false,
    demoSteps: [
      "Сохранить текущий статус и правила UFW",
      "Разрешить профиль OpenSSH",
      "Установить запрет входящих соединений по умолчанию",
      "Включить UFW",
      "Проверить, что SSH остается доступным",
    ],
    realModeNotes:
      "Откат частичный: можно восстановить сохраненный набор правил, но сетевой доступ должен проверяться отдельно.",
  },
  {
    id: "install_fail2ban",
    title: "Установить и включить fail2ban",
    description: "Имитирует установку fail2ban и включение базового правила защиты SSH.",
    findingIds: ["fail2ban_missing"],
    riskOfBreaking: "low",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    targetFiles: ["/etc/fail2ban/jail.local"],
    backupRequired: false,
    rollbackAvailable: false,
    demoSteps: [
      "Создать запись в журнале действия",
      "Установить пакет fail2ban",
      "Включить защитное правило для sshd",
      "Запустить службу fail2ban",
      "Проверить статус правила",
    ],
    realModeNotes:
      "Агент должен учитывать пакетный менеджер ОС и наличие кастомных jail-конфигураций.",
  },
  {
    id: "enable_unattended_upgrades",
    title: "Включить автоматические обновления безопасности",
    description: "Настраивает unattended-upgrades для регулярной установки обновлений безопасности.",
    findingIds: ["unattended_upgrades_disabled"],
    riskOfBreaking: "low",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    targetFiles: ["/etc/apt/apt.conf.d/20auto-upgrades"],
    backupRequired: true,
    rollbackAvailable: true,
    demoSteps: [
      "Создать резервную копию конфигурации автообновлений",
      "Включить unattended-upgrades",
      "Включить периодическое обновление списка пакетов",
      "Проверить конфигурацию apt",
    ],
    realModeNotes:
      "В промышленной среде нужно согласовать политику автоматических перезагрузок и окна обслуживания.",
  },
  {
    id: "disable_nginx_server_tokens",
    title: "Скрыть версию Nginx",
    description: "Отключает server_tokens и проверяет синтаксис Nginx.",
    findingIds: ["nginx_server_tokens"],
    riskOfBreaking: "low",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    targetFiles: ["/etc/nginx/nginx.conf"],
    backupRequired: true,
    rollbackAvailable: true,
    demoSteps: [
      "Создать резервную копию /etc/nginx/nginx.conf",
      "Установить server_tokens off",
      "Проверить конфигурацию командой nginx -t",
      "Перезагрузить Nginx",
    ],
    realModeNotes:
      "Агент должен найти контекст http и не дублировать директиву.",
  },
  {
    id: "add_nginx_security_headers",
    title: "Добавить базовые защитные заголовки",
    description: "Добавляет базовый набор заголовков для уменьшения веб-рисков.",
    findingIds: ["nginx_security_headers_missing"],
    riskOfBreaking: "medium",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    targetFiles: ["/etc/nginx/snippets/security-headers.conf", "/etc/nginx/sites-enabled/*"],
    backupRequired: true,
    rollbackAvailable: true,
    demoSteps: [
      "Создать резервную копию затронутых конфигураций сайта",
      "Создать или обновить фрагмент с защитными заголовками",
      "Подключить фрагмент к server-блокам",
      "Проверить конфигурацию командой nginx -t",
      "Перезагрузить Nginx",
    ],
    realModeNotes:
      "Для CSP нужен ручной режим, потому что политика зависит от конкретного приложения.",
  },
  {
    id: "review_cron_permissions",
    title: "Проверить права cron-файлов",
    description: "Проверяет владельцев и права cron-файлов, чтобы исключить изменение заданий обычными пользователями.",
    findingIds: ["lynis_schd-7704"],
    riskOfBreaking: "medium",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    targetFiles: ["/etc/crontab", "/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.hourly/*"],
    backupRequired: true,
    rollbackAvailable: true,
    demoSteps: [
      "Собрать список cron-файлов из отчета Lynis",
      "Создать резервную копию затронутых файлов",
      "Проверить владельца root и группу root",
      "Убрать запись для group/other там, где она не требуется",
      "Повторить аудит Lynis",
    ],
    realModeNotes:
      "Автоматическое изменение прав cron-файлов требует ручного подтверждения списка файлов, чтобы не сломать системные задания.",
  },
  {
    id: "restrict_compilers",
    title: "Ограничить доступ к компиляторам",
    description: "Снижает риск компиляции вредоносного кода на production-хосте непривилегированными пользователями.",
    findingIds: ["lynis_hrdn-7222"],
    riskOfBreaking: "medium",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    targetFiles: ["/usr/bin/gcc", "/usr/bin/g++", "/usr/bin/cc", "пакеты build-essential"],
    backupRequired: false,
    rollbackAvailable: true,
    demoSteps: [
      "Проверить, нужны ли компиляторы на сервере",
      "Определить пользователей и процессы, которым нужен доступ",
      "Ограничить права через группу или удалить компиляторы с production-хоста",
      "Зафиксировать исключения для CI/CD или build-серверов",
      "Повторить аудит Lynis",
    ],
    realModeNotes:
      "На build-хостах компиляторы могут быть необходимы. Для production-серверов предпочтительно удалить их или ограничить доступ отдельной группой.",
  },
];

export function getRemediation(remediationId: string) {
  return remediations.find((remediation) => remediation.id === remediationId);
}

export function getRemediationsForFindings(findingIds: string[]) {
  return remediations.filter((remediation) =>
    remediation.findingIds.some((findingId) => findingIds.includes(findingId)),
  );
}
