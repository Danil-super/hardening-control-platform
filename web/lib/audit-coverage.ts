export type IncompleteAuditCheck = {
  id: string;
  title: string;
  description: string;
  nextStep: string;
};

type CheckDetails = Omit<IncompleteAuditCheck, "id">;

const knownChecks: Record<string, CheckDetails> = {
  open_ports: {
    title: "Открытые порты",
    description: "Не удалось получить и разобрать список прослушиваемых TCP/UDP-сокетов.",
    nextStep: "Проверьте, что на хосте доступна команда ss (обычно пакет iproute2), затем повторите основной аудит.",
  },
  ssh_effective_config: {
    title: "Эффективная конфигурация SSH",
    description: "sshd -T не вернула набор параметров, по которому можно достоверно оценить SSH. Один файл sshd_config для этого недостаточен: важны Include, значения по умолчанию и Match.",
    nextStep: "На целевом хосте проверьте конфигурацию командой sudo sshd -t. После исправления причины повторите основной аудит; при Match отдельно проверьте нужного пользователя и адрес.",
  },
  firewall_active: {
    title: "Состояние межсетевого экрана",
    description: "HCP не смогла автоматически получить достоверное состояние UFW, firewalld, nftables или iptables.",
    nextStep: "Не запускайте команды вручную ради отчёта: повторите основной аудит после проверки доступа к хосту. Если ОС блокирует даже read-only запросы, используйте «Внешний аудит» для портов и SSH; локальное состояние firewall останется неподтверждённым.",
  },
  security_auto_updates: {
    title: "Автоматические обновления безопасности",
    description: "Не удалось проверить необходимые пакеты или настройки автоматических обновлений.",
    nextStep: "Проверьте доступность менеджера пакетов и права sudo для аудита, затем повторите проверку.",
  },
  package_updates_available: {
    title: "Доступные обновления пакетов",
    description: "Менеджер пакетов не вернул результат, по которому можно безопасно оценить наличие обновлений.",
    nextStep: "Проверьте источники пакетов и подключение к репозиториям, затем повторите аудит или выполните CVE-проверку отдельно.",
  },
  sudo_nopasswd: {
    title: "Права sudo без пароля",
    description: "Не удалось прочитать или проверить правила sudo для учётной записи аудита.",
    nextStep: "Проверьте права выбранной учётной записи и работоспособность sudo; пароль для одного действия в HCP не сохраняется.",
  },
  empty_password_accounts: {
    title: "Учётные записи без пароля",
    description: "Не удалось прочитать сведения об учётных записях из защищённой базы.",
    nextStep: "Проверьте административные права для чтения shadow-данных и повторите аудит.",
  },
  failed_logins: {
    title: "Неудачные попытки входа",
    description: "Не удалось получить журнал неудачных входов в поддерживаемом формате.",
    nextStep: "Проверьте наличие и доступность журналов аутентификации, затем повторите аудит.",
  },
  nginx_configuration: {
    title: "Конфигурация Nginx",
    description: "Активный Nginx найден, но nginx -T не вернул проверяемую конфигурацию.",
    nextStep: "На хосте выполните sudo nginx -t, устраните ошибку или предоставьте доступ к конфигурации, затем повторите аудит.",
  },
  apache_configuration: {
    title: "Конфигурация Apache",
    description: "Активный Apache найден, но его итоговая конфигурация не была получена.",
    nextStep: "На хосте проверьте apache2ctl -t или httpd -t и повторите аудит после устранения причины.",
  },
  docker_engine_available: {
    title: "Доступ к Docker Engine",
    description: "Профиль Docker не получил безопасный ответ от Docker Engine.",
    nextStep: "Проверьте, что выбран правильный профиль, Docker действительно используется и учётная запись аудита имеет только необходимые права.",
  },
  docker_rootless: {
    title: "Режим Docker rootless",
    description: "Docker не вернул SecurityOptions, по которым определяется rootless-режим.",
    nextStep: "Проверьте доступ к docker info и повторите аудит; не добавляйте пользователя в группу docker только ради проверки.",
  },
  docker_socket_permissions: {
    title: "Права docker.sock",
    description: "Не удалось прочитать владельца и режим доступа к сокету Docker.",
    nextStep: "Проверьте существование /var/run/docker.sock и административные права аудита, затем повторите проверку.",
  },
  docker_privileged_containers: {
    title: "Privileged-контейнеры Docker",
    description: "Docker не вернул полный список либо свойства запущенных контейнеров.",
    nextStep: "Проверьте доступ к docker ps и docker inspect, затем повторите аудит.",
  },
  world_writable_dirs: {
    title: "Права временных директорий",
    description: "Не удалось проверить world-writable директории без sticky bit.",
    nextStep: "Проверьте доступность find и права sudo для аудита, затем повторите проверку.",
  },
};

function dynamicCheckDetails(id: string): CheckDetails | null {
  if (id.startsWith("service_")) {
    const service = id.slice("service_".length);
    return {
      title: `Состояние службы ${service}`,
      description: "systemctl не вернул однозначный статус службы.",
      nextStep: "Проверьте systemd и права учётной записи аудита, затем повторите аудит.",
    };
  }
  return null;
}

function fallbackCheckDetails(id: string): CheckDetails {
  return {
    title: `Проверка «${id.replace(/_/g, " ")}»`,
    description: "Сканер не получил результат, достаточный для достоверного вывода.",
    nextStep: "Откройте технические данные отчёта, устраните причину сбора данных и повторите аудит.",
  };
}

/** Converts scanner.incompleteChecks into safe, human-readable next actions. */
export function describeIncompleteAuditChecks(value: unknown): IncompleteAuditCheck[] {
  if (!Array.isArray(value)) return [];
  const ids = [...new Set(value.filter((item): item is string => typeof item === "string" && item.trim().length > 0))];
  return ids.map((id) => ({ id, ...(knownChecks[id] ?? dynamicCheckDetails(id) ?? fallbackCheckDetails(id)) }));
}
