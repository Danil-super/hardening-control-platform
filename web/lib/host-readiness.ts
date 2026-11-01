import { resolveLinuxPlatform, type LinuxPlatform } from "@/lib/linux-platform";

export type ReadinessCheck = {
  id: string;
  title: string;
  state: "ready" | "needs_setup" | "unsupported" | "unknown";
  detail: string;
};

export type HostReadiness = {
  os: string;
  astraVersion: string | null;
  kernel: string;
  pythonVersion: string;
  initSystem: string | null;
  serviceManager: "systemd" | "openrc" | "sysv" | "unknown";
  architecture: string | null;
  platform: LinuxPlatform;
  checks: ReadinessCheck[];
  notes: string[];
};

type Probe = {
  schemaVersion: number;
  osRelease: Record<string, string>;
  astraVersion: string | null;
  kernel: string;
  pythonVersion: string;
  effectiveUid: number;
  initSystem: string | null;
  serviceManager?: "systemd" | "openrc" | "sysv" | "unknown";
  architecture?: string;
  securityModules?: Record<string, string>;
  tools: Record<string, string | null>;
  firewall: Record<string, string>;
  errors: string[];
};

/** Target Python support from the Ansible core support matrix (2026-10-30).
 * Unknown future core releases require an actual module probe, not a guess.
 */
export function assessTargetPython(version: string | null, coreVersion: string | null) {
  const python = version?.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!python) return { compatible: false, message: "Не удалось определить настроенный Python на хосте. Установите Python из репозитория своего выпуска ОС и задайте ansible_python_interpreter." };
  const major = Number(python[1]);
  const minor = Number(python[2]);
  if (major !== 3 || minor < 5) return { compatible: false, message: `Обнаружен Python ${version}. Удалённым скриптам HCP требуется Python 3.5 или новее из репозитория вашего выпуска ОС.` };
  const branch = coreVersion?.match(/^(2\.\d+)(?:\.\d+)?$/)?.[1];
  const ranges: Record<string, [number, number]> = {
    "2.12": [5, 10], "2.13": [5, 10], "2.14": [5, 11], "2.15": [5, 11],
    "2.16": [6, 12], "2.17": [7, 12], "2.18": [8, 13], "2.19": [8, 13],
    "2.20": [9, 14], "2.21": [9, 14],
  };
  const range = branch ? ranges[branch] : undefined;
  if (!range) return { compatible: null, message: `Python ${version}; совместимость с установленным Ansible проверяется запуском модуля.` };
  const compatible = minor >= range[0] && minor <= range[1];
  return { compatible, message: compatible
    ? `Python ${version}; ansible-core ${coreVersion}: версии совместимы, требуется проверка выполнения модуля.`
    : `Python ${version} не входит в диапазон 3.${range[0]}–3.${range[1]} установленного ansible-core ${coreVersion}. Выберите совместимый control node; не заменяйте системный Python хоста пакетами другой ОС.` };
}

/** Readiness describes prerequisites only; it is never a security assessment. */
export function assessHostReadiness(value: unknown): HostReadiness {
  const probe = value as Probe | null;
  if (!probe || probe.schemaVersion !== 1 || !probe.osRelease || !probe.tools || !probe.firewall
    || [probe.osRelease, probe.tools, probe.firewall].some((item) => typeof item !== "object" || Array.isArray(item))
    || !Array.isArray(probe.errors) || typeof probe.effectiveUid !== "number"
    || typeof probe.kernel !== "string" || typeof probe.pythonVersion !== "string" || !(probe.initSystem === null || typeof probe.initSystem === "string")
    || !Object.values(probe.osRelease).every((item) => typeof item === "string")
    || !Object.values(probe.tools).every((item) => item === null || typeof item === "string")
    || !Object.values(probe.firewall).every((item) => typeof item === "string")
    || (probe.serviceManager !== undefined && !["systemd", "openrc", "sysv", "unknown"].includes(probe.serviceManager))
    || (probe.architecture !== undefined && typeof probe.architecture !== "string")
    || (probe.securityModules !== undefined && (!probe.securityModules || typeof probe.securityModules !== "object" || Array.isArray(probe.securityModules) || !Object.values(probe.securityModules).every((item) => typeof item === "string")))
    || !probe.errors.every((item) => typeof item === "string")
    || !(probe.astraVersion === null || typeof probe.astraVersion === "string")) {
    throw new Error("Не удалось разобрать сведения о готовности хоста.");
  }
  const platform = resolveLinuxPlatform(probe.osRelease, probe.astraVersion);
  const id = platform.id;
  const astra = platform.packageCveProvider === "astra-oval";
  const elevated = probe.effectiveUid === 0;
  const systemd = probe.initSystem === "systemd" && Boolean(probe.tools.systemctl);
  // Older schema-1 probes only established systemd; never infer OpenRC from
  // an installed command or assume a container's process is an init system.
  const serviceManager = probe.serviceManager ?? (systemd ? "systemd" : "unknown");
  const serviceReady = serviceManager === "systemd" ? systemd
    : serviceManager === "openrc" && ["init", "openrc-init"].includes(probe.initSystem ?? "") && Boolean(probe.tools["rc-service"] && probe.tools["rc-status"]);
  const checks: ReadinessCheck[] = [];
  const missing = ["ss", "sshd"].filter((name) => !probe.tools[name]);
  checks.push({ id: "baseline", title: "Системный аудит", state: elevated && serviceReady && !missing.length ? "ready" : "needs_setup",
    detail: [elevated ? "Доступ root подтверждён." : "Для полного сбора нужны права sudo/root.",
      serviceReady ? `Доступен адаптер служб ${serviceManager}.` : serviceManager === "sysv" ? "SysV: состояние подтверждается только для служб с проверяемым LSB status; остальные результаты будут неполными." : "Действующий менеджер служб не подтверждён; проверки служб будут неполными.",
      missing.length ? `Не найдены: ${missing.join(", ")}.` : "Основные инструменты обнаружены."].join(" ") });
  const packageTool = platform.packageManager === "dpkg" ? "dpkg-query" : platform.packageManager;
  const packages = Boolean(packageTool && probe.tools[packageTool]);
  checks.push({ id: "packages", title: "Инвентаризация пакетов", state: !packageTool ? "unsupported" : packages ? "ready" : "needs_setup",
    detail: packages ? `Доступен сбор ${platform.packageManager}. Целостность базы и метаданные пакетов проверяются при аудите; поддержка CVE оценивается отдельно.` : packageTool ? `Для ${id} не найден ${packageTool}. Наличие стороннего пакетного менеджера не заменяет штатную базу ОС.` : "Для этой ОС пакетный адаптер пока не реализован. Системные проверки выполняются независимо от него." });
  checks.push({ id: "cve", title: "CVE пакетов ОС", state: !astra && platform.packageCveProvider !== "trivy" ? "unsupported" : !packages || astra || !platform.versionId ? "needs_setup" : "ready",
    detail: astra ? "Назначьте OVAL-базу для группы в «Источниках» и запустите «Проверить CVE Astra по OVAL». Нужен OpenSCAP; применимость, свежесть базы и полнота выполнения проверяются при аудите."
      : platform.packageCveProvider === "trivy" ? `Настроен маршрут Trivy для ${platform.trivyFamily}. Точный выпуск, происхождение пакетов, полноту обработки и свежесть базы подтвердит аудит. Эта проверка не подтверждает отсутствие уязвимостей.`
        : "Для точного дистрибутива нужен подтверждённый источник производителя. База из ID_LIKE не используется как доказательство CVE-покрытия." });
  checks.push({ id: "openscap", title: "Профиль OpenSCAP", state: "needs_setup",
    detail: [probe.tools.oscap ? "OpenSCAP обнаружен." : "OpenSCAP не найден на целевой машине.",
      astra ? "В «Политиках» доступен профиль «Astra Linux — базовые проверки HCP». Он проверяет настройки с учётом возможностей хоста, требует SCE и не является сертификационным профилем."
        : "Назначьте в «Политиках» datastream и профиль для точного выпуска ОС. Наличие сканера не подтверждает применимость правил."].join(" ") });
  const ufw = probe.firewall.ufw;
  const firewalld = probe.firewall.firewalld;
  const persistent = probe.firewall.netfilterPersistent;
  const known = [ufw, firewalld, persistent].every((state) => ["active", "inactive", "missing"].includes(state));
  const active = [ufw === "active" ? "UFW" : null, firewalld === "active" ? "firewalld" : null].filter(Boolean);
  checks.push({ id: "firewall", title: "Управление firewall", state: !known ? "unknown" : active.length === 1 && persistent !== "active" && elevated && systemd ? "ready" : "needs_setup",
    detail: !known ? "Не удалось однозначно определить активные средства управления firewall. Проверьте права и состояние служб."
      : active.length > 1 || (active.length && persistent === "active") ? "Обнаружено несколько средств управления правилами. Сначала устраните конфликт конфигураций."
        : active.length === 1 ? `Активен ${active[0]}. ${!systemd ? "Транзакционные изменения пока требуют systemd. " : ""}Перед изменениями проверяются backup, метки безопасности и сохранение SSH-доступа.`
          : "Активный UFW/firewalld не обнаружен. Самостоятельные правила iptables/nftables доступны для аудита; автоматическое изменение такого backend пока не поддерживается." });
  return {
    os: probe.osRelease.PRETTY_NAME || [probe.osRelease.NAME || id || "Неизвестная ОС", probe.osRelease.VERSION_ID].filter(Boolean).join(" "),
    astraVersion: probe.astraVersion, kernel: probe.kernel, pythonVersion: probe.pythonVersion, initSystem: probe.initSystem,
    serviceManager, architecture: probe.architecture ?? null, platform,
    checks, notes: ["Проверены предпосылки запуска. Аудит и применение настроек ещё не выполнялись.",
      ...platform.notes,
      ...(probe.securityModules?.selinux === "enforcing" ? ["SELinux работает в enforcing. Backup/rollback должен сохранить исходные метки; отключать SELinux для применения настроек не требуется."] : []),
      ...(astra ? ["Уровень защищённости Astra подтвердите в настройках ОС и запишите в протокол. Не отключайте её средства защиты для прохождения проверок."] : []),
      ...probe.errors.slice(0, 15)],
  };
}
