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
  tools: Record<string, string | null>;
  firewall: Record<string, string>;
  errors: string[];
};

/** Target Python support from the Ansible core support matrix (2026-09-10).
 * Unknown future core releases require an actual module probe, not a guess.
 */
export function assessTargetPython(version: string | null, coreVersion: string | null) {
  const python = version?.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!python) return { compatible: false, message: "Не удалось определить Python /usr/bin/python3 на хосте. Установите Python из репозитория своего выпуска ОС." };
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
    || !Array.isArray(probe.errors) || typeof probe.effectiveUid !== "number"
    || typeof probe.kernel !== "string" || typeof probe.pythonVersion !== "string" || !(probe.initSystem === null || typeof probe.initSystem === "string")
    || !Object.values(probe.osRelease).every((item) => typeof item === "string")
    || !Object.values(probe.tools).every((item) => item === null || typeof item === "string")
    || !probe.errors.every((item) => typeof item === "string")
    || !(probe.astraVersion === null || typeof probe.astraVersion === "string")) {
    throw new Error("Не удалось разобрать сведения о готовности хоста.");
  }
  const id = (probe.osRelease.ID ?? "").toLowerCase();
  const astra = Boolean(probe.astraVersion) || id.startsWith("astra") || /astra/i.test(probe.osRelease.NAME ?? "");
  const elevated = probe.effectiveUid === 0;
  const systemd = probe.initSystem === "systemd";
  const checks: ReadinessCheck[] = [];
  const missing = ["ss", "sshd", "systemctl"].filter((name) => !probe.tools[name]);
  checks.push({ id: "baseline", title: "Системный аудит", state: elevated && systemd && !missing.length ? "ready" : "needs_setup",
    detail: [elevated ? "Доступ root подтверждён." : "Для полного сбора нужны права sudo/root.",
      systemd ? "Службы systemd доступны." : "systemd не является PID 1: часть проверок служб неприменима.",
      missing.length ? `Не найдены: ${missing.join(", ")}.` : "Основные инструменты обнаружены."].join(" ") });
  const packages = Boolean(probe.tools["dpkg-query"] || probe.tools.rpm);
  checks.push({ id: "packages", title: "Инвентаризация пакетов", state: packages ? "ready" : "needs_setup",
    detail: packages ? "Доступен сбор установленных пакетов. Поддержка их CVE-базы оценивается отдельно." : "Не найдены dpkg-query или rpm." });
  checks.push({ id: "cve", title: "CVE пакетов ОС", state: !packages || astra ? "needs_setup" : ["debian", "ubuntu"].includes(id) && probe.tools["dpkg-query"] ? "ready" : "unsupported",
    detail: astra ? "Назначьте OVAL-базу для группы в «Источниках» и запустите «Проверить CVE Astra по OVAL». Нужен OpenSCAP; применимость, свежесть базы и полнота выполнения проверяются при аудите."
      : ["debian", "ubuntu"].includes(id) ? "Поддерживается сбор dpkg. Версию ОС, полноту обработки и свежесть базы Trivy подтвердит сам аудит."
        : "Полнота CVE-сопоставления этого дистрибутива в HCP не подтверждена; требуется сверка с данными производителя." });
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
        : active.length === 1 ? `Активен ${active[0]}. Перед изменениями нужны снимок ВМ и проверка сохранения SSH-доступа.`
          : "Активный UFW/firewalld не обнаружен. Это не означает отсутствие фильтрации: правила могут задаваться через iptables/nftables или средствами Astra." });
  return {
    os: probe.osRelease.PRETTY_NAME || [probe.osRelease.NAME || id || "Неизвестная ОС", probe.osRelease.VERSION_ID].filter(Boolean).join(" "),
    astraVersion: probe.astraVersion, kernel: probe.kernel, pythonVersion: probe.pythonVersion, initSystem: probe.initSystem,
    checks, notes: ["Проверены предпосылки запуска. Аудит и применение настроек ещё не выполнялись.",
      ...(astra ? ["Уровень защищённости Astra подтвердите в настройках ОС и запишите в протокол. Не отключайте её средства защиты для прохождения проверок."] : []),
      ...probe.errors.slice(0, 15)],
  };
}
