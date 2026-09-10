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
  checks.push({ id: "cve", title: "CVE пакетов ОС", state: !packages ? "needs_setup" : !astra && ["debian", "ubuntu"].includes(id) && probe.tools["dpkg-query"] ? "ready" : "unsupported",
    detail: astra ? "Полнота проверки пакетов Astra по базе производителя пока не поддерживается. Пустой результат Trivy не подтверждает отсутствие CVE."
      : ["debian", "ubuntu"].includes(id) ? "Поддерживается сбор dpkg. Версию ОС, полноту обработки и свежесть базы Trivy подтвердит сам аудит."
        : "Полнота CVE-сопоставления этого дистрибутива в HCP не подтверждена; требуется сверка с данными производителя." });
  checks.push({ id: "openscap", title: "Профиль OpenSCAP", state: "needs_setup",
    detail: [probe.tools.oscap ? "OpenSCAP обнаружен." : "OpenSCAP не найден на целевой машине.",
      astra ? "В SSG 0.1.79 нет профиля Astra. Нужен проверенный профиль для этого выпуска ОС; профиль Ubuntu/Debian не подходит."
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
