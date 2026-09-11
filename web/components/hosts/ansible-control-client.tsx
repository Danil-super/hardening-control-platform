"use client";

import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Copy,
  FileText,
  KeyRound,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldCheck,
  Terminal,
  Upload,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button, LinkButton } from "@/components/ui/button";

type HealthPayload = {
  ansibleInstalled?: boolean;
  version?: string | null;
  inventoryReady?: boolean;
  message?: string;
};

type RunPayload = {
  ok?: boolean;
  partial?: boolean;
  warnings?: string[];
  action?: string;
  command?: string;
  message?: string;
  stdout?: string;
  stderr?: string;
  reportRunId?: string | null;
  reportId?: string | null;
  postAuditReportId?: string | null;
  transaction?: RemediationTransaction;
};

type RemediationTransaction = {
  id: string;
  createdAt: string;
  hostAlias: string;
  action: string;
  status: "preparing" | "backed_up" | "applied" | "failed" | "rolling_back" | "rollback_failed" | "rolled_back";
  reason: string;
  backupRef: string | null;
  preAuditReportId: string | null;
  postAuditReportId: string | null;
  error: string | null;
};

type ManagedHost = {
  alias: string;
  address: string;
  user: string | null;
  port: number;
  become: boolean | null;
  groups: string[];
  reportCount: number;
  lastReport: {
    fileName: string;
    createdAt: string | null;
    profileId: string | null;
    score: number | null;
    high: number;
    medium: number;
    low: number;
    info: number;
  } | null;
};

type HostsPayload = {
  inventoryReady?: boolean;
  hosts?: ManagedHost[];
  summary?: {
    total: number;
    withReports: number;
    withoutReports: number;
    becomeEnabled: number;
    averageScore: number | null;
  };
};

type PreflightPayload = {
  ok?: boolean;
  message?: string;
  readiness?: import("@/lib/host-readiness").HostReadiness | null;
  readinessError?: string | null;
  checks?: {
    ssh: { ok: boolean; message: string };
    python: { ok: boolean; message: string };
    sudo: { ok: boolean; message: string };
  };
  facts?: {
    os: string | null;
    python: string | null;
  };
};

type DiscoveryPayload = {
  ok?: boolean;
  defaultCidr?: string;
  candidates?: Array<{ cidr: string; device?: string }>;
  found?: Array<{ ip: string; sshOpen: boolean; alias: string; methods: string[] }>;
  message?: string;
};

type AccessPayload = {
  ok?: boolean;
  publicKey?: string;
  fingerprint?: string | null;
  message?: string;
};

type HostKeyPayload = {
  ok?: boolean;
  fingerprints?: Array<{ fingerprint: string; algorithm: string }>;
  message?: string;
};

const profileOptions = [
  { id: "basic_linux", label: "Базовый Linux" },
  { id: "ssh_security", label: "SSH-сервер" },
  { id: "web_server", label: "Веб-сервер" },
  { id: "docker_host", label: "Docker-хост" },
] as const;

const auditActions = [
  { id: "agentlessAudit", label: "Запустить аудит", icon: ShieldCheck },
  { id: "ping", label: "Проверить связь", icon: Server },
  { id: "collectFacts", label: "Собрать сведения", icon: FileText, advanced: true },
  { id: "packageInventory", label: "Проверить пакеты и CVE", icon: FileText, advanced: true },
  { id: "collectEvents", label: "Собрать события", icon: Terminal, advanced: true },
  { id: "sshCryptoAudit", label: "Проверить SSH-криптографию", icon: ShieldCheck, advanced: true },
  { id: "networkPortScan", label: "Проверить открытые порты", icon: Search, requiresConfirmation: true, advanced: true },
  { id: "lynisTemporaryAudit", label: "Запустить Lynis", icon: ShieldCheck, requiresConfirmation: true, advanced: true },
  { id: "openScapAudit", label: "Проверить профиль OpenSCAP", icon: ShieldCheck, requiresConfirmation: true, advanced: true },
  { id: "astraOvalAudit", label: "Проверить CVE Astra по OVAL", icon: ShieldCheck, requiresConfirmation: true, advanced: true },
] as const;

const responseActions = [
  { id: "closePort", label: "Закрыть порт", icon: Ban },
  { id: "blockIp", label: "Блок IP", icon: AlertTriangle },
] as const;

const primaryAuditActions = auditActions.filter((action) => !("advanced" in action && action.advanced));
const additionalAuditActions = auditActions.filter((action) => "advanced" in action && action.advanced);

const transactionStatusLabels: Record<RemediationTransaction["status"], string> = {
  preparing: "подготовка",
  backed_up: "резервная копия создана",
  applied: "применено",
  failed: "ошибка",
  rolling_back: "выполняется откат",
  rollback_failed: "ошибка отката",
  rolled_back: "восстановлено",
};

const transactionActionLabels: Record<string, string> = {
  closePort: "Закрытие порта",
  blockIp: "Блокировка IP",
};

function formatDate(value: string | null | undefined) {
  if (!value) {
    return "нет отчета";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

function scoreTone(score: number | null | undefined) {
  if (typeof score !== "number") {
    return "border-slate-700 bg-slate-900 text-slate-300";
  }
  if (score >= 80) {
    return "border-emerald-400/40 bg-emerald-500/15 text-emerald-100";
  }
  if (score >= 55) {
    return "border-amber-400/40 bg-amber-500/15 text-amber-100";
  }
  return "border-red-400/40 bg-red-500/15 text-red-100";
}

function reportHref(fileName: string) {
  return `/reports/agentless/${encodeURIComponent(fileName.replace(/\.json$/i, ""))}`;
}

export function AnsibleControlClient() {
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [hosts, setHosts] = useState<HostsPayload | null>(null);
  const [profileId, setProfileId] = useState("basic_linux");
  const [selectedAlias, setSelectedAlias] = useState("");
  const [loading, setLoading] = useState("");
  const [runResult, setRunResult] = useState<RunPayload | null>(null);
  const [freshReportHref, setFreshReportHref] = useState("");
  const [manualAlias, setManualAlias] = useState("");
  const [manualAddress, setManualAddress] = useState("");
  const [manualUser, setManualUser] = useState("");
  const [manualPort, setManualPort] = useState("22");
  const [manualGroup, setManualGroup] = useState("linux_hosts");
  const [manualBecome, setManualBecome] = useState(true);
  const [preflight, setPreflight] = useState<PreflightPayload | null>(null);
  const [preflightFor, setPreflightFor] = useState("");
  const [scanCidr, setScanCidr] = useState("");
  const [discovery, setDiscovery] = useState<DiscoveryPayload | null>(null);
  const [targetPort, setTargetPort] = useState("23");
  const [targetProtocol, setTargetProtocol] = useState("tcp");
  const [blockIp, setBlockIp] = useState("");
  const [changeReason, setChangeReason] = useState("");
  const [confirmedHost, setConfirmedHost] = useState("");
  const [transactions, setTransactions] = useState<RemediationTransaction[]>([]);
  const [access, setAccess] = useState<AccessPayload | null>(null);
  const [hostKeyScan, setHostKeyScan] = useState<HostKeyPayload | null>(null);
  const [trustedFingerprint, setTrustedFingerprint] = useState("");
  const [accessLoading, setAccessLoading] = useState("");
  const [accessMessage, setAccessMessage] = useState("");
  const [copied, setCopied] = useState("");
  const [greenboneFile, setGreenboneFile] = useState<File | null>(null);
  const [greenboneMessage, setGreenboneMessage] = useState("");

  const selectedHost = useMemo(
    () => hosts?.hosts?.find((host) => host.alias === selectedAlias) ?? null,
    [hosts, selectedAlias],
  );

  const connectionSignature = useMemo(
    () => [manualAlias, manualAddress, manualUser, manualPort, manualBecome ? "sudo" : "no-sudo"].join("\u0000"),
    [manualAddress, manualAlias, manualBecome, manualPort, manualUser],
  );

  useEffect(() => {
    void refreshAll();
    void loadControlKey();
  }, []);

  const installPublicKeyCommand = useMemo(() => {
    if (!access?.publicKey) {
      return "";
    }
    const quotedKey = access.publicKey.replaceAll("'", "'\"'\"'");
    return `install -d -m 700 ~/.ssh && printf '%s\\n' '${quotedKey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`;
  }, [access?.publicKey]);

  async function refreshAll() {
    setLoading("refresh");
    try {
      const [healthResponse, hostsResponse, remediationResponse] = await Promise.all([
        fetch("/api/ansible/health"),
        fetch("/api/ansible/hosts"),
        fetch("/api/ansible/remediations"),
      ]);
      const nextHealth = await healthResponse.json();
      const nextHosts = await hostsResponse.json();
      const nextRemediations = await remediationResponse.json();
      setHealth(nextHealth);
      setHosts(nextHosts);
      setTransactions(nextRemediations.transactions ?? []);
      if (!selectedAlias && nextHosts.hosts?.[0]) {
        setSelectedAlias(nextHosts.hosts[0].alias);
      }
      return nextHosts as HostsPayload;
    } catch {
      setRunResult({ ok: false, message: "Не удалось обновить данные. Проверьте подключение к платформе и повторите запрос." });
    } finally {
      setLoading("");
    }
  }

  async function loadHosts() {
    const response = await fetch("/api/ansible/hosts");
    const payload = await response.json();
    setHosts(payload);
    return payload as HostsPayload;
  }

  async function loadRemediations() {
    const response = await fetch("/api/ansible/remediations");
    const payload = await response.json();
    setTransactions(payload.transactions ?? []);
  }

  async function loadControlKey() {
    setAccessLoading("key");
    try {
      const response = await fetch("/api/ansible/access");
      const payload = await response.json();
      setAccess(payload);
      if (!payload.ok) {
        setAccessMessage(payload.message ?? "Не удалось получить публичный ключ узла управления.");
      }
    } catch {
      setAccess({ ok: false, message: "Не удалось связаться с мастером подключения." });
      setAccessMessage("Не удалось связаться с мастером подключения.");
    } finally {
      setAccessLoading("");
    }
  }

  async function copyToClipboard(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
    } catch {
      setAccessMessage("Не удалось скопировать автоматически. Выделите значение и скопируйте вручную.");
    }
  }

  async function scanHostFingerprint() {
    if (!manualAddress) {
      setAccessMessage("Сначала укажите IP-адрес или hostname целевого хоста.");
      return;
    }
    setAccessLoading("scan");
    setAccessMessage("");
    setHostKeyScan(null);
    try {
      const response = await fetch("/api/ansible/access", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: "scan", address: manualAddress, port: manualPort }),
      });
      const payload = await response.json();
      setHostKeyScan(payload);
      setAccessMessage(payload.message ?? "");
    } catch {
      setAccessMessage("Не удалось получить fingerprint SSH-хоста.");
    } finally {
      setAccessLoading("");
    }
  }

  async function trustScannedHostKey() {
    if (!manualAddress || !trustedFingerprint) {
      setAccessMessage("Укажите хост и вставьте fingerprint, подтверждённый через консоль или доверенный канал.");
      return;
    }
    setAccessLoading("trust");
    setAccessMessage("");
    try {
      const response = await fetch("/api/ansible/access", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operation: "trust",
          address: manualAddress,
          port: manualPort,
          expectedFingerprint: trustedFingerprint.trim(),
        }),
      });
      const payload = await response.json();
      setAccessMessage(payload.message ?? "");
    } catch {
      setAccessMessage("Не удалось сохранить проверенный SSH-ключ сервера.");
    } finally {
      setAccessLoading("");
    }
  }

  async function addManualHost() {
    if (!preflight?.ok || preflightFor !== connectionSignature) {
      setRunResult({
        ok: false,
        action: "addHost",
        message: "Сначала успешно проверьте это SSH-подключение. После изменения полей проверку нужно повторить.",
      });
      return;
    }
    setLoading("manualHost");
    setRunResult(null);
    setFreshReportHref("");
    try {
      const response = await fetch("/api/ansible/hosts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alias: manualAlias,
          address: manualAddress,
          user: manualUser,
          port: manualPort,
          group: manualGroup,
          become: manualBecome,
        }),
      });
      const payload = await response.json();
      setRunResult({ ok: payload.ok, action: "addHost", message: payload.message });
      if (payload.ok) {
        setSelectedAlias(manualAlias.trim());
        setManualAddress("");
        await refreshAll();
      }
    } finally {
      setLoading("");
    }
  }

  async function updateManualHost() {
    setLoading("updateHost");
    setRunResult(null);
    setFreshReportHref("");
    try {
      const response = await fetch("/api/ansible/hosts", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alias: manualAlias,
          address: manualAddress,
          user: manualUser,
          port: manualPort,
          group: manualGroup,
          become: manualBecome,
        }),
      });
      const payload = await response.json();
      setRunResult({ ok: payload.ok, action: "updateHost", message: payload.message });
      if (payload.ok) {
        setSelectedAlias(manualAlias.trim());
        await refreshAll();
      }
    } finally {
      setLoading("");
    }
  }

  async function deleteSelectedHost() {
    if (!selectedAlias || !window.confirm(`Удалить хост ${selectedAlias} из inventory?`)) {
      return;
    }
    setLoading("deleteHost");
    setRunResult(null);
    setFreshReportHref("");
    try {
      const response = await fetch("/api/ansible/hosts", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias: selectedAlias }),
      });
      const payload = await response.json();
      setRunResult({ ok: payload.ok, action: "deleteHost", message: payload.message });
      if (payload.ok) {
        setSelectedAlias("");
        await refreshAll();
      }
    } finally {
      setLoading("");
    }
  }

  async function checkPreflight() {
    setLoading("preflight");
    setRunResult(null);
    setPreflight(null);
    setPreflightFor("");
    const checkedConnection = connectionSignature;
    try {
      const response = await fetch("/api/ansible/hosts/preflight", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alias: manualAlias,
          address: manualAddress,
          user: manualUser,
          port: manualPort,
          become: manualBecome,
        }),
      });
      setPreflight(await response.json());
      setPreflightFor(checkedConnection);
    } catch {
      setPreflight({ ok: false, message: "Проверка подключения не завершена: нет ответа от платформы." });
    } finally {
      setLoading("");
    }
  }

  async function detectNetwork() {
    setLoading("detect");
    try {
      const response = await fetch("/api/ansible/discover");
      const payload = await response.json();
      setDiscovery(payload);
      if (payload.defaultCidr) {
        setScanCidr(payload.defaultCidr);
      }
    } finally {
      setLoading("");
    }
  }

  async function scanNetwork() {
    setLoading("scan");
    try {
      const response = await fetch("/api/ansible/discover", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cidr: scanCidr, sshUser: manualUser, become: manualBecome, addToInventory: false }),
      });
      setDiscovery(await response.json());
    } finally {
      setLoading("");
    }
  }

  async function runAction(action: string, mode: "preview" | "apply" = "apply") {
    if (!selectedAlias) {
      setRunResult({ ok: false, action, message: "Выберите хост." });
      return;
    }

    const isResponse = responseActions.some((item) => item.id === action);
    const actionMeta = auditActions.find((item) => item.id === action);
    const requiresConfirmation = Boolean(
      actionMeta && "requiresConfirmation" in actionMeta && actionMeta.requiresConfirmation === true,
    );
    const confirmationText = action === "lynisTemporaryAudit"
      ? "Lynis будет временно передан на выбранную ВМ, выполнен с sudo, а его каталог и сырой отчет будут удалены. Продолжить?"
      : action === "openScapAudit"
        ? "OpenSCAP проверит выбранный профиль на ВМ. Встроенный профиль HCP временно передаётся по SSH. Настройки не меняются; проверка может занять до 30 минут. Продолжить?"
      : action === "astraOvalAudit"
        ? "OpenSCAP проверит хост по OVAL-базе, назначенной его группе в «Источниках». Настройки хоста не меняются. Продолжить?"
      : action === "networkPortScan"
        ? "Nmap выполнит сетевую проверку top-100 TCP-портов выбранного хоста с control node. Продолжить?"
        : "Запустить проверку?";
    if (requiresConfirmation && !window.confirm(confirmationText)) {
      return;
    }

    if (isResponse && changeReason.trim().length < 10) {
      setRunResult({ ok: false, action, message: "Укажите причину изменения не короче 10 символов." });
      return;
    }
    if (isResponse && confirmedHost.trim() !== selectedAlias) {
      setRunResult({ ok: false, action, message: "Введите точный alias выбранного хоста в поле подтверждения." });
      return;
    }

    const extraVars =
      action === "closePort"
        ? { target_port: targetPort, target_protocol: targetProtocol }
        : action === "blockIp"
          ? { block_ip: blockIp }
          : {};

    setLoading(action);
    setRunResult(null);
    setFreshReportHref("");
    try {
      const response = await fetch("/api/ansible/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action,
          profileId,
          limit: selectedAlias,
          mode,
          reason: changeReason.trim(),
          confirmedHost: isResponse ? confirmedHost.trim() : undefined,
          confirmAudit: requiresConfirmation,
          extraVars,
        }),
      });
      const payload = await response.json();
      setRunResult(payload);
      await loadHosts();
      await loadRemediations();
      if (payload.ok && action === "packageInventory") {
        const cveResponse = await fetch("/api/ansible/vulnerabilities/check", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ hostAlias: selectedAlias, reportId: payload.reportId }),
        });
        const cvePayload = await cveResponse.json();
        let dependencyTrackMessage = "";
        let dependencyTrackFailed = false;
        if (cvePayload.ok && cvePayload.reportId && cvePayload.report?.vulnerabilityScan?.sbomFile) {
          try {
            const dependencyTrackResponse = await fetch("/api/ansible/dependency-track/sync", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ hostAlias: selectedAlias, vulnerabilityReportId: cvePayload.reportId }),
            });
            const dependencyTrackPayload = await dependencyTrackResponse.json();
            dependencyTrackFailed = !dependencyTrackResponse.ok || !dependencyTrackPayload.ok;
            dependencyTrackMessage = dependencyTrackPayload.message ? ` ${dependencyTrackPayload.message}` : "";
          } catch {
            dependencyTrackFailed = true;
            dependencyTrackMessage = " Передача в Dependency-Track не подтверждена: нет ответа от платформы.";
          }
        }
        setRunResult({
          ok: cvePayload.ok,
          partial: Boolean(cvePayload.partial || dependencyTrackFailed),
          action,
          message: `${cvePayload.message ?? (cvePayload.ok ? "CVE-аудит пакетов выполнен." : "Не удалось выполнить CVE-аудит пакетов.")}${dependencyTrackMessage}`,
          stdout: payload.stdout,
          stderr: payload.stderr,
        });
        await loadHosts();
        if (cvePayload.ok && cvePayload.reportId) {
          setFreshReportHref(`/reports/agentless/${encodeURIComponent(cvePayload.reportId)}`);
        }
      }
      if (payload.ok && action !== "packageInventory" && payload.reportId) {
        setFreshReportHref(`/reports/agentless/${encodeURIComponent(payload.reportId)}`);
      }
      if (payload.ok && payload.postAuditReportId) {
        setFreshReportHref(`/reports/agentless/${encodeURIComponent(payload.postAuditReportId)}`);
      }
    } catch {
      setRunResult({ ok: false, action, message: "Ответ на запуск не получен. Проверьте журнал действий и отчёты перед повторным запуском." });
    } finally {
      setLoading("");
    }
  }

  async function importGreenboneReport() {
    if (!selectedAlias || !greenboneFile) {
      setGreenboneMessage("Выберите хост и XML-файл отчёта Greenbone.");
      return;
    }
    setLoading("greenboneImport");
    setGreenboneMessage("");
    setFreshReportHref("");
    try {
      const form = new FormData();
      form.set("hostAlias", selectedAlias);
      form.set("report", greenboneFile);
      const response = await fetch("/api/ansible/greenbone/import", { method: "POST", body: form });
      const payload = await response.json();
      setGreenboneMessage(payload.message ?? "Не удалось импортировать отчёт Greenbone.");
      setRunResult({ ok: payload.ok, partial: payload.partial, action: "greenboneImport", message: payload.message });
      if (payload.ok && payload.reportId) {
        setFreshReportHref(`/reports/agentless/${encodeURIComponent(payload.reportId)}`);
        setGreenboneFile(null);
        await loadHosts();
      }
    } finally {
      setLoading("");
    }
  }

  async function rollbackTransaction(transaction: RemediationTransaction) {
    const confirmedHost = window.prompt(`Введите alias ${transaction.hostAlias} для отката:`);
    if (confirmedHost?.trim() !== transaction.hostAlias) {
      return;
    }
    setLoading(`rollback-${transaction.id}`);
    setRunResult(null);
    try {
      const response = await fetch(`/api/ansible/remediations/${encodeURIComponent(transaction.id)}/rollback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirmedHost: confirmedHost.trim() }),
      });
      setRunResult(await response.json());
      await loadRemediations();
      await loadHosts();
    } finally {
      setLoading("");
    }
  }

  function fillHostForm(host: ManagedHost) {
    setSelectedAlias(host.alias);
    setManualAlias(host.alias);
    setManualAddress(host.address);
    setManualUser(host.user ?? "");
    setManualPort(String(host.port ?? 22));
    setManualGroup(host.groups[0] ?? "linux_hosts");
    setManualBecome(Boolean(host.become));
  }

  const summary = hosts?.summary;

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Управление хостами</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">Проверка безопасности</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            Выберите хост, запустите аудит и просмотрите результат. Изменения firewall выполняются отдельно, с планом и откатом.
          </p>
        </div>
        <Button variant="secondary" onClick={refreshAll} disabled={Boolean(loading)}>
          <RefreshCw size={16} className={loading === "refresh" ? "animate-spin" : ""} aria-hidden="true" />
          Обновить данные
        </Button>
      </header>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Сводка">
        <StatusTile label="Ansible" value={health?.ansibleInstalled ? "Готов" : "Не готов"} good={health ? Boolean(health.ansibleInstalled) : undefined} />
        <StatusTile label="Inventory" value={hosts?.inventoryReady ? "Готов" : "Не готов"} good={hosts ? Boolean(hosts.inventoryReady) : undefined} />
        <StatusTile label="Хосты" value={summary?.total ?? 0} />
        <StatusTile label="Последние аудиты" value={summary?.withReports ?? 0} />
      </section>

      <details className="group rounded-md border border-slate-800 bg-slate-950/70" open={!hosts?.hosts?.length}>
        <summary className="flex cursor-pointer items-center justify-between gap-4 p-4 text-left">
          <span>
            <span className="block text-base font-semibold text-white">Добавить или изменить хост</span>
            <span className="mt-1 block text-sm text-slate-400">Укажите SSH-подключение, проверьте его и сохраните в inventory.</span>
          </span>
          <span className="text-sm text-sky-200 group-open:hidden">Открыть</span>
          <span className="hidden text-sm text-slate-400 group-open:block">Свернуть</span>
        </summary>
        <div className="border-t border-slate-800 p-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
          <Field label="Имя хоста" value={manualAlias} onChange={setManualAlias} placeholder="web-01" />
          <Field label="IP-адрес или домен" value={manualAddress} onChange={setManualAddress} placeholder="192.168.1.10" />
          <Field label="Пользователь SSH" value={manualUser} onChange={setManualUser} placeholder="admin" />
          <Field label="Порт SSH" value={manualPort} onChange={setManualPort} placeholder="22" />
          <Field label="Группа inventory" value={manualGroup} onChange={setManualGroup} placeholder="linux_hosts" />
          <label className="flex h-10 min-w-0 items-center gap-2 self-end rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={manualBecome}
              onChange={(event) => setManualBecome(event.target.checked)}
              className="h-4 w-4 rounded border-slate-600 bg-slate-950"
            />
            Использовать sudo
          </label>
          <Button variant="secondary" onClick={checkPreflight} disabled={Boolean(loading) || !manualAlias || !manualAddress || !manualUser} className="w-full self-end">
            <CheckCircle2 size={16} className={loading === "preflight" ? "animate-spin" : ""} aria-hidden="true" />
            Проверить подключение
          </Button>
          <Button onClick={addManualHost} disabled={Boolean(loading) || !manualAlias || !manualAddress || !manualUser} className="w-full self-end">
            <Plus size={16} aria-hidden="true" />
            Добавить в inventory
          </Button>
          <Button variant="secondary" onClick={updateManualHost} disabled={Boolean(loading) || !manualAlias || !manualAddress || !manualUser} className="w-full self-end">
            Сохранить изменения
          </Button>
          <Button variant="danger" onClick={deleteSelectedHost} disabled={Boolean(loading) || !selectedAlias} className="w-full self-end">
            Удалить хост
          </Button>
        </div>
        <section className="mt-4 rounded-md border border-sky-400/25 bg-sky-500/5 p-4" aria-labelledby="connection-wizard-title">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex gap-3">
              <KeyRound size={20} className="mt-0.5 shrink-0 text-sky-200" aria-hidden="true" />
              <div>
                <h3 id="connection-wizard-title" className="font-semibold text-white">Мастер первого SSH-подключения</h3>
                <p className="mt-1 max-w-3xl text-sm leading-5 text-slate-300">
                  Пароли в платформу не вводятся и не сохраняются. Сначала добавьте ключ узла управления на хост, затем подтвердите SSH fingerprint через независимый канал.
                </p>
              </div>
            </div>
            <Button variant="secondary" onClick={loadControlKey} disabled={Boolean(accessLoading)}>
              <RefreshCw size={16} className={accessLoading === "key" ? "animate-spin" : ""} aria-hidden="true" />
              Обновить ключ
            </Button>
          </div>

          {access?.ok && access.publicKey ? (
            <ol className="mt-4 grid gap-3 lg:grid-cols-3">
              <li className="rounded-md border border-slate-700 bg-slate-950/70 p-3">
                <p className="text-sm font-semibold text-white">1. Добавьте ключ на хост</p>
                <p className="mt-1 text-xs leading-5 text-slate-400">
                  Откройте консоль ВМ или используйте уже выданный временный доступ. Выполните команду только на выбранном целевом хосте.
                </p>
                <code className="mt-3 block break-all rounded bg-slate-900 p-2 text-xs text-sky-100">{access.publicKey}</code>
                <Button variant="secondary" className="mt-2 w-full" onClick={() => copyToClipboard(access.publicKey ?? "", "public-key")}>
                  <Copy size={15} aria-hidden="true" />
                  {copied === "public-key" ? "Скопировано" : "Скопировать ключ"}
                </Button>
                <code className="mt-2 block break-all rounded bg-slate-900 p-2 text-xs text-slate-300">{installPublicKeyCommand}</code>
                <Button variant="secondary" className="mt-2 w-full" onClick={() => copyToClipboard(installPublicKeyCommand, "install-command")}>
                  <Copy size={15} aria-hidden="true" />
                  {copied === "install-command" ? "Скопировано" : "Скопировать команду"}
                </Button>
              </li>

              <li className="rounded-md border border-slate-700 bg-slate-950/70 p-3">
                <p className="text-sm font-semibold text-white">2. Подтвердите ключ сервера</p>
                <p className="mt-1 text-xs leading-5 text-slate-400">
                  Укажите выше адрес и порт SSH. Сверьте fingerprint с консолью гипервизора, панелью провайдера или утверждённым реестром ключей — не с результатом сканирования.
                </p>
                <Button variant="secondary" className="mt-3 w-full" onClick={scanHostFingerprint} disabled={Boolean(accessLoading) || !manualAddress}>
                  <Search size={15} className={accessLoading === "scan" ? "animate-pulse" : ""} aria-hidden="true" />
                  Получить fingerprint по сети
                </Button>
                {hostKeyScan?.fingerprints?.length ? (
                  <div className="mt-2 space-y-1" aria-label="Неподтверждённые fingerprints">
                    {hostKeyScan.fingerprints.map((item) => (
                      <button
                        key={`${item.algorithm}-${item.fingerprint}`}
                        onClick={() => setTrustedFingerprint(item.fingerprint)}
                        className="block w-full break-all rounded border border-amber-400/25 bg-amber-500/10 p-2 text-left text-xs text-amber-100"
                        title="Подставить для сравнения после независимой проверки"
                      >
                        {item.algorithm}: {item.fingerprint}
                      </button>
                    ))}
                  </div>
                ) : null}
                <Field label="Подтверждённый SHA256 fingerprint" value={trustedFingerprint} onChange={setTrustedFingerprint} placeholder="SHA256:…" />
                <Button className="mt-2 w-full" onClick={trustScannedHostKey} disabled={Boolean(accessLoading) || !manualAddress || !trustedFingerprint}>
                  <ShieldCheck size={15} className={accessLoading === "trust" ? "animate-pulse" : ""} aria-hidden="true" />
                  Сохранить проверенный ключ
                </Button>
              </li>

              <li className="rounded-md border border-slate-700 bg-slate-950/70 p-3">
                <p className="text-sm font-semibold text-white">3. Проверьте и добавьте</p>
                <p className="mt-1 text-xs leading-5 text-slate-400">
                  Нажмите «Проверить подключение». Платформа проверит SSH, Python, sudo и предпосылки аудита. Для добавления достаточно рабочего подключения; подготовка сканеров показана отдельно.
                </p>
                <div className="mt-3 rounded bg-slate-900 p-2 text-xs leading-5 text-slate-300">
                  Fingerprint узла управления: <span className="break-all text-sky-100">{access.fingerprint ?? "не определён"}</span>
                </div>
              </li>
            </ol>
          ) : (
            <p className="mt-3 rounded-md border border-slate-700 bg-slate-950/70 p-3 text-sm text-slate-300">
              {accessLoading === "key" ? "Загружается публичный ключ узла управления…" : access?.message ?? "Публичный ключ узла управления пока недоступен."}
            </p>
          )}
          {accessMessage ? <p className="mt-3 text-sm text-amber-100" role="status">{accessMessage}</p> : null}
        </section>
        {preflight && preflightFor === connectionSignature ? (
          <>
          <div className="mt-3 grid gap-2 text-sm md:grid-cols-4">
            <CheckBadge label="SSH" ok={preflight.checks?.ssh.ok} text={preflight.checks?.ssh.message ?? preflight.message ?? ""} />
            <CheckBadge label="Python" ok={preflight.checks?.python.ok} text={preflight.checks?.python.message ?? ""} />
            <CheckBadge label="sudo" ok={preflight.checks?.sudo.ok} text={preflight.checks?.sudo.message ?? ""} />
            <CheckBadge label="OS" ok={Boolean(preflight.facts?.os)} text={preflight.facts?.os ?? "не определена"} />
          </div>
          {preflight.readiness ? (
            <section className="mt-3 rounded-md border border-slate-700 bg-slate-950/70 p-3" aria-label="Готовность к аудиту">
              <h3 className="text-sm font-semibold text-white">Готовность к аудиту</h3>
              <p className="mt-1 break-words text-xs leading-5 text-slate-400">
                {preflight.readiness.astraVersion ? `Выпуск Astra: ${preflight.readiness.astraVersion}. ` : ""}
                Ядро: {preflight.readiness.kernel}. Python: {preflight.readiness.pythonVersion}.
              </p>
              <div className="mt-3 grid gap-2 lg:grid-cols-2">
                {preflight.readiness.checks.map((check) => (
                  <div key={check.id} className="min-w-0 rounded border border-slate-800 p-3">
                    <div className="flex flex-wrap items-start justify-between gap-2 text-xs">
                      <span className="font-semibold text-slate-200">{check.title}</span>
                      <span className={check.state === "ready" ? "text-sky-200" : "text-amber-200"}>
                        {{ ready: "Предпосылки выполнены", needs_setup: "Нужна подготовка", unsupported: "Покрытие не подтверждено", unknown: "Не определено" }[check.state]}
                      </span>
                    </div>
                    <p className="mt-2 break-words text-xs leading-5 text-slate-400">{check.detail}</p>
                  </div>
                ))}
              </div>
              {preflight.readiness.notes.map((note, index) => <p key={index} className="mt-2 break-words text-xs leading-5 text-slate-400">{note}</p>)}
            </section>
          ) : preflight.readinessError ? <p className="mt-2 text-sm text-amber-200" role="status">Готовность к аудиту не подтверждена: {preflight.readinessError}</p> : null}
          </>
        ) : null}
        <details className="mt-3 rounded-md border border-slate-800 bg-slate-900/70 p-3">
          <summary className="cursor-pointer text-sm font-semibold text-slate-200">Найти хосты в разрешённой подсети</summary>
          <p className="mt-1 text-xs leading-5 text-slate-400">Проверка ищет только SSH в выбранной приватной подсети и не добавляет хосты автоматически.</p>
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Подсеть CIDR" value={scanCidr} onChange={setScanCidr} placeholder="192.168.1.0/24" />
            <Button variant="secondary" onClick={detectNetwork} disabled={Boolean(loading)}>
              <Search size={16} aria-hidden="true" />
              Подставить подсеть
            </Button>
            <Button variant="secondary" onClick={scanNetwork} disabled={Boolean(loading) || !scanCidr}>
              <Search size={16} className={loading === "scan" ? "animate-pulse" : ""} aria-hidden="true" />
              Найти SSH-хосты
            </Button>
          </div>
          {discovery?.candidates?.length ? (
            <div className="mt-2 flex flex-wrap gap-2">
              {discovery.candidates.map((candidate) => (
                <button
                  key={candidate.cidr}
                  onClick={() => setScanCidr(candidate.cidr)}
                  className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-slate-300"
                >
                  {candidate.cidr}{candidate.device ? ` · ${candidate.device}` : ""}
                </button>
              ))}
            </div>
          ) : null}
          {discovery?.found?.length ? (
            <div className="mt-2 flex flex-wrap gap-2">
              {discovery.found.filter((host) => host.sshOpen).map((host) => (
                <button
                  key={host.ip}
                  onClick={() => {
                    setManualAddress(host.ip);
                    setManualAlias(host.alias);
                  }}
                  className="rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-100"
                >
                  {host.ip}
                </button>
              ))}
            </div>
          ) : null}
        </details>
        </div>
      </details>

      <section className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
        <div className="flex flex-col gap-3 border-b border-slate-800 p-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">Управляемые хосты</h2>
            <p className="mt-1 text-sm text-slate-400">Нажмите «Выбрать», затем выполните аудит в следующем блоке.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <select
              value={profileId}
              onChange={(event) => setProfileId(event.target.value)}
              className="h-10 rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
            >
              {profileOptions.map((profile) => (
                <option key={profile.id} value={profile.id}>{profile.label}</option>
              ))}
            </select>
            <LinkButton href="/reports" variant="secondary">
              <FileText size={16} aria-hidden="true" />
              Отчеты
            </LinkButton>
          </div>
        </div>

        {hosts?.hosts?.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[880px] text-left text-sm">
              <thead className="bg-slate-900/70 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Хост</th>
                  <th className="px-4 py-3">SSH</th>
                  <th className="px-4 py-3">Оценка</th>
                  <th className="px-4 py-3">Риски</th>
                  <th className="px-4 py-3">Последний аудит</th>
                  <th className="px-4 py-3">Действия</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {hosts.hosts.map((host) => (
                  <tr key={host.alias} className={selectedAlias === host.alias ? "bg-sky-500/5" : ""}>
                    <td className="px-4 py-4">
                      <button onClick={() => fillHostForm(host)} className="text-left">
                        <span className="block font-semibold text-white">{host.alias}</span>
                        <span className="mt-1 block text-xs text-slate-500">{host.address}</span>
                      </button>
                    </td>
                    <td className="px-4 py-4 text-slate-300">
                      <span>{host.user ?? "не указан"}</span>
                      <span className={host.become ? "ml-2 text-emerald-200" : "ml-2 text-slate-500"}>
                        {host.become ? "sudo" : "без sudo"}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold ${scoreTone(host.lastReport?.score)}`}>
                        {host.lastReport?.score === null || host.lastReport?.score === undefined ? "нет" : `${host.lastReport.score}%`}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-xs">
                      {host.lastReport ? (
                        <div className="grid grid-cols-4 gap-1">
                          <span className="rounded-md bg-red-500/15 px-2 py-1 text-red-100" title="Высокий риск">Выс. {host.lastReport.high}</span>
                          <span className="rounded-md bg-amber-500/15 px-2 py-1 text-amber-100" title="Средний риск">Ср. {host.lastReport.medium}</span>
                          <span className="rounded-md bg-sky-500/15 px-2 py-1 text-sky-100" title="Низкий риск">Низ. {host.lastReport.low}</span>
                          <span className="rounded-md bg-slate-800 px-2 py-1 text-slate-300" title="Информационная запись">Инф. {host.lastReport.info}</span>
                        </div>
                      ) : (
                        <span className="text-slate-500">нет данных</span>
                      )}
                    </td>
                    <td className="px-4 py-4 text-slate-300">{formatDate(host.lastReport?.createdAt)}</td>
                    <td className="px-4 py-4">
                      <div className="flex flex-wrap gap-2">
                        <Button variant="secondary" onClick={() => fillHostForm(host)}>
                          Настроить
                        </Button>
                        {host.lastReport ? (
                          <LinkButton href={reportHref(host.lastReport.fileName)} variant="secondary">
                            Последний аудит
                          </LinkButton>
                        ) : null}
                        <LinkButton href={`/reports/agentless?host=${encodeURIComponent(host.alias)}`} variant="secondary">
                          История ({host.reportCount})
                        </LinkButton>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-5 text-sm leading-6 text-slate-400">Добавьте первый хост через форму выше. После проверки подключения он появится здесь.</div>
        )}
      </section>

      <section className="grid gap-5">
        <div id="ansible-actions" className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Аудит хоста</h2>
              <p className="mt-1 text-sm text-slate-400">
                Хост: <span className="font-semibold text-slate-100">{selectedHost?.alias ?? "не выбран"}</span>
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <label className="block">
                <span className="sr-only">Профиль аудита</span>
                <select
                  value={profileId}
                  onChange={(event) => setProfileId(event.target.value)}
                  className="h-10 rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
                >
                  {profileOptions.map((profile) => (
                    <option key={profile.id} value={profile.id}>{profile.label}</option>
                  ))}
                </select>
              </label>
              {primaryAuditActions.map((action) => {
                const Icon = action.icon;
                return (
                  <Button key={action.id} variant={action.id === "agentlessAudit" ? "primary" : "secondary"} onClick={() => runAction(action.id)} disabled={Boolean(loading) || !selectedHost}>
                    <Icon size={16} className={loading === action.id ? "animate-spin" : ""} aria-hidden="true" />
                    {action.label}
                  </Button>
                );
              })}
            </div>
          </div>

          <details className="mt-4 rounded-md border border-slate-800 bg-slate-900/70 p-3">
            <summary className="cursor-pointer text-sm font-semibold text-slate-200">Дополнительные проверки</summary>
            <p className="mt-1 text-xs leading-5 text-slate-400">Используйте их, когда обычного аудита недостаточно.</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {additionalAuditActions.map((action) => {
                const Icon = action.icon;
                return (
                  <Button key={action.id} variant="secondary" onClick={() => runAction(action.id)} disabled={Boolean(loading) || !selectedHost}>
                    <Icon size={16} className={loading === action.id ? "animate-spin" : ""} aria-hidden="true" />
                    {action.label}
                  </Button>
                );
              })}
            </div>
          </details>

          <details className="mt-4 rounded-md border border-slate-800 bg-slate-900/70 p-3">
            <summary className="cursor-pointer text-sm font-semibold text-slate-200">Импорт сетевого отчёта Greenbone / OpenVAS</summary>
            <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-400">
              Greenbone запускается отдельным сканером сети. Экспортируйте завершённый report в XML и привяжите его к выбранному хосту: результаты не смешиваются с SSH и CVE-аудитом.
            </p>
            <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-end">
              <label className="block min-w-0 flex-1">
                <span className="text-xs font-semibold text-slate-400">XML-отчёт Greenbone (до 20 МБ)</span>
                <input
                  type="file"
                  accept=".xml,application/xml,text/xml"
                  onChange={(event) => setGreenboneFile(event.target.files?.[0] ?? null)}
                  className="mt-2 block w-full text-sm text-slate-300 file:mr-3 file:rounded-md file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-sm file:text-slate-100"
                />
              </label>
              <Button variant="secondary" onClick={importGreenboneReport} disabled={Boolean(loading) || !selectedHost || !greenboneFile}>
                <Upload size={16} className={loading === "greenboneImport" ? "animate-pulse" : ""} aria-hidden="true" />
                Импортировать XML
              </Button>
            </div>
            {greenboneMessage ? <p className="mt-3 text-xs leading-5 text-slate-300" role="status">{greenboneMessage}</p> : null}
          </details>

          <details className="mt-4 rounded-md border border-amber-400/20 bg-amber-500/5 p-3">
            <summary className="cursor-pointer text-sm font-semibold text-amber-100">Обратимые изменения firewall</summary>
            <p className="mt-1 text-xs leading-5 text-slate-400">
              Сначала проверьте план. При применении платформа создаёт резервную копию firewall, выполняет изменение и запускает повторный аудит.
            </p>
            <div className="mt-3 grid gap-3 lg:grid-cols-3">
              <Field label="Причина изменения" value={changeReason} onChange={setChangeReason} placeholder="Например: закрытие Telnet по результату аудита" />
              <Field label="Подтверждение" value={confirmedHost} onChange={setConfirmedHost} placeholder={selectedHost?.alias ?? "Введите alias хоста"} />
              <p className="self-end pb-2 text-xs leading-5 text-slate-400">Для плана и применения введите точный alias выбранного хоста.</p>
            </div>
            <div className="mt-3 grid gap-3 lg:grid-cols-2">
              <div className="rounded-md border border-slate-800 bg-slate-950/60 p-3">
                <p className="font-semibold text-slate-100">Закрыть порт</p>
                <div className="mt-3 grid grid-cols-2 gap-3">
                  <Field label="Порт" value={targetPort} onChange={setTargetPort} placeholder="23" />
                  <label className="block">
                    <span className="text-xs font-semibold uppercase text-slate-500">Протокол</span>
                    <select value={targetProtocol} onChange={(event) => setTargetProtocol(event.target.value)} className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100">
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                  </label>
                </div>
                <ActionPair action={responseActions[0]} loading={loading} disabled={!selectedHost} onRun={runAction} />
              </div>
              <div className="rounded-md border border-slate-800 bg-slate-950/60 p-3">
                <p className="font-semibold text-slate-100">Заблокировать IP-адрес</p>
                <div className="mt-3"><Field label="IP-адрес" value={blockIp} onChange={setBlockIp} placeholder="192.168.1.50" /></div>
                <ActionPair action={responseActions[1]} loading={loading} disabled={!selectedHost} onRun={runAction} />
              </div>
            </div>
          </details>
        </div>

        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-white">Последние изменения</h2>
              <p className="mt-1 text-sm text-slate-400">Резервную копию можно восстановить после применения или ошибки изменения.</p>
            </div>
            <Button variant="secondary" onClick={loadRemediations} disabled={Boolean(loading)}>
              <RefreshCw size={16} aria-hidden="true" />
              Обновить
            </Button>
          </div>
          {transactions.length ? (
            <div className="mt-4 space-y-2">
              {transactions.slice(0, 8).map((transaction) => (
                <div key={transaction.id} className="flex flex-col gap-3 rounded-md border border-slate-800 bg-slate-900/70 p-3 lg:flex-row lg:items-center lg:justify-between">
                  <div className="min-w-0 text-sm">
                    <p className="font-semibold text-slate-100">{transactionActionLabels[transaction.action] ?? transaction.action} · {transaction.hostAlias}</p>
                    <p className="mt-1 text-xs text-slate-400">{formatDate(transaction.createdAt)} · {transactionStatusLabels[transaction.status]} · {transaction.reason}</p>
                    {transaction.error ? <p className="mt-1 text-xs text-red-200">{transaction.error}</p> : null}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {transaction.postAuditReportId ? (
                      <LinkButton href={`/reports/agentless/${encodeURIComponent(transaction.postAuditReportId)}`} variant="secondary">
                        Отчёт после изменения
                      </LinkButton>
                    ) : null}
                    {transaction.backupRef && ["applied", "failed", "rollback_failed"].includes(transaction.status) ? (
                      <Button variant="danger" onClick={() => rollbackTransaction(transaction)} disabled={Boolean(loading)}>
                        <RotateCcw size={16} aria-hidden="true" />
                        Откатить
                      </Button>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          ) : <p className="mt-4 text-sm text-slate-500">Изменений пока не было.</p>}
        </section>

        <aside className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="text-lg font-semibold text-white">Последний запуск</h2>
          {runResult ? (
            <div className="mt-3 space-y-3 text-sm">
              <div className={`rounded-md border p-3 ${
                !runResult.ok ? "border-red-400/30 bg-red-500/10 text-red-100" : runResult.partial ? "border-amber-400/30 bg-amber-500/10 text-amber-100" : "border-emerald-400/30 bg-emerald-500/10 text-emerald-100"
              }`}>
                <p className="font-semibold">{!runResult.ok ? "Ошибка" : runResult.partial ? "Выполнено с ограничениями" : "Выполнено"}</p>
                {runResult.message ? <p className="mt-1">{runResult.message}</p> : null}
                {runResult.warnings?.length ? <ul className="mt-2 list-inside list-disc space-y-1">{runResult.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul> : null}
                {freshReportHref ? (
                  <LinkButton href={freshReportHref} variant="secondary" className="mt-3 w-full bg-slate-950/60">
                    Открыть отчет
                  </LinkButton>
                ) : null}
              </div>
              {(runResult.stdout || runResult.stderr) ? (
                <details className="rounded-md border border-slate-800 bg-slate-900/70 p-3">
                  <summary className="cursor-pointer text-xs font-semibold text-slate-300">Технический вывод запуска</summary>
                  <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs leading-5 text-slate-200">
{`${runResult.stdout ?? ""}${runResult.stderr ? `\n\nSTDERR:\n${runResult.stderr}` : ""}`}
                  </pre>
                </details>
              ) : null}
            </div>
          ) : (
            <p className="mt-3 text-sm leading-6 text-slate-400">Выберите хост и запустите аудит. Здесь появится понятный результат и ссылка на отчёт.</p>
          )}
        </aside>
      </section>
    </div>
  );
}

function StatusTile({
  label,
  value,
  good,
}: {
  label: string;
  value: string | number;
  good?: boolean;
}) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
      <p className="text-xs font-semibold uppercase text-slate-500">{label}</p>
      <p className={good === false ? "mt-2 text-2xl font-semibold text-red-100" : "mt-2 text-2xl font-semibold text-white"}>
        {value}
      </p>
    </div>
  );
}

function CheckBadge({
  label,
  ok,
  text,
}: {
  label: string;
  ok?: boolean;
  text: string;
}) {
  return (
    <div className={`rounded-md border p-3 ${
      ok ? "border-emerald-400/30 bg-emerald-500/10" : "border-red-400/30 bg-red-500/10"
    }`}>
      <p className={ok ? "font-semibold text-emerald-100" : "font-semibold text-red-100"}>
        {label}: {ok ? "готово" : "ошибка"}
      </p>
      <p className="mt-1 break-words text-xs leading-5 text-slate-300">{text || "нет данных"}</p>
    </div>
  );
}

function ActionPair({
  action,
  loading,
  disabled,
  onRun,
}: {
  action: (typeof responseActions)[number];
  loading: string;
  disabled: boolean;
  onRun: (action: string, mode: "preview" | "apply") => void;
}) {
  const Icon = action.icon;
  return (
    <div className="mt-3 flex overflow-hidden rounded-md border border-slate-700">
      <Button variant="secondary" onClick={() => onRun(action.id, "preview")} disabled={Boolean(loading) || disabled} className="flex-1 rounded-none border-0 px-3">
        Проверить план
      </Button>
      <Button variant="danger" onClick={() => onRun(action.id, "apply")} disabled={Boolean(loading) || disabled} className="flex-1 rounded-none border-0 px-3">
        <Icon size={16} className={loading === action.id ? "animate-spin" : ""} aria-hidden="true" />
        Применить
      </Button>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="block min-w-0">
      <span className="text-xs font-semibold text-slate-400">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
      />
    </label>
  );
}
