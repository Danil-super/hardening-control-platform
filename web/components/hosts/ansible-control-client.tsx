"use client";

import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  FileText,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldCheck,
  Terminal,
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
  status: "preparing" | "backed_up" | "applied" | "failed" | "rolled_back";
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

const profileOptions = [
  { id: "basic_linux", label: "Linux" },
  { id: "ssh_security", label: "SSH" },
  { id: "web_server", label: "Web" },
  { id: "docker_host", label: "Docker" },
] as const;

const auditActions = [
  { id: "ping", label: "Ping", icon: Server },
  { id: "collectFacts", label: "Факты", icon: FileText },
  { id: "agentlessAudit", label: "Аудит", icon: ShieldCheck },
  { id: "packageInventory", label: "CVE пакеты", icon: FileText },
  { id: "collectEvents", label: "События", icon: Terminal },
  { id: "sshCryptoAudit", label: "SSH crypto", icon: ShieldCheck },
  { id: "networkPortScan", label: "Порты", icon: Search, requiresConfirmation: true },
  { id: "lynisTemporaryAudit", label: "Lynis временно", icon: ShieldCheck, requiresConfirmation: true },
] as const;

const responseActions = [
  { id: "closePort", label: "Закрыть порт", icon: Ban },
  { id: "blockIp", label: "Блок IP", icon: AlertTriangle },
] as const;

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
  const [manualAlias, setManualAlias] = useState("server1");
  const [manualAddress, setManualAddress] = useState("");
  const [manualUser, setManualUser] = useState("danil");
  const [manualPort, setManualPort] = useState("22");
  const [manualGroup, setManualGroup] = useState("linux_hosts");
  const [manualBecome, setManualBecome] = useState(true);
  const [preflight, setPreflight] = useState<PreflightPayload | null>(null);
  const [scanCidr, setScanCidr] = useState("");
  const [discovery, setDiscovery] = useState<DiscoveryPayload | null>(null);
  const [targetPort, setTargetPort] = useState("23");
  const [targetProtocol, setTargetProtocol] = useState("tcp");
  const [blockIp, setBlockIp] = useState("");
  const [changeReason, setChangeReason] = useState("");
  const [transactions, setTransactions] = useState<RemediationTransaction[]>([]);

  const selectedHost = useMemo(
    () => hosts?.hosts?.find((host) => host.alias === selectedAlias) ?? null,
    [hosts, selectedAlias],
  );

  useEffect(() => {
    void refreshAll();
  }, []);

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

  async function addManualHost() {
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
    const confirmedHost = isResponse
      ? window.prompt(`Введите alias ${selectedAlias} для ${mode === "preview" ? "проверки плана" : "применения изменения"}:`)
      : null;
    if (isResponse && confirmedHost?.trim() !== selectedAlias) {
      setRunResult({ ok: false, action, message: "Alias не подтвержден: действие отменено." });
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
          confirmedHost: confirmedHost?.trim(),
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
        setRunResult({
          ok: cvePayload.ok,
          action,
          message: cvePayload.ok
            ? "CVE-аудит пакетов выполнен."
            : cvePayload.message ?? "Не удалось выполнить CVE-аудит пакетов.",
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
    <div className="space-y-5">
      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        <StatusTile label="Ansible" value={health?.ansibleInstalled ? "OK" : "нет"} good={Boolean(health?.ansibleInstalled)} />
        <StatusTile label="Inventory" value={hosts?.inventoryReady ? "OK" : "нет"} good={Boolean(hosts?.inventoryReady)} />
        <StatusTile label="Хосты" value={summary?.total ?? 0} />
        <StatusTile label="С отчетами" value={summary?.withReports ?? 0} />
        <StatusTile label="Средний score" value={summary?.averageScore === null || summary?.averageScore === undefined ? "нет" : `${summary.averageScore}%`} />
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
          <Field label="Alias" value={manualAlias} onChange={setManualAlias} placeholder="web-01" />
          <Field label="IP/host" value={manualAddress} onChange={setManualAddress} placeholder="192.168.1.10" />
          <Field label="SSH user" value={manualUser} onChange={setManualUser} placeholder="danil" />
          <Field label="Port" value={manualPort} onChange={setManualPort} placeholder="22" />
          <Field label="Group" value={manualGroup} onChange={setManualGroup} placeholder="linux_hosts" />
          <label className="flex h-10 min-w-0 items-center gap-2 self-end rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={manualBecome}
              onChange={(event) => setManualBecome(event.target.checked)}
              className="h-4 w-4 rounded border-slate-600 bg-slate-950"
            />
            sudo
          </label>
          <Button variant="secondary" onClick={checkPreflight} disabled={Boolean(loading) || !manualAlias || !manualAddress || !manualUser} className="w-full self-end">
            <CheckCircle2 size={16} className={loading === "preflight" ? "animate-spin" : ""} aria-hidden="true" />
            Проверить
          </Button>
          <Button onClick={addManualHost} disabled={Boolean(loading) || !manualAlias || !manualAddress || !manualUser} className="w-full self-end">
            <Plus size={16} aria-hidden="true" />
            Сохранить
          </Button>
          <Button variant="secondary" onClick={updateManualHost} disabled={Boolean(loading) || !manualAlias || !manualAddress || !manualUser} className="w-full self-end">
            Изменить
          </Button>
          <Button variant="danger" onClick={deleteSelectedHost} disabled={Boolean(loading) || !selectedAlias} className="w-full self-end">
            Удалить
          </Button>
        </div>
        {preflight ? (
          <div className="mt-3 grid gap-2 text-sm md:grid-cols-4">
            <CheckBadge label="SSH" ok={preflight.checks?.ssh.ok} text={preflight.checks?.ssh.message ?? preflight.message ?? ""} />
            <CheckBadge label="Python" ok={preflight.checks?.python.ok} text={preflight.checks?.python.message ?? ""} />
            <CheckBadge label="sudo" ok={preflight.checks?.sudo.ok} text={preflight.checks?.sudo.message ?? ""} />
            <CheckBadge label="OS" ok={Boolean(preflight.facts?.os)} text={preflight.facts?.os ?? "не определена"} />
          </div>
        ) : null}
        <div className="mt-3 rounded-md border border-slate-800 bg-slate-900/70 p-3">
          <div className="flex flex-wrap items-end gap-2">
            <Field label="CIDR scan" value={scanCidr} onChange={setScanCidr} placeholder="192.168.1.0/24" />
            <Button variant="secondary" onClick={detectNetwork} disabled={Boolean(loading)}>
              <Search size={16} aria-hidden="true" />
              Подсеть
            </Button>
            <Button variant="secondary" onClick={scanNetwork} disabled={Boolean(loading) || !scanCidr}>
              <Search size={16} className={loading === "scan" ? "animate-pulse" : ""} aria-hidden="true" />
              Найти SSH
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
        </div>
      </section>

      <section className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
        <div className="flex flex-col gap-3 border-b border-slate-800 p-4 lg:flex-row lg:items-center lg:justify-between">
          <h2 className="text-lg font-semibold text-white">Хосты</h2>
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
            <Button variant="secondary" onClick={refreshAll} disabled={Boolean(loading)}>
              <RefreshCw size={16} className={loading === "refresh" ? "animate-spin" : ""} aria-hidden="true" />
              Обновить
            </Button>
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
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Риски</th>
                  <th className="px-4 py-3">Последний отчет</th>
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
                      <span>{host.user ?? "user ?"}</span>
                      <span className={host.become ? "ml-2 text-emerald-200" : "ml-2 text-slate-500"}>
                        {host.become ? "sudo" : "no sudo"}
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
                          <span className="rounded-md bg-red-500/15 px-2 py-1 text-red-100">H {host.lastReport.high}</span>
                          <span className="rounded-md bg-amber-500/15 px-2 py-1 text-amber-100">M {host.lastReport.medium}</span>
                          <span className="rounded-md bg-sky-500/15 px-2 py-1 text-sky-100">L {host.lastReport.low}</span>
                          <span className="rounded-md bg-slate-800 px-2 py-1 text-slate-300">I {host.lastReport.info}</span>
                        </div>
                      ) : (
                        <span className="text-slate-500">нет данных</span>
                      )}
                    </td>
                    <td className="px-4 py-4 text-slate-300">{formatDate(host.lastReport?.createdAt)}</td>
                    <td className="px-4 py-4">
                      <div className="flex flex-wrap gap-2">
                        <Button variant="secondary" onClick={() => fillHostForm(host)}>
                          Выбрать
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
          <div className="p-5 text-sm text-slate-400">Добавьте первый хост, затем запустите Ping или Аудит.</div>
        )}
      </section>

      <section className="grid gap-5">
        <div id="ansible-actions" className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Действия</h2>
              <p className="mt-1 text-sm text-slate-400">
                Хост: <span className="text-slate-100">{selectedHost?.alias ?? "не выбран"}</span>
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {auditActions.map((action) => {
                const Icon = action.icon;
                return (
                  <Button key={action.id} onClick={() => runAction(action.id)} disabled={Boolean(loading) || !selectedHost}>
                    <Icon size={16} className={loading === action.id ? "animate-spin" : ""} aria-hidden="true" />
                    {action.label}
                  </Button>
                );
              })}
            </div>
          </div>

          <div className="mt-4 rounded-md border border-slate-800 bg-slate-900/70 p-3">
            <p className="text-sm font-semibold text-slate-100">Обратимые изменения</p>
            <p className="mt-1 text-xs leading-5 text-slate-400">
              Сначала выполните dry-run. При применении платформа сохраняет firewall-конфигурацию на хосте,
              запускает действие и повторный аудит. Введите alias хоста для каждого изменения.
            </p>
            <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Field label="Порт" value={targetPort} onChange={setTargetPort} placeholder="23" />
              <label className="block">
                <span className="text-xs font-semibold uppercase text-slate-500">Протокол</span>
                <select
                  value={targetProtocol}
                  onChange={(event) => setTargetProtocol(event.target.value)}
                  className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100"
                >
                  <option value="tcp">tcp</option>
                  <option value="udp">udp</option>
                </select>
              </label>
              <Field label="IP block" value={blockIp} onChange={setBlockIp} placeholder="192.168.1.50" />
              <Field label="Причина" value={changeReason} onChange={setChangeReason} placeholder="Например: закрытие Telnet по результату аудита" />
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {responseActions.map((action) => {
                const Icon = action.icon;
                return (
                  <div key={action.id} className="flex overflow-hidden rounded-md border border-slate-700">
                    <Button variant="secondary" onClick={() => runAction(action.id, "preview")} disabled={Boolean(loading) || !selectedHost} className="rounded-none border-0">
                      План: {action.label}
                    </Button>
                    <Button variant="danger" onClick={() => runAction(action.id, "apply")} disabled={Boolean(loading) || !selectedHost} className="rounded-none border-0">
                      <Icon size={16} className={loading === action.id ? "animate-spin" : ""} aria-hidden="true" />
                      Применить
                    </Button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-white">Транзакции изменений</h2>
              <p className="mt-1 text-sm text-slate-400">Хранятся в локальной SQLite-базе; откат доступен только для примененных действий.</p>
            </div>
            <Button variant="secondary" onClick={loadRemediations} disabled={Boolean(loading)}>
              <RefreshCw size={16} aria-hidden="true" />
              Обновить
            </Button>
          </div>
          {transactions.length ? (
            <div className="mt-4 space-y-2">
              {transactions.map((transaction) => (
                <div key={transaction.id} className="flex flex-col gap-3 rounded-md border border-slate-800 bg-slate-900/70 p-3 lg:flex-row lg:items-center lg:justify-between">
                  <div className="min-w-0 text-sm">
                    <p className="font-semibold text-slate-100">{transaction.action} · {transaction.hostAlias}</p>
                    <p className="mt-1 text-xs text-slate-400">{formatDate(transaction.createdAt)} · {transaction.status} · {transaction.reason}</p>
                    {transaction.error ? <p className="mt-1 text-xs text-red-200">{transaction.error}</p> : null}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {transaction.postAuditReportId ? (
                      <LinkButton href={`/reports/agentless/${encodeURIComponent(transaction.postAuditReportId)}`} variant="secondary">
                        Отчет после
                      </LinkButton>
                    ) : null}
                    {transaction.status === "applied" ? (
                      <Button variant="danger" onClick={() => rollbackTransaction(transaction)} disabled={Boolean(loading)}>
                        <RotateCcw size={16} aria-hidden="true" />
                        Откатить
                      </Button>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          ) : <p className="mt-4 text-sm text-slate-500">Транзакций пока нет.</p>}
        </section>

        <aside className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="text-lg font-semibold text-white">Последний запуск</h2>
          {runResult ? (
            <div className="mt-3 space-y-3 text-sm">
              <div className={`rounded-md border p-3 ${
                runResult.ok ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-100" : "border-red-400/30 bg-red-500/10 text-red-100"
              }`}>
                <p className="font-semibold">{runResult.ok ? "Успешно" : "Ошибка"}</p>
                {runResult.message ? <p className="mt-1">{runResult.message}</p> : null}
                {freshReportHref ? (
                  <LinkButton href={freshReportHref} variant="secondary" className="mt-3 w-full bg-slate-950/60">
                    Открыть отчет
                  </LinkButton>
                ) : null}
              </div>
              <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-md bg-slate-900 p-3 text-xs leading-5 text-slate-200">
{`${runResult.stdout ?? ""}${runResult.stderr ? `\n\nSTDERR:\n${runResult.stderr}` : ""}`}
              </pre>
            </div>
          ) : (
            <p className="mt-3 text-sm leading-6 text-slate-400">Выберите хост и запустите действие.</p>
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
        {label}: {ok ? "OK" : "ERROR"}
      </p>
      <p className="mt-1 truncate text-xs text-slate-300" title={text}>{text || "нет данных"}</p>
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
      <span className="text-xs font-semibold uppercase text-slate-500">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
      />
    </label>
  );
}
