"use client";

import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  FileText,
  Plus,
  Power,
  RefreshCw,
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
};

type ManagedHost = {
  alias: string;
  address: string;
  user: string | null;
  become: boolean | null;
  groups: string[];
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
  { id: "collectEvents", label: "События", icon: Terminal },
] as const;

const responseActions = [
  { id: "closeDangerousPorts", label: "Закрыть опасные", icon: AlertTriangle },
  { id: "closePort", label: "Закрыть порт", icon: Ban },
  { id: "blockIp", label: "Блок IP", icon: AlertTriangle },
  { id: "stopService", label: "Стоп сервис", icon: Power },
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
  const [serviceName, setServiceName] = useState("nginx");

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
      const [healthResponse, hostsResponse] = await Promise.all([
        fetch("/api/ansible/health"),
        fetch("/api/ansible/hosts"),
      ]);
      const nextHealth = await healthResponse.json();
      const nextHosts = await hostsResponse.json();
      setHealth(nextHealth);
      setHosts(nextHosts);
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

  async function runAction(action: string) {
    if (!selectedAlias) {
      setRunResult({ ok: false, action, message: "Выберите хост." });
      return;
    }

    const isResponse = responseActions.some((item) => item.id === action);
    if (isResponse && !window.confirm("Запустить response-playbook на выбранном хосте?")) {
      return;
    }

    const extraVars =
      action === "closePort"
        ? { target_port: targetPort, target_protocol: targetProtocol }
        : action === "blockIp"
          ? { block_ip: blockIp }
          : action === "stopService"
            ? { service_name: serviceName }
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
          confirmResponse: isResponse,
          extraVars,
        }),
      });
      const payload = await response.json();
      setRunResult(payload);
      const nextHosts = await loadHosts();
      if (payload.ok && action === "agentlessAudit") {
        const report = nextHosts.hosts?.find((host) => host.alias === selectedAlias)?.lastReport;
        if (report) {
          setFreshReportHref(reportHref(report.fileName));
        }
      }
    } finally {
      setLoading("");
    }
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
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[140px_180px_130px_90px_140px_110px_110px_110px]">
          <Field label="Alias" value={manualAlias} onChange={setManualAlias} placeholder="web-01" />
          <Field label="IP/host" value={manualAddress} onChange={setManualAddress} placeholder="192.168.1.10" />
          <Field label="SSH user" value={manualUser} onChange={setManualUser} placeholder="danil" />
          <Field label="Port" value={manualPort} onChange={setManualPort} placeholder="22" />
          <Field label="Group" value={manualGroup} onChange={setManualGroup} placeholder="linux_hosts" />
          <label className="flex h-10 items-center gap-2 self-end rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={manualBecome}
              onChange={(event) => setManualBecome(event.target.checked)}
              className="h-4 w-4 rounded border-slate-600 bg-slate-950"
            />
            sudo
          </label>
          <Button variant="secondary" onClick={checkPreflight} disabled={Boolean(loading) || !manualAlias || !manualAddress || !manualUser} className="self-end">
            <CheckCircle2 size={16} className={loading === "preflight" ? "animate-spin" : ""} aria-hidden="true" />
            Проверить
          </Button>
          <Button onClick={addManualHost} disabled={Boolean(loading) || !manualAlias || !manualAddress || !manualUser} className="self-end">
            <Plus size={16} aria-hidden="true" />
            Сохранить
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
                      <button onClick={() => setSelectedAlias(host.alias)} className="text-left">
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
                        <Button variant="secondary" onClick={() => setSelectedAlias(host.alias)}>
                          Выбрать
                        </Button>
                        {host.lastReport ? (
                          <LinkButton href={reportHref(host.lastReport.fileName)} variant="secondary">
                            Отчет
                          </LinkButton>
                        ) : null}
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

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px]">
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
            <div className="grid gap-3 md:grid-cols-4">
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
              <Field label="Service" value={serviceName} onChange={setServiceName} placeholder="nginx" />
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {responseActions.map((action) => {
                const Icon = action.icon;
                return (
                  <Button key={action.id} variant="danger" onClick={() => runAction(action.id)} disabled={Boolean(loading) || !selectedHost}>
                    <Icon size={16} className={loading === action.id ? "animate-spin" : ""} aria-hidden="true" />
                    {action.label}
                  </Button>
                );
              })}
            </div>
          </div>
        </div>

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
              <pre className="max-h-64 overflow-auto rounded-md bg-slate-900 p-3 text-xs leading-5 text-slate-200">
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
    <label className="block">
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
