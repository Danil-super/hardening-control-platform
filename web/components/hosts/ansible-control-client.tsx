"use client";

import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock,
  FileText,
  KeyRound,
  ListChecks,
  Power,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Terminal,
  Wrench,
} from "lucide-react";
import { useEffect, useState } from "react";
import { SummaryCard } from "@/components/ui/summary-card";
import { Button } from "@/components/ui/button";

type HealthPayload = {
  ansibleInstalled?: boolean;
  version?: string | null;
  inventoryReady?: boolean;
  inventoryPath?: string;
  inventoryExamplePath?: string;
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

type SchedulerPayload = {
  ok?: boolean;
  active?: boolean;
  state?: {
    enabled: boolean;
    action: string;
    intervalMinutes: number;
    profileId: string;
    limit: string | null;
    lastRunAt: string | null;
    nextRunAt: string | null;
    running: boolean;
  };
  message?: string;
};

type IncidentPayload = {
  ok?: boolean;
  incidents?: Array<{
    id: string;
    createdAt: string;
    action: string;
    kind: "audit" | "response" | "system";
    status: "success" | "failed";
    profileId: string;
    limit: string | null;
    message: string;
    command?: string;
  }>;
  summary?: {
    total: number;
    success: number;
    failed: number;
    audit: number;
    response: number;
    system: number;
  };
};

type DiscoveryInfo = {
  candidates?: Array<{
    cidr: string;
    device?: string;
    source?: string;
  }>;
  defaultCidr?: string;
  maxHostsPerScan?: number;
  message?: string;
};

type DiscoveryResult = {
  ok?: boolean;
  cidr?: string;
  scannedHosts?: number;
  sshUser?: string;
  become?: boolean;
  addToInventory?: boolean;
  found?: Array<{
    ip: string;
    reachable: boolean;
    sshOpen: boolean;
    methods: string[];
    alias: string;
    added: boolean;
  }>;
  sshReady?: number;
  added?: number;
  inventoryPath?: string;
  message?: string;
};

type ManagedHost = {
  alias: string;
  address: string;
  user: string | null;
  become: boolean | null;
  groups: string[];
  raw: string;
  lastReport: {
    path: string;
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
  ok?: boolean;
  inventoryReady?: boolean;
  inventoryPath?: string;
  reportsPath?: string;
  hosts?: ManagedHost[];
  summary?: {
    total: number;
    withReports: number;
    withoutReports: number;
    becomeEnabled: number;
    averageScore: number | null;
  };
};

const profileOptions = [
  { id: "basic_linux", label: "Базовое усиление Linux" },
  { id: "ssh_security", label: "Безопасность SSH" },
  { id: "web_server", label: "Усиление веб-сервера" },
  { id: "docker_host", label: "Усиление Docker-хоста" },
] as const;

type ActionConfig = {
  id: string;
  title: string;
  description: string;
  icon: typeof Server;
  mode: "agentless" | "response";
  variant: "primary" | "secondary" | "danger";
  requiresLimit?: boolean;
  requiresConfirmation?: boolean;
};

const actions: ActionConfig[] = [
  {
    id: "ping",
    title: "Проверить доступность",
    description: "Запускает Ansible ping по inventory. Настройки хостов не меняются.",
    icon: Server,
    mode: "agentless",
    variant: "primary",
  },
  {
    id: "collectFacts",
    title: "Собрать факты",
    description: "Собирает ОС, сеть, ядро и ресурсы через Ansible без установки агента.",
    icon: FileText,
    mode: "agentless",
    variant: "primary",
  },
  {
    id: "agentlessAudit",
    title: "Безагентный аудит",
    description: "Проверяет открытые порты, firewall и базовые признаки риска через SSH.",
    icon: ShieldCheck,
    mode: "agentless",
    variant: "primary",
  },
  {
    id: "collectEvents",
    title: "Собрать события",
    description: "Читает auth/syslog/UFW/Suricata-события через Ansible, если логи доступны.",
    icon: ListChecks,
    mode: "agentless",
    variant: "primary",
  },
  {
    id: "closeDangerousPorts",
    title: "Закрыть опасные порты",
    description: "Response-playbook: блокирует опасные TCP/UDP-порты через активный ufw/firewalld.",
    icon: AlertTriangle,
    mode: "response",
    variant: "danger",
    requiresLimit: true,
    requiresConfirmation: true,
  },
  {
    id: "closePort",
    title: "Закрыть порт",
    description: "Response-playbook: блокирует выбранный порт через ufw/firewalld.",
    icon: Ban,
    mode: "response",
    variant: "danger",
    requiresLimit: true,
    requiresConfirmation: true,
  },
  {
    id: "blockIp",
    title: "Заблокировать IP",
    description: "Response-playbook: добавляет firewall-правило drop/deny для IP-адреса источника.",
    icon: AlertTriangle,
    mode: "response",
    variant: "danger",
    requiresLimit: true,
    requiresConfirmation: true,
  },
  {
    id: "stopService",
    title: "Остановить сервис",
    description: "Response-playbook: останавливает и отключает выбранный systemd-сервис.",
    icon: Power,
    mode: "response",
    variant: "danger",
    requiresLimit: true,
    requiresConfirmation: true,
  },
];

function formatDate(value: string | null | undefined) {
  if (!value) {
    return "нет данных";
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

export function AnsibleControlClient() {
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [hosts, setHosts] = useState<HostsPayload | null>(null);
  const [discoveryInfo, setDiscoveryInfo] = useState<DiscoveryInfo | null>(null);
  const [discoveryResult, setDiscoveryResult] = useState<DiscoveryResult | null>(null);
  const [scanCidr, setScanCidr] = useState("");
  const [sshUser, setSshUser] = useState("danil");
  const [become, setBecome] = useState(true);
  const [addToInventory, setAddToInventory] = useState(true);
  const [profileId, setProfileId] = useState("basic_linux");
  const [limit, setLimit] = useState("");
  const [loading, setLoading] = useState("");
  const [runResult, setRunResult] = useState<RunPayload | null>(null);
  const [scheduler, setScheduler] = useState<SchedulerPayload | null>(null);
  const [incidents, setIncidents] = useState<IncidentPayload | null>(null);
  const [scheduleEnabled, setScheduleEnabled] = useState(false);
  const [scheduleAction, setScheduleAction] = useState("agentlessAudit");
  const [scheduleInterval, setScheduleInterval] = useState(15);
  const [targetPort, setTargetPort] = useState("23");
  const [targetProtocol, setTargetProtocol] = useState("tcp");
  const [blockIp, setBlockIp] = useState("");
  const [serviceName, setServiceName] = useState("nginx");

  useEffect(() => {
    loadDiscoveryInfo();
    loadHosts();
    loadScheduler();
    loadIncidents();
  }, []);

  async function loadDiscoveryInfo() {
    const response = await fetch("/api/ansible/discover");
    const payload = await response.json();
    setDiscoveryInfo(payload);
    if (payload.defaultCidr) {
      setScanCidr(payload.defaultCidr);
    }
  }

  async function loadHosts() {
    const response = await fetch("/api/ansible/hosts");
    setHosts(await response.json());
  }

  async function loadScheduler() {
    const response = await fetch("/api/ansible/scheduler");
    const payload = await response.json();
    setScheduler(payload);
    if (payload.state) {
      setScheduleEnabled(payload.state.enabled);
      setScheduleAction(payload.state.action);
      setScheduleInterval(payload.state.intervalMinutes);
    }
  }

  async function loadIncidents() {
    const response = await fetch("/api/ansible/incidents");
    setIncidents(await response.json());
  }

  async function checkHealth() {
    setLoading("health");
    setRunResult(null);
    try {
      const response = await fetch("/api/ansible/health");
      setHealth(await response.json());
    } finally {
      setLoading("");
    }
  }

  async function runAction(action: string) {
    const selectedAction = actions.find((item) => item.id === action);
    if (selectedAction?.requiresLimit && !limit.trim()) {
      setRunResult({
        ok: false,
        action,
        message: "Для response-playbook выберите конкретный хост или группу в поле Limit.",
      });
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

    const confirmResponse = selectedAction?.requiresConfirmation
      ? window.confirm("Запустить response-playbook? Он может изменить firewall на выбранных хостах.")
      : false;
    if (selectedAction?.requiresConfirmation && !confirmResponse) {
      return;
    }

    setLoading(action);
    setRunResult(null);
    try {
      const response = await fetch("/api/ansible/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, profileId, limit: limit.trim() || undefined, confirmResponse, extraVars }),
      });
      setRunResult(await response.json());
      await loadHosts();
      await loadIncidents();
    } finally {
      setLoading("");
    }
  }

  async function saveScheduler() {
    setLoading("scheduler");
    setRunResult(null);
    try {
      const response = await fetch("/api/ansible/scheduler", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: scheduleEnabled,
          action: scheduleAction,
          intervalMinutes: scheduleInterval,
          profileId,
          limit: limit.trim() || undefined,
        }),
      });
      const payload = await response.json();
      setScheduler(payload);
      setRunResult({
        ok: payload.ok,
        action: "scheduler",
        message: payload.ok ? "Планировщик обновлен." : payload.message,
      });
    } finally {
      setLoading("");
    }
  }

  async function scanNetwork() {
    setLoading("discover");
    setDiscoveryResult(null);
    setRunResult(null);
    try {
      const response = await fetch("/api/ansible/discover", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cidr: scanCidr, sshUser, become, addToInventory }),
      });
      setDiscoveryResult(await response.json());
      await loadHosts();
    } finally {
      setLoading("");
    }
  }

  function selectHostLimit(host: ManagedHost) {
    setLimit(host.alias);
    document.getElementById("ansible-actions")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  const averageScore = hosts?.summary?.averageScore;

  return (
    <div className="space-y-6">
      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_380px]">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <Server size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Главный компьютер Ansible</h2>
          </div>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            Этот экран работает на локально запущенном сайте. Он проверяет Ansible на главном компьютере и запускает
            только разрешенные playbook'и из папки `ansible/playbooks`.
          </p>
          <div className="mt-5 grid gap-3 text-sm md:grid-cols-2">
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Профиль аудита</span>
              <select
                value={profileId}
                onChange={(event) => setProfileId(event.target.value)}
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              >
                {profileOptions.map((profile) => (
                  <option key={profile.id} value={profile.id}>{profile.label}</option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Ограничить хост/группу</span>
              <input
                value={limit}
                onChange={(event) => setLimit(event.target.value)}
                placeholder="server1 или linux_hosts"
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              />
            </label>
          </div>
          <Button onClick={checkHealth} disabled={loading === "health"} className="mt-5">
            <RefreshCw size={16} className={loading === "health" ? "animate-spin" : ""} aria-hidden="true" />
            Проверить control node
          </Button>
        </div>

        <aside className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Статус</h2>
          <div className="mt-4 space-y-3 text-sm">
            <div className={`rounded-md border p-3 ${
              health?.ansibleInstalled ? "border-emerald-400/30 bg-emerald-500/10" : "border-slate-800 bg-slate-900/70"
            }`}>
              <p className="font-semibold text-white">Ansible</p>
              <p className="mt-1 leading-6 text-slate-300">{health?.version ?? "Статус еще не проверен."}</p>
            </div>
            <div className={`rounded-md border p-3 ${
              health?.inventoryReady ? "border-emerald-400/30 bg-emerald-500/10" : "border-amber-400/30 bg-amber-500/10"
            }`}>
              <p className="font-semibold text-white">Inventory</p>
              <p className="mt-1 leading-6 text-slate-300">{health?.message ?? "Нажмите проверку control node."}</p>
            </div>
          </div>
        </aside>
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <div className="flex items-center gap-3">
          <KeyRound size={22} className="text-sky-200" aria-hidden="true" />
          <h2 className="text-xl font-semibold text-white">SSH-доступ к хостам</h2>
        </div>
        <p className="mt-3 max-w-4xl text-sm leading-6 text-slate-400">
          Для постоянной работы Ansible лучше использовать SSH-ключи. Парольный доступ можно использовать для первичной
          проверки вручную, но веб-панель рассчитана на ключевой доступ с главного сервера.
        </p>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <code className="rounded-md border border-slate-800 bg-slate-900 p-3 text-xs leading-5 text-slate-200">
            ssh-keygen -t ed25519 -C hcp-control
          </code>
          <code className="rounded-md border border-slate-800 bg-slate-900 p-3 text-xs leading-5 text-slate-200">
            ssh-copy-id danil@192.168.1.10
          </code>
          <code className="rounded-md border border-slate-800 bg-slate-900 p-3 text-xs leading-5 text-slate-200">
            ansible all -i ansible/inventory.ini -m ping
          </code>
        </div>
      </section>

      <section className="space-y-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h2 className="text-xl font-semibold text-white">Управляемые хосты</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Список строится из `ansible/inventory.ini`. После audit-only запуска здесь появится последняя оценка
              защищенности и счетчики рисков по каждому хосту.
            </p>
          </div>
          <Button variant="secondary" onClick={loadHosts} disabled={Boolean(loading)}>
            <RefreshCw size={16} aria-hidden="true" />
            Обновить список
          </Button>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <SummaryCard
            label="Хостов в inventory"
            value={hosts?.summary?.total ?? 0}
            detail={hosts?.inventoryReady ? "Файл inventory найден" : "Inventory пока не создан"}
            icon={<Server size={18} aria-hidden="true" />}
          />
          <SummaryCard
            label="С отчётами"
            value={hosts?.summary?.withReports ?? 0}
            detail={`Без отчёта: ${hosts?.summary?.withoutReports ?? 0}`}
            icon={<FileText size={18} aria-hidden="true" />}
          />
          <SummaryCard
            label="Средняя оценка"
            value={averageScore === null || averageScore === undefined ? "нет" : `${averageScore}%`}
            detail="По последним найденным отчётам"
            icon={<ShieldCheck size={18} aria-hidden="true" />}
          />
          <SummaryCard
            label="Sudo-доступ"
            value={hosts?.summary?.becomeEnabled ?? 0}
            detail="Хосты с ansible_become=true"
            icon={<Wrench size={18} aria-hidden="true" />}
          />
        </div>

        <div className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
          {hosts?.hosts?.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[920px] text-left text-sm">
                <thead className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Хост</th>
                    <th className="px-4 py-3">Подключение</th>
                    <th className="px-4 py-3">Группы</th>
                    <th className="px-4 py-3">Последний аудит</th>
                    <th className="px-4 py-3">Риски</th>
                    <th className="px-4 py-3">Действие</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {hosts.hosts.map((host) => (
                    <tr key={host.alias} className="align-top">
                      <td className="px-4 py-4">
                        <p className="font-semibold text-white">{host.alias}</p>
                        <p className="mt-1 text-xs text-slate-500">{host.address}</p>
                      </td>
                      <td className="px-4 py-4 text-slate-300">
                        <p>{host.user ? `пользователь: ${host.user}` : "пользователь не указан"}</p>
                        <p className={host.become ? "mt-1 text-emerald-200" : "mt-1 text-slate-500"}>
                          {host.become ? "sudo включен" : "sudo не указан"}
                        </p>
                      </td>
                      <td className="px-4 py-4 text-slate-300">{host.groups.join(", ")}</td>
                      <td className="px-4 py-4">
                        {host.lastReport ? (
                          <div>
                            <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold ${scoreTone(host.lastReport.score)}`}>
                              {host.lastReport.score === null ? "оценка нет" : `${host.lastReport.score}%`}
                            </span>
                            <p className="mt-2 text-xs text-slate-400">{formatDate(host.lastReport.createdAt)}</p>
                            <p className="mt-1 text-xs text-slate-500">{host.lastReport.profileId ?? "профиль не указан"}</p>
                          </div>
                        ) : (
                          <span className="text-slate-500">аудит ещё не запускался</span>
                        )}
                      </td>
                      <td className="px-4 py-4 text-xs text-slate-300">
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
                      <td className="px-4 py-4">
                        <Button variant="secondary" onClick={() => selectHostLimit(host)}>
                          <Terminal size={16} aria-hidden="true" />
                          Выбрать
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-5 text-sm leading-6 text-slate-400">
              В inventory пока нет активных хостов. Используйте автообнаружение ниже или добавьте строки в
              `ansible/inventory.ini`, затем обновите список.
            </div>
          )}
        </div>
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <Search size={22} className="text-sky-200" aria-hidden="true" />
              <h2 className="text-xl font-semibold text-white">Автообнаружение хостов в локальной сети</h2>
            </div>
            <p className="mt-3 max-w-4xl text-sm leading-6 text-slate-400">
              Сканирование ищет устройства в приватной локальной подсети через ping, ARP/neighbor table и проверку
              SSH-порта 22. В `ansible/inventory.ini` добавляются только хосты с открытым SSH, потому что Ansible
              подключается по SSH. Размер сканирования ограничен подсетями от /24 до /30.
            </p>
          </div>
          <Button variant="secondary" onClick={loadDiscoveryInfo} disabled={Boolean(loading)}>
            <RefreshCw size={16} aria-hidden="true" />
            Определить подсеть
          </Button>
        </div>

        <div className="mt-5 grid gap-3 text-sm md:grid-cols-2 xl:grid-cols-4">
          <label className="block">
            <span className="text-xs font-semibold uppercase text-slate-500">Подсеть для сканирования</span>
            <input
              value={scanCidr}
              onChange={(event) => setScanCidr(event.target.value)}
              placeholder="192.168.1.0/24"
              className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
            />
          </label>
          <label className="block">
            <span className="text-xs font-semibold uppercase text-slate-500">SSH-пользователь</span>
            <input
              value={sshUser}
              onChange={(event) => setSshUser(event.target.value)}
              placeholder="danil"
              className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
            />
          </label>
          <label className="flex items-center gap-3 rounded-md border border-slate-800 bg-slate-900/70 p-3">
            <input
              type="checkbox"
              checked={become}
              onChange={(event) => setBecome(event.target.checked)}
              className="h-4 w-4 rounded border-slate-600 bg-slate-950"
            />
            <span>
              <span className="block font-semibold text-white">become=true</span>
              <span className="mt-1 block text-xs leading-5 text-slate-500">Для sudo-проверок Ansible.</span>
            </span>
          </label>
          <label className="flex items-center gap-3 rounded-md border border-slate-800 bg-slate-900/70 p-3">
            <input
              type="checkbox"
              checked={addToInventory}
              onChange={(event) => setAddToInventory(event.target.checked)}
              className="h-4 w-4 rounded border-slate-600 bg-slate-950"
            />
            <span>
              <span className="block font-semibold text-white">Добавить в inventory</span>
              <span className="mt-1 block text-xs leading-5 text-slate-500">Новые IP попадут в linux_hosts.</span>
            </span>
          </label>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <Button onClick={scanNetwork} disabled={Boolean(loading) || !scanCidr}>
            <Search size={16} className={loading === "discover" ? "animate-pulse" : ""} aria-hidden="true" />
            {loading === "discover" ? "Сканирование..." : "Сканировать и добавить"}
          </Button>
          <p className="text-sm text-slate-500">
            {discoveryInfo?.message ?? "Подсеть будет определена автоматически при открытии страницы."}
          </p>
        </div>

        {discoveryInfo?.candidates?.length ? (
          <div className="mt-4 flex flex-wrap gap-2">
            {discoveryInfo.candidates.map((candidate) => (
              <button
                key={`${candidate.cidr}-${candidate.device ?? ""}`}
                onClick={() => setScanCidr(candidate.cidr)}
                className="rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 hover:border-sky-300"
              >
                {candidate.cidr}{candidate.device ? ` · ${candidate.device}` : ""}
              </button>
            ))}
          </div>
        ) : null}

        {discoveryResult ? (
          <div className="mt-5 rounded-md border border-slate-800 bg-slate-900/70 p-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="font-semibold text-white">
                  Найдено устройств: {discoveryResult.found?.length ?? 0} · SSH доступен: {discoveryResult.sshReady ?? 0}
                </p>
                <p className="mt-1 text-sm text-slate-400">
                  Подсеть: {discoveryResult.cidr ?? "не указана"} · просканировано: {discoveryResult.scannedHosts ?? 0} ·
                  добавлено: {discoveryResult.added ?? 0}
                </p>
              </div>
              <span className={`w-fit rounded-md border px-2 py-1 text-xs font-semibold uppercase ${
                discoveryResult.ok ? "border-emerald-400/40 bg-emerald-500/15 text-emerald-100" : "border-red-400/40 bg-red-500/15 text-red-100"
              }`}>
                {discoveryResult.ok ? "готово" : "ошибка"}
              </span>
            </div>
            {discoveryResult.message ? <p className="mt-3 text-sm text-red-100">{discoveryResult.message}</p> : null}
            {discoveryResult.found?.length ? (
              <div className="mt-4 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                {discoveryResult.found.map((host) => (
                  <div key={host.ip} className="rounded-md border border-slate-800 bg-slate-950/70 p-3 text-sm">
                    <div className="flex items-start justify-between gap-2">
                      <p className="font-semibold text-white">{host.alias}</p>
                      <span className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${
                        host.sshOpen
                          ? "border-emerald-400/40 bg-emerald-500/15 text-emerald-100"
                          : "border-amber-400/40 bg-amber-500/15 text-amber-100"
                      }`}>
                        {host.sshOpen ? "SSH открыт" : "SSH закрыт"}
                      </span>
                    </div>
                    <p className="mt-2 text-slate-400">{host.ip}</p>
                    <p className="mt-1 text-xs text-slate-500">Сигналы: {host.methods.join(", ") || "нет данных"}</p>
                    <p className={host.added ? "mt-2 text-emerald-200" : "mt-2 text-slate-500"}>
                      {host.added
                        ? "добавлен в inventory"
                        : host.sshOpen
                          ? "уже был в inventory или добавление выключено"
                          : "не добавлен: для Ansible нужно включить SSH"}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mt-4 rounded-md border border-amber-400/30 bg-amber-500/10 p-4 text-sm leading-6 text-amber-100">
                Устройства не найдены. Проверьте, что выбрана правильная подсеть, устройства находятся в той же сети,
                а firewall не блокирует ping/ARP/SSH. Для Ansible на целевых Linux-хостах нужен открытый SSH-порт 22.
              </div>
            )}
          </div>
        ) : null}
      </section>

      <section id="ansible-actions" className="space-y-4">
        <div>
          <h2 className="text-xl font-semibold text-white">Безагентное управление</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            Главный сервер подключается к хостам по SSH, выполняет проверки и response-playbook'и без установки
            постоянного агента на целевые устройства.
          </p>
        </div>

        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h3 className="font-semibold text-white">Параметры response-действий</h3>
          <div className="mt-4 grid gap-3 text-sm md:grid-cols-2 xl:grid-cols-4">
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Порт</span>
              <input
                value={targetPort}
                onChange={(event) => setTargetPort(event.target.value)}
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Протокол</span>
              <select
                value={targetProtocol}
                onChange={(event) => setTargetProtocol(event.target.value)}
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              >
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">IP для блокировки</span>
              <input
                value={blockIp}
                onChange={(event) => setBlockIp(event.target.value)}
                placeholder="192.168.1.50"
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Systemd-сервис</span>
              <input
                value={serviceName}
                onChange={(event) => setServiceName(event.target.value)}
                placeholder="nginx"
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              />
            </label>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {actions.map((action) => {
            const Icon = action.icon;
            return (
              <article key={action.id} className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
                <Icon size={22} className={action.variant === "danger" ? "text-red-200" : "text-sky-200"} aria-hidden="true" />
                <h3 className="mt-4 font-semibold text-white">{action.title}</h3>
                <p className="mt-2 min-h-20 text-sm leading-6 text-slate-400">{action.description}</p>
                <Button
                  variant={action.variant}
                  onClick={() => runAction(action.id)}
                  disabled={Boolean(loading)}
                  className="mt-4 w-full"
                >
                  {loading === action.id ? (
                    <RefreshCw size={16} className="animate-spin" aria-hidden="true" />
                  ) : (
                    <CheckCircle2 size={16} aria-hidden="true" />
                  )}
                  Запустить
                </Button>
              </article>
            );
          })}
        </div>
      </section>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_420px]">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <Clock size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Планировщик проверок</h2>
          </div>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            Планировщик работает пока запущен локальный сайт. Он запускает только безопасные audit-playbook'и;
            response-действия по расписанию запрещены.
          </p>
          <div className="mt-4 grid gap-3 text-sm md:grid-cols-2 xl:grid-cols-4">
            <label className="flex items-center gap-3 rounded-md border border-slate-800 bg-slate-900/70 p-3">
              <input
                type="checkbox"
                checked={scheduleEnabled}
                onChange={(event) => setScheduleEnabled(event.target.checked)}
                className="h-4 w-4 rounded border-slate-600 bg-slate-950"
              />
              <span className="font-semibold text-white">Включить</span>
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Действие</span>
              <select
                value={scheduleAction}
                onChange={(event) => setScheduleAction(event.target.value)}
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              >
                <option value="ping">Проверить доступность</option>
                <option value="collectFacts">Собрать факты</option>
                <option value="agentlessAudit">Безагентный аудит</option>
                <option value="collectEvents">Собрать события</option>
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Интервал</span>
              <select
                value={scheduleInterval}
                onChange={(event) => setScheduleInterval(Number(event.target.value))}
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              >
                <option value={5}>5 минут</option>
                <option value={15}>15 минут</option>
                <option value={30}>30 минут</option>
                <option value={60}>60 минут</option>
              </select>
            </label>
            <Button onClick={saveScheduler} disabled={Boolean(loading)} className="mt-6">
              <Clock size={16} aria-hidden="true" />
              Сохранить
            </Button>
          </div>
          <p className="mt-4 text-sm text-slate-400">
            Статус: {scheduler?.state?.enabled ? "включен" : "выключен"} · следующий запуск:{" "}
            {formatDate(scheduler?.state?.nextRunAt)}
          </p>
        </div>

        <aside className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <ListChecks size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Журнал инцидентов</h2>
          </div>
          <div className="mt-4 grid grid-cols-3 gap-2 text-sm">
            <div className="rounded-md bg-slate-900 p-3">
              <p className="text-slate-500">Всего</p>
              <p className="mt-1 text-2xl font-semibold text-white">{incidents?.summary?.total ?? 0}</p>
            </div>
            <div className="rounded-md bg-emerald-500/10 p-3">
              <p className="text-emerald-200">Успешно</p>
              <p className="mt-1 text-2xl font-semibold text-white">{incidents?.summary?.success ?? 0}</p>
            </div>
            <div className="rounded-md bg-red-500/10 p-3">
              <p className="text-red-200">Ошибки</p>
              <p className="mt-1 text-2xl font-semibold text-white">{incidents?.summary?.failed ?? 0}</p>
            </div>
          </div>
          <div className="mt-4 max-h-72 space-y-2 overflow-auto pr-1">
            {incidents?.incidents?.length ? incidents.incidents.slice(0, 8).map((incident) => (
              <div key={incident.id} className="rounded-md border border-slate-800 bg-slate-900/70 p-3 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <p className="font-semibold text-white">{incident.action}</p>
                  <span className={incident.status === "success" ? "text-emerald-200" : "text-red-200"}>
                    {incident.status === "success" ? "успех" : "ошибка"}
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-500">{formatDate(incident.createdAt)} · {incident.limit ?? "без limit"}</p>
                <p className="mt-2 text-slate-300">{incident.message}</p>
              </div>
            )) : (
              <p className="rounded-md border border-slate-800 bg-slate-900/70 p-3 text-sm text-slate-400">
                Журнал пока пуст. Запустите проверку или response-playbook.
              </p>
            )}
          </div>
        </aside>
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <h2 className="text-xl font-semibold text-white">Журнал выполнения</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Результаты безагентных Ansible playbook'ов сохраняются на главном компьютере в `ansible/reports`.
        </p>
        {runResult ? (
          <div className="mt-4 space-y-3">
            <div className={`rounded-md border p-4 text-sm ${
              runResult.ok ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-100" : "border-red-400/30 bg-red-500/10 text-red-100"
            }`}>
              <p className="font-semibold">{runResult.ok ? "Playbook выполнен" : "Playbook завершился с ошибкой"}</p>
              <p className="mt-2 break-all">{runResult.command}</p>
              {runResult.message ? <p className="mt-2">{runResult.message}</p> : null}
            </div>
            <pre className="max-h-[420px] overflow-auto rounded-md bg-slate-900 p-4 text-xs leading-5 text-slate-200">
{`${runResult.stdout ?? ""}${runResult.stderr ? `\n\nSTDERR:\n${runResult.stderr}` : ""}`}
            </pre>
          </div>
        ) : (
          <div className="mt-4 rounded-md border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-400">
            Запустите проверку или playbook, чтобы увидеть вывод.
          </div>
        )}
      </section>
    </div>
  );
}
