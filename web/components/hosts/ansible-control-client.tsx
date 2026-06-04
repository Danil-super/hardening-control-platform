"use client";

import { CheckCircle2, Download, Play, RefreshCw, Search, Server, Terminal, Wrench } from "lucide-react";
import { useEffect, useState } from "react";
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
    sshOpen: boolean;
    alias: string;
    added: boolean;
  }>;
  added?: number;
  inventoryPath?: string;
  message?: string;
};

const profileOptions = [
  { id: "basic_linux", label: "Базовое усиление Linux" },
  { id: "ssh_security", label: "Безопасность SSH" },
  { id: "web_server", label: "Усиление веб-сервера" },
  { id: "docker_host", label: "Усиление Docker-хоста" },
];

const actions = [
  {
    id: "ping",
    title: "Проверить доступность",
    description: "Запускает Ansible ping по inventory. Настройки хостов не меняются.",
    icon: Server,
  },
  {
    id: "installAgent",
    title: "Установить audit-only агент",
    description: "Копирует agent.py и server.py в /opt/hcp-agent на выбранные хосты.",
    icon: Download,
  },
  {
    id: "audit",
    title: "Запустить audit-only",
    description: "Запускает базовый аудит и сохраняет JSON-отчеты в ansible/reports.",
    icon: Play,
  },
  {
    id: "auditLynis",
    title: "Audit-only с Lynis",
    description: "Добавляет результаты Lynis, если инструмент установлен на хостах.",
    icon: Terminal,
  },
  {
    id: "auditOpenScap",
    title: "Audit-only с Lynis + OpenSCAP",
    description: "Добавляет внешние сканеры Lynis и OpenSCAP/SSG.",
    icon: Wrench,
  },
];

export function AnsibleControlClient() {
  const [health, setHealth] = useState<HealthPayload | null>(null);
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

  useEffect(() => {
    loadDiscoveryInfo();
  }, []);

  async function loadDiscoveryInfo() {
    const response = await fetch("/api/ansible/discover");
    const payload = await response.json();
    setDiscoveryInfo(payload);
    if (payload.defaultCidr) {
      setScanCidr(payload.defaultCidr);
    }
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
    setLoading(action);
    setRunResult(null);
    try {
      const response = await fetch("/api/ansible/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, profileId, limit: limit.trim() || undefined }),
      });
      setRunResult(await response.json());
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
    } finally {
      setLoading("");
    }
  }

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
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <Search size={22} className="text-sky-200" aria-hidden="true" />
              <h2 className="text-xl font-semibold text-white">Автообнаружение хостов в локальной сети</h2>
            </div>
            <p className="mt-3 max-w-4xl text-sm leading-6 text-slate-400">
              Сканирование ищет хосты с открытым SSH-портом 22 в приватной локальной подсети и может сразу добавить их
              в `ansible/inventory.ini`. Для безопасности размер сканирования ограничен подсетями от /24 до /30.
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
              <span className="mt-1 block text-xs leading-5 text-slate-500">Для sudo-проверок агента.</span>
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
                  Найдено SSH-хостов: {discoveryResult.found?.length ?? 0}
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
                    <p className="font-semibold text-white">{host.alias}</p>
                    <p className="mt-1 text-slate-400">{host.ip} · SSH открыт</p>
                    <p className={host.added ? "mt-1 text-emerald-200" : "mt-1 text-slate-500"}>
                      {host.added ? "добавлен в inventory" : "уже был в inventory или добавление выключено"}
                    </p>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        {actions.map((action) => {
          const Icon = action.icon;
          return (
            <article key={action.id} className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
              <Icon size={22} className="text-sky-200" aria-hidden="true" />
              <h3 className="mt-4 font-semibold text-white">{action.title}</h3>
              <p className="mt-2 min-h-20 text-sm leading-6 text-slate-400">{action.description}</p>
              <Button
                variant={action.id === "installAgent" ? "secondary" : "primary"}
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
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <h2 className="text-xl font-semibold text-white">Журнал выполнения</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Результаты audit-only playbook'ов сохраняются на главном компьютере в `ansible/reports`.
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
