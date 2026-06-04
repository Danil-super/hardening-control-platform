"use client";

import { CheckCircle2, Download, Play, RefreshCw, Server, Terminal, Wrench } from "lucide-react";
import { useState } from "react";
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
  const [profileId, setProfileId] = useState("basic_linux");
  const [limit, setLimit] = useState("");
  const [loading, setLoading] = useState("");
  const [runResult, setRunResult] = useState<RunPayload | null>(null);

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
