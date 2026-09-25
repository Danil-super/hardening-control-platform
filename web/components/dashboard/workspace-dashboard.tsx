"use client";

import { CheckCircle2, CircleAlert, Database, FileText, RefreshCw, Server, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button, LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { errorMessage, readApiResponse } from "@/lib/client-api";

type Health = {
  ansibleInstalled?: boolean;
  inventoryReady?: boolean;
  version?: string | null;
  message?: string;
};

type Host = {
  alias: string;
  reportCount: number;
  lastReport: { createdAt: string | null; score: number | null } | null;
};

type HostPayload = { ok?: boolean; hosts?: Host[]; message?: string };
type DashboardState = { health: Health; hosts: Host[] };

function formatDate(value: string | null) {
  if (!value) return "ещё не запускался";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

export function WorkspaceDashboard() {
  const [state, setState] = useState<DashboardState | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");

  async function load() {
    setLoading(true);
    setMessage("");
    try {
      const [healthResponse, hostsResponse] = await Promise.all([
        fetch("/api/ansible/health", { cache: "no-store" }),
        fetch("/api/ansible/hosts", { cache: "no-store" }),
      ]);
      const health = await readApiResponse(healthResponse) as Health;
      const hostsPayload = await readApiResponse(hostsResponse) as HostPayload;
      if (!hostsResponse.ok || !hostsPayload.ok) throw new Error(hostsPayload.message ?? "Не удалось прочитать хосты.");
      setState({ health, hosts: hostsPayload.hosts ?? [] });
    } catch (error) {
      setMessage(errorMessage(error, "Не удалось получить состояние платформы."));
      setState(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  const summary = useMemo(() => {
    const hosts = state?.hosts ?? [];
    const audited = hosts.filter((host) => host.reportCount > 0);
    const latest = audited
      .map((host) => ({ host, time: host.lastReport?.createdAt ? new Date(host.lastReport.createdAt).getTime() : 0 }))
      .sort((left, right) => right.time - left.time)[0]?.host ?? null;
    return { hosts, audited, latest };
  }, [state]);

  const controlReady = Boolean(state?.health.ansibleInstalled && state?.health.inventoryReady);
  const controlDetail = !state
    ? "Проверяем Ansible и inventory"
    : !state.health.ansibleInstalled
      ? "Ansible недоступен — откройте инструкцию"
      : !state.health.inventoryReady
        ? "Inventory появится после первого хоста"
        : state.health.version ?? "Ansible и inventory готовы";
  const nextStep = !state
    ? { title: "Проверьте подключение к платформе", text: "Не удалось получить состояние control node. Обновите страницу или откройте инструкцию.", href: "/guide", label: "Открыть инструкцию" }
    : !state.health.ansibleInstalled
      ? { title: "Подготовьте control node", text: "Ansible недоступен. Выполните шаг установки из инструкции, затем вернитесь сюда.", href: "/guide", label: "Открыть инструкцию" }
      : !summary.hosts.length
        ? { title: "Подключите первый хост", text: "Добавьте Astra или другой Linux-хост через безопасное SSH-подключение. Пароль используется один раз и не сохраняется.", href: "/hosts", label: "Добавить хост" }
        : !summary.audited.length
          ? { title: "Запустите основной аудит", text: "Выберите подключённый хост и профиль. После завершения отчёт подскажет, какие проверки нужно исправить или продолжить.", href: "/hosts", label: "Перейти к аудиту" }
          : { title: "Разберите подтверждённые результаты", text: "Откройте свежий отчёт, выберите только нужные изменения и добавьте их в план работ. Фактические изменения firewall остаются обратимыми.", href: "/remediation-plan", label: "Открыть план работ" };

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-sky-200">Контур безопасности</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Обзор</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">После развёртывания не нужно искать следующий шаг: платформа показывает готовность контура, подключённые хосты и одно приоритетное действие.</p>
        </div>
        <Button variant="secondary" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} aria-hidden="true" />
          Обновить
        </Button>
      </header>

      {message ? <section role="alert" className="rounded-xl border border-red-400/30 bg-red-500/10 p-4 text-sm leading-6 text-red-100">{message}</section> : null}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <SummaryCard label="Control node" value={loading ? "…" : controlReady ? "готов" : "требует внимания"} detail={controlDetail} icon={controlReady ? <CheckCircle2 size={18} /> : <CircleAlert size={18} />} />
        <SummaryCard label="Подключённые хосты" value={loading ? "…" : summary.hosts.length} detail={summary.hosts.length ? "Хосты из inventory" : "Добавьте первый хост"} icon={<Server size={18} />} />
        <SummaryCard label="С аудитом" value={loading ? "…" : summary.audited.length} detail={summary.audited.length ? "Есть сохранённые отчёты" : "Основной аудит ещё не запускался"} icon={<ShieldCheck size={18} />} />
        <SummaryCard label="Последний отчёт" value={loading ? "…" : summary.latest?.alias ?? "нет"} detail={summary.latest ? formatDate(summary.latest.lastReport?.createdAt ?? null) : "Появится после первого аудита"} icon={<FileText size={18} />} />
      </section>

      <section className="rounded-2xl border border-sky-400/20 bg-[linear-gradient(135deg,rgba(14,116,144,.17),rgba(8,17,31,.92)_56%)] p-5 shadow-xl shadow-black/10 sm:p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="max-w-3xl">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-sky-200">Следующий шаг</p>
            <h2 className="mt-2 text-xl font-semibold text-white">{nextStep.title}</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">{nextStep.text}</p>
          </div>
          <LinkButton href={nextStep.href}>{nextStep.label}</LinkButton>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <article className="rounded-xl border border-slate-800 bg-slate-950/70 p-5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-400/10 text-sm font-semibold text-sky-200">1</span>
          <h2 className="mt-4 font-semibold text-white">Проведите аудит</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">Основной профиль проверяет конфигурацию роли хоста. Специальные инструменты — CVE, OpenSCAP, Nmap и Lynis — запускаются только по необходимости.</p>
          <LinkButton href="/hosts" variant="secondary" className="mt-4">Открыть хосты</LinkButton>
        </article>
        <article className="rounded-xl border border-slate-800 bg-slate-950/70 p-5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-400/10 text-sm font-semibold text-sky-200">2</span>
          <h2 className="mt-4 font-semibold text-white">Выберите изменения</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">В план попадают только выбранные подтверждённые находки. До выполнения решение можно изменить; после реального изменения сохраняется след и доступен откат там, где он поддерживается.</p>
          <LinkButton href="/remediation-plan" variant="secondary" className="mt-4">Открыть план</LinkButton>
        </article>
        <article className="rounded-xl border border-slate-800 bg-slate-950/70 p-5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-400/10 text-sm font-semibold text-sky-200">3</span>
          <h2 className="mt-4 font-semibold text-white">Расширяйте охват</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">Подключите актуальную CVE-базу, назначьте политики и используйте собственные сценарии только через контролируемый тестовый контур.</p>
          <LinkButton href="/data-sources" variant="secondary" className="mt-4"><Database size={16} aria-hidden="true" />Источники</LinkButton>
        </article>
      </section>
    </div>
  );
}
