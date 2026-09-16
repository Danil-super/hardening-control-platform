"use client";

import { useEffect, useState } from "react";
import { Download, FileOutput, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useFeedbackMessage } from "@/components/ui/feedback";
import { errorMessage, readApiResponse } from "@/lib/client-api";

type Host = { alias: string };
type ProjectReport = { id: string; createdAt: string; hostAlias: string; pdfSha256: string; snapshotSha256: string; sourceManifestSha256: string; subject: { clientName: string; projectName: string; period: string; specialist: string } };
type Response = { ok?: boolean; reports?: ProjectReport[]; report?: ProjectReport; downloadUrl?: string; message?: string };
const inputClass = "mt-1 h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:border-sky-300 focus:outline-none";

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

export function ProjectReportsClient() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [hostAlias, setHostAlias] = useState("");
  const [reports, setReports] = useState<ProjectReport[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useFeedbackMessage();
  const [subject, setSubject] = useState({ clientName: "", projectName: "", period: "", specialist: "" });

  async function loadHosts() {
    try {
      const response = await fetch("/api/ansible/hosts", { cache: "no-store" });
      const payload = await readApiResponse(response) as { ok?: boolean; hosts?: Host[]; message?: string };
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось прочитать список хостов.");
      const next = payload.hosts ?? [];
      setHosts(next); setHostAlias((value) => value || next[0]?.alias || "");
    } catch (error) { setMessage(errorMessage(error, "Не удалось прочитать список хостов.")); }
  }

  async function loadReports(alias = hostAlias) {
    if (!alias) { setReports([]); return; }
    try {
      const response = await fetch(`/api/ansible/project-reports?hostAlias=${encodeURIComponent(alias)}`, { cache: "no-store" });
      const payload = await readApiResponse(response) as Response;
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось прочитать список итоговых отчётов.");
      setReports(payload.reports ?? []);
    } catch (error) { setMessage(errorMessage(error, "Не удалось прочитать список итоговых отчётов.")); }
  }

  useEffect(() => { void loadHosts(); }, []);
  useEffect(() => { void loadReports(); }, [hostAlias]);

  async function create() {
    setBusy(true);
    try {
      const response = await fetch("/api/ansible/project-reports", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hostAlias, subject }) });
      const payload = await readApiResponse(response) as Response;
      if (!response.ok || !payload.ok || !payload.downloadUrl) throw new Error(payload.message ?? "Не удалось сформировать итоговый отчёт.");
      setMessage(payload.message ?? "Итоговый отчёт сформирован.", "success");
      await loadReports();
      window.location.assign(payload.downloadUrl);
    } catch (error) { setMessage(errorMessage(error, "Не удалось сформировать итоговый отчёт.")); }
    finally { setBusy(false); }
  }

  return <div className="space-y-6">
    <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between"><div><p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Перед передачей заказчику</p><h1 className="mt-2 text-3xl font-semibold text-white">Итоговые отчёты</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">PDF формируется из серверного снимка доступных отчётов, плана работ и зафиксированных изменений. После экспорта его хеш и хеши источников записываются в журнал HCP.</p></div>
      <Button variant="secondary" onClick={() => void loadReports()} disabled={busy || !hostAlias}><RefreshCw size={16} className={busy ? "animate-spin" : ""} aria-hidden="true" />Обновить список</Button></header>

    <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 sm:p-5"><div className="flex items-start gap-3"><FileOutput className="mt-0.5 text-sky-200" size={22} aria-hidden="true" /><div><h2 className="text-lg font-semibold text-white">Сформировать PDF</h2><p className="mt-1 text-sm leading-6 text-slate-400">Перед экспортом проверьте покрытие аудита и решения по находкам. Отчёт не содержит паролей, приватных ключей, команд и путей к резервным копиям.</p></div></div>
      <div className="mt-4 grid gap-3 lg:grid-cols-2"><label className="text-sm text-slate-300">Целевой хост<select className={inputClass} value={hostAlias} onChange={(event) => setHostAlias(event.target.value)} disabled={busy || !hosts.length}><option value="">Выберите хост</option>{hosts.map((host) => <option key={host.alias} value={host.alias}>{host.alias}</option>)}</select></label>
        <label className="text-sm text-slate-300">Заказчик<input className={inputClass} value={subject.clientName} onChange={(event) => setSubject((value) => ({ ...value, clientName: event.target.value }))} placeholder="Наименование организации" /></label>
        <label className="text-sm text-slate-300">Проект или договор<input className={inputClass} value={subject.projectName} onChange={(event) => setSubject((value) => ({ ...value, projectName: event.target.value }))} placeholder="Например, харденинг серверов" /></label>
        <label className="text-sm text-slate-300">Период работ<input className={inputClass} value={subject.period} onChange={(event) => setSubject((value) => ({ ...value, period: event.target.value }))} placeholder="01–05.10.2026" /></label>
        <label className="text-sm text-slate-300">Специалист<input className={inputClass} value={subject.specialist} onChange={(event) => setSubject((value) => ({ ...value, specialist: event.target.value }))} placeholder="ФИО или роль" /></label></div>
      {!hosts.length ? <p className="mt-4 text-sm text-amber-100">Сначала подключите хост и выполните хотя бы один аудит.</p> : <div className="mt-5"><Button onClick={() => void create()} disabled={busy || !hostAlias}>{busy ? <RefreshCw size={16} className="animate-spin" aria-hidden="true" /> : <Download size={16} aria-hidden="true" />}{busy ? "Формирование…" : "Сформировать и скачать PDF"}</Button></div>}</section>

    <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 sm:p-5"><div className="flex items-start gap-3"><ShieldCheck className="mt-0.5 text-emerald-200" size={22} aria-hidden="true" /><div><h2 className="text-lg font-semibold text-white">Сохранённые экспорты</h2><p className="mt-1 text-sm leading-6 text-slate-400">Повторное скачивание проверяет SHA-256 файла по записи HCP. Снимки и отчёты не удаляются при завершении доступа к хосту.</p></div></div>
      <div className="mt-4 space-y-3">{reports.length ? reports.map((report) => <article key={report.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4"><div className="flex flex-col justify-between gap-3 sm:flex-row"><div><p className="font-semibold text-white">{report.subject.projectName} · {report.hostAlias}</p><p className="mt-1 text-sm text-slate-400">{report.subject.clientName} · {report.subject.period} · {formatDate(report.createdAt)}</p><p className="mt-2 break-all text-xs text-slate-500">PDF SHA-256: {report.pdfSha256}<br />Снимок: {report.snapshotSha256}<br />Манифест источников: {report.sourceManifestSha256}</p></div><a className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-4 text-sm font-semibold text-slate-100 hover:bg-slate-800" href={`/api/ansible/project-reports/${encodeURIComponent(report.id)}`}><Download size={16} aria-hidden="true" />Скачать PDF</a></div></article>) : <p className="text-sm text-slate-500">Итоговые отчёты для выбранного хоста ещё не формировались.</p>}</div></section>
    {message ? <p className="sr-only" aria-live="polite">{message}</p> : null}
  </div>;
}
