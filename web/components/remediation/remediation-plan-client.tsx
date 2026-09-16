"use client";

import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, FileWarning, Plus, RefreshCw } from "lucide-react";
import { Button, LinkButton } from "@/components/ui/button";
import { useFeedbackMessage } from "@/components/ui/feedback";
import { errorMessage, readApiResponse } from "@/lib/client-api";

type PlanStatus = "discovered" | "proposed" | "agreed" | "completed" | "confirmed" | "accepted_risk";
type Evidence = { reportId: string; findingId: string; source: string; mode: string; createdAt: string | null; evidence: string; reportSha256: string };
type PlanItem = { id: string; hostAlias: string; findingKey: string; title: string; category: string; risk: "high" | "medium" | "low" | "info"; description: string; recommendation: string; evidence: Evidence[]; status: PlanStatus; owner: string | null; dueAt: string | null; approvalReference: string | null; implementationNote: string | null; verificationReportId: string | null; riskAcceptedUntil: string | null; createdAt: string; updatedAt: string };
type CorrelationFinding = { id: string; title: string; category: string; risk: string; description: string; recommendation: string; sources: Evidence[] };
type Coverage = { reportId: string; mode: string; createdAt: string | null; fresh: boolean; partial: boolean; available: boolean; validTime: boolean; auditEvidence: boolean };
type Host = { alias: string };
type PlanData = { ok?: boolean; items?: PlanItem[]; correlation?: { findings?: CorrelationFinding[]; coverage?: Coverage[] }; message?: string };

const labels: Record<PlanStatus, string> = { discovered: "Найдено", proposed: "Предложено", agreed: "Согласовано", completed: "Выполнено", confirmed: "Подтверждено", accepted_risk: "Принято как риск" };
const transitions: Record<PlanStatus, PlanStatus[]> = { discovered: ["proposed"], proposed: ["agreed", "accepted_risk"], agreed: ["proposed", "completed", "accepted_risk"], completed: ["agreed", "confirmed"], confirmed: [], accepted_risk: ["proposed"] };
const riskTone: Record<string, string> = { high: "border-red-400/40 bg-red-500/10 text-red-100", medium: "border-amber-400/40 bg-amber-500/10 text-amber-100", low: "border-sky-400/40 bg-sky-500/10 text-sky-100", info: "border-slate-600 bg-slate-800 text-slate-200" };
const inputClass = "mt-1 h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:border-sky-300 focus:outline-none";

function formatDate(value: string | null) {
  if (!value) return "не указан";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

export function RemediationPlanClient({ initialHost = "" }: { initialHost?: string }) {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [hostAlias, setHostAlias] = useState(initialHost);
  const [data, setData] = useState<PlanData>({});
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState<string>("");
  const [message, setMessage] = useFeedbackMessage();
  const [form, setForm] = useState({ note: "", owner: "", dueAt: "", approvalReference: "", verificationReportId: "", riskAcceptedUntil: "" });

  async function loadHosts() {
    try {
      const response = await fetch("/api/ansible/hosts", { cache: "no-store" });
      const payload = await readApiResponse(response) as { ok?: boolean; hosts?: Host[]; message?: string };
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось прочитать список хостов.");
      const next = payload.hosts ?? [];
      setHosts(next);
      setHostAlias((current) => current || next[0]?.alias || "");
    } catch (error) { setMessage(errorMessage(error, "Не удалось прочитать список хостов.")); }
  }

  async function loadPlan() {
    if (!hostAlias) { setData({}); return; }
    setLoading(true);
    try {
      const response = await fetch(`/api/ansible/remediation-plans?hostAlias=${encodeURIComponent(hostAlias)}`, { cache: "no-store" });
      const payload = await readApiResponse(response) as PlanData;
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось прочитать план устранения.");
      setData(payload);
    } catch (error) { setData({}); setMessage(errorMessage(error, "Не удалось прочитать план устранения.")); }
    finally { setLoading(false); }
  }

  useEffect(() => { void loadHosts(); }, []);
  useEffect(() => { void loadPlan(); }, [hostAlias]);

  const planned = useMemo(() => new Set((data.items ?? []).filter((item) => !["confirmed", "accepted_risk"].includes(item.status)).map((item) => item.findingKey)), [data.items]);
  const verificationReports = (data.correlation?.coverage ?? []).filter((item) => item.auditEvidence && item.available && item.validTime && !item.partial && item.fresh);

  async function addFinding(findingKey: string) {
    setUpdating(`add:${findingKey}`);
    try {
      const response = await fetch("/api/ansible/remediation-plans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hostAlias, findingKey }) });
      const payload = await readApiResponse(response) as PlanData;
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось добавить находку в план.");
      setMessage(payload.message ?? "Находка добавлена в план.", "success"); await loadPlan();
    } catch (error) { setMessage(errorMessage(error, "Не удалось добавить находку в план.")); }
    finally { setUpdating(""); }
  }

  function openTransition(item: PlanItem, status: PlanStatus) {
    setUpdating(`${item.id}:${status}`);
    setForm({ note: "", owner: item.owner ?? "", dueAt: item.dueAt ? item.dueAt.slice(0, 10) : "", approvalReference: item.approvalReference ?? "", verificationReportId: "", riskAcceptedUntil: item.riskAcceptedUntil ? item.riskAcceptedUntil.slice(0, 10) : "" });
  }

  async function updateItem(item: PlanItem, status: PlanStatus) {
    try {
      const response = await fetch(`/api/ansible/remediation-plans/${encodeURIComponent(item.id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status, ...form, dueAt: form.dueAt ? new Date(`${form.dueAt}T12:00:00Z`).toISOString() : "", riskAcceptedUntil: form.riskAcceptedUntil ? new Date(`${form.riskAcceptedUntil}T12:00:00Z`).toISOString() : "" }) });
      const payload = await readApiResponse(response) as PlanData;
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось обновить пункт плана.");
      setMessage(payload.message ?? "Пункт плана обновлён.", "success"); setUpdating(""); await loadPlan();
    } catch (error) { setMessage(errorMessage(error, "Не удалось обновить пункт плана.")); }
  }

  const transitionTarget = updating.includes(":") ? updating.split(":").at(-1) as PlanStatus : null;
  return <div className="space-y-6">
    <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
      <div><p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Проектный цикл</p><h1 className="mt-2 text-3xl font-semibold text-white">План устранения</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Находка становится работой только после решения специалиста и согласования заказчика. Это не электронная подпись: укажите номер тикета, письма или другого внешнего документа.</p></div>
      <Button variant="secondary" onClick={() => void loadPlan()} disabled={loading || !hostAlias}><RefreshCw size={16} className={loading ? "animate-spin" : ""} aria-hidden="true" />Обновить</Button>
    </header>
    <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 sm:p-5"><label className="block max-w-md text-sm text-slate-300">Целевой хост
      <select className={inputClass} value={hostAlias} onChange={(event) => setHostAlias(event.target.value)} disabled={loading}>{hosts.map((host) => <option key={host.alias} value={host.alias}>{host.alias}</option>)}</select>
    </label>{!hosts.length && !loading ? <p className="mt-3 text-sm text-amber-100">Сначала подключите хотя бы один хост.</p> : null}</section>

    {data.correlation?.findings?.length ? <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 sm:p-5">
      <div className="flex items-start gap-3"><FileWarning className="mt-0.5 text-amber-200" size={22} aria-hidden="true" /><div><h2 className="text-lg font-semibold text-white">Свежие доказательства аудита</h2><p className="mt-1 text-sm leading-6 text-slate-400">Добавляйте в план только те проблемы, которые требуют решения. Совпадение CVE или порта само по себе не доказывает применимость.</p></div></div>
      <div className="mt-4 space-y-3">{data.correlation.findings.map((finding) => <article key={finding.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4"><div className="flex flex-col justify-between gap-3 sm:flex-row"><div><h3 className="font-semibold text-white">{finding.title}</h3><p className="mt-1 text-sm text-slate-400">{finding.description}</p><p className="mt-2 text-sm text-slate-200">{finding.recommendation}</p></div><span className={`h-fit rounded-md border px-2 py-1 text-xs font-semibold ${riskTone[finding.risk] ?? riskTone.info}`}>{finding.risk}</span></div>
        <p className="mt-3 text-xs text-slate-500">Источники: {finding.sources.map((source) => `${source.mode} · ${source.reportId}`).join("; ")}</p>
        <Button className="mt-3" variant="secondary" disabled={Boolean(updating) || planned.has(finding.id)} onClick={() => void addFinding(finding.id)}><Plus size={16} aria-hidden="true" />{planned.has(finding.id) ? "Уже в активном плане" : "Добавить в план"}</Button></article>)}</div>
    </section> : hostAlias && !loading ? <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-5 text-sm leading-6 text-slate-400">Свежих проблем для плана нет. Выполните аудит и проверьте покрытие источниками.</section> : null}

    <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 sm:p-5"><div className="flex items-start gap-3"><CheckCircle2 className="mt-0.5 text-sky-200" size={22} aria-hidden="true" /><div><h2 className="text-lg font-semibold text-white">Решения и подтверждения</h2><p className="mt-1 text-sm leading-6 text-slate-400">«Выполнено» фиксирует работу специалиста. «Подтверждено» требует полного свежего повторного аудита после этой работы.</p></div></div>
      <div className="mt-4 space-y-4">{data.items?.length ? data.items.map((item) => { const target = updating.startsWith(`${item.id}:`) ? transitionTarget : null; return <article key={item.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4"><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><h3 className="font-semibold text-white">{item.title}</h3><p className="mt-1 text-sm text-slate-400">{item.description}</p></div><div className="flex flex-wrap gap-2"><span className={`rounded-md border px-2 py-1 text-xs font-semibold ${riskTone[item.risk]}`}>{item.risk}</span><span className="rounded-md border border-sky-400/30 bg-sky-500/10 px-2 py-1 text-xs font-semibold text-sky-100">{labels[item.status]}</span></div></div>
        <p className="mt-3 text-sm text-slate-200">Рекомендация: {item.recommendation}</p><p className="mt-2 text-xs text-slate-500">Доказательства: {item.evidence.map((source) => source.reportId).join(", ")}. Создан: {formatDate(item.createdAt)}.</p>
        {item.owner || item.dueAt || item.approvalReference ? <p className="mt-2 text-xs text-slate-400">Ответственный: {item.owner ?? "не указан"} · срок: {formatDate(item.dueAt)} · согласование: {item.approvalReference ?? "не указано"}</p> : null}
        {item.implementationNote ? <p className="mt-2 text-xs text-slate-400">Выполнение: {item.implementationNote}</p> : null}
        {item.verificationReportId ? <LinkButton className="mt-3" variant="secondary" href={`/reports/agentless/${encodeURIComponent(item.verificationReportId)}`}>Повторный аудит</LinkButton> : null}
        {!target ? <div className="mt-4 flex flex-wrap gap-2">{transitions[item.status].map((status) => <Button key={status} variant={status === "accepted_risk" ? "secondary" : "primary"} disabled={Boolean(updating)} onClick={() => openTransition(item, status)}>{labels[status]}</Button>)}</div> : <div className="mt-4 rounded-md border border-sky-400/25 bg-sky-500/5 p-4"><h4 className="font-semibold text-sky-100">Перевести в статус «{labels[target]}»</h4><label className="mt-3 block text-sm text-slate-300">Комментарий
          <textarea className="mt-1 min-h-24 w-full rounded-md border border-slate-700 bg-slate-950 p-3 text-sm text-slate-100" value={form.note} onChange={(event) => setForm((value) => ({ ...value, note: event.target.value }))} placeholder={target === "proposed" ? "Мера и риск её применения" : target === "completed" ? "Что именно выполнил специалист" : "Основание решения"} />
        </label>{["agreed", "accepted_risk"].includes(target) ? <div className="mt-3 grid gap-3 sm:grid-cols-2"><label className="text-sm text-slate-300">Ответственный<input className={inputClass} value={form.owner} onChange={(event) => setForm((value) => ({ ...value, owner: event.target.value }))} placeholder="ФИО или роль" /></label><label className="text-sm text-slate-300">Ссылка на согласование<input className={inputClass} value={form.approvalReference} onChange={(event) => setForm((value) => ({ ...value, approvalReference: event.target.value }))} placeholder="Тикет, письмо, акт" /></label></div> : null}
        {target === "agreed" ? <label className="mt-3 block text-sm text-slate-300">Срок выполнения<input className={inputClass} type="date" value={form.dueAt} onChange={(event) => setForm((value) => ({ ...value, dueAt: event.target.value }))} /></label> : null}
        {target === "accepted_risk" ? <label className="mt-3 block text-sm text-slate-300">Срок действия принятого риска<input className={inputClass} type="date" value={form.riskAcceptedUntil} onChange={(event) => setForm((value) => ({ ...value, riskAcceptedUntil: event.target.value }))} /></label> : null}
        {target === "confirmed" ? <label className="mt-3 block text-sm text-slate-300">Полный свежий повторный отчёт<select className={inputClass} value={form.verificationReportId} onChange={(event) => setForm((value) => ({ ...value, verificationReportId: event.target.value }))}><option value="">Выберите отчёт</option>{verificationReports.map((report) => <option key={report.reportId} value={report.reportId}>{report.mode} · {formatDate(report.createdAt)}</option>)}</select></label> : null}
        <div className="mt-4 flex flex-wrap gap-2"><Button onClick={() => void updateItem(item, target)} disabled={Boolean(updating) && !updating.startsWith(item.id)}>{target === "confirmed" ? "Подтвердить результат" : "Сохранить решение"}</Button><Button variant="secondary" onClick={() => setUpdating("")}>Отмена</Button></div></div>}</article>; }) : <p className="text-sm text-slate-500">Пунктов плана пока нет.</p>}</div>
    </section>
  </div>;
}
