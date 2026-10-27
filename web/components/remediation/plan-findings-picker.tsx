"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { ChevronRight, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { planFindingRisk, planRiskLevels, selectPlanFindings, type PlanFinding } from "@/lib/plan-findings";
import { auditReportLabels } from "@/lib/audit-job-status";

export type CandidateFinding = PlanFinding & { sources: { reportId: string; mode: string; createdAt: string | null }[] };

export function PlanRiskBadge({ finding }: { finding: Pick<PlanFinding, "risk" | "severityUnknown" | "severityAssessment"> }) {
  const level = planRiskLevels.find((item) => item.id === planFindingRisk(finding)) ?? planRiskLevels[5];
  return <span className={`inline-flex shrink-0 rounded-md border px-2 py-1 text-[11px] font-semibold ${level.tone}`}>{level.label}</span>;
}

export function PlanFindingsPicker({ findings, planned, busy, onAdd }: { findings: CandidateFinding[]; planned: Set<string>; busy: boolean; onAdd: (id: string) => void }) {
  const [risk, setRisk] = useState("all");
  const [query, setQuery] = useState("");
  const [hidePlanned, setHidePlanned] = useState(true);
  const [page, setPage] = useState(1);
  const eligible = useMemo(() => findings.filter((finding) => !hidePlanned || !planned.has(finding.id)), [findings, hidePlanned, planned]);
  const filtered = useMemo(() => selectPlanFindings(eligible, { risk, query }), [eligible, risk, query]);
  const counts = useMemo(() => new Map(planRiskLevels.map((level) => [level.id, eligible.filter((finding) => planFindingRisk(finding) === level.id).length])), [eligible]);
  const pages = Math.max(1, Math.ceil(filtered.length / 25));
  const currentPage = Math.min(page, pages);
  const visible = filtered.slice((currentPage - 1) * 25, currentPage * 25);
  return <div className="mt-4 space-y-3">
    <div className="flex flex-wrap gap-2" aria-label="Фильтр по уровню риска">
      <Button variant="secondary" aria-pressed={risk === "all"} className={risk === "all" ? "border-sky-300 text-sky-200" : ""} onClick={() => { setRisk("all"); setPage(1); }}>Все · {eligible.length}</Button>
      {planRiskLevels.map((level) => <Button key={level.id} variant="secondary" aria-pressed={risk === level.id} className={risk === level.id ? "border-sky-300 text-sky-200" : ""} onClick={() => { setRisk(level.id); setPage(1); }}>{level.label} · {counts.get(level.id) ?? 0}</Button>)}
    </div>
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center"><label className="block min-w-0 flex-1 text-xs text-slate-400">Поиск по CVE, пакету или рекомендации<input type="search" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} placeholder="Например, chromium или firewall" className="mt-1 h-9 w-full border border-slate-700 px-3 text-sm" /></label><label className="flex items-center gap-2 text-xs text-slate-400"><input type="checkbox" checked={hidePlanned} onChange={(event) => { setHidePlanned(event.target.checked); setPage(1); }} />Скрыть уже добавленные</label></div>
    <p className="text-xs text-slate-500" aria-live="polite">Показано {filtered.length ? (currentPage - 1) * 25 + 1 : 0}–{Math.min(currentPage * 25, filtered.length)} из {filtered.length}. Подробности раскрываются по нажатию на название.</p>
    <div className="divide-y divide-slate-800 rounded-lg border border-slate-800">{visible.map((finding) => <article key={finding.id} className="flex items-start gap-2 px-3 py-2">
      <details className="group min-w-0 flex-1"><summary className="flex min-h-8 cursor-pointer flex-wrap items-start gap-2 py-1 text-sm"><ChevronRight size={15} className="mt-0.5 shrink-0 transition-transform group-open:rotate-90" aria-hidden="true" /><span className="min-w-0 flex-1 break-words font-medium text-white">{finding.title}</span><PlanRiskBadge finding={finding} /></summary>
        <div className="space-y-2 py-2 pl-6 text-sm leading-6"><p className="text-slate-400">{finding.description}</p><p className="text-slate-200"><span className="font-semibold">Рекомендация: </span>{finding.recommendation}</p><p className="text-xs text-slate-500">{finding.category}</p><div className="flex flex-wrap gap-x-3 gap-y-1">{Array.from(new Map(finding.sources.map((source) => [source.reportId, source])).values()).map((source) => <Link key={source.reportId} href={`/reports/agentless/${encodeURIComponent(source.reportId)}`} prefetch={false} className="break-words text-xs text-sky-200 underline underline-offset-4">{auditReportLabels[source.mode] ?? source.mode}{source.createdAt ? ` · ${new Date(source.createdAt).toLocaleDateString("ru-RU")}` : ""}</Link>)}</div></div>
      </details>
      <Button variant="secondary" className="[&]:min-h-8 [&]:px-2 [&]:py-1 [&]:text-xs" title="Добавить в план без применения настроек на хосте" aria-label={`Добавить в план: ${finding.title}`} disabled={busy || planned.has(finding.id)} onClick={() => onAdd(finding.id)}><Plus size={14} aria-hidden="true" />{planned.has(finding.id) ? "В плане" : "В план"}</Button>
    </article>)}</div>
    {!visible.length ? <p className="py-3 text-sm text-slate-400">Нет находок для выбранных фильтров.</p> : null}
    {pages > 1 ? <nav aria-label="Страницы рекомендаций" className="flex items-center justify-between gap-3"><Button variant="secondary" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}>Назад</Button><span className="text-xs text-slate-400">{currentPage} / {pages}</span><Button variant="secondary" disabled={currentPage === pages} onClick={() => setPage(currentPage + 1)}>Далее</Button></nav> : null}
  </div>;
}
