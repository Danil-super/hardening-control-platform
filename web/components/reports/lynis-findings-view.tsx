"use client";

import { useMemo, useState } from "react";
import { ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { FindingDescription } from "@/components/reports/finding-description";
import type { Finding } from "@/types";

function LynisFindingRow({ finding, reportId }: { finding: Finding; reportId: string }) {
  const [expanded, setExpanded] = useState(false);
  const data = finding.lynis;
  const label = data?.kind === "warning" ? "Предупреждение" : data?.kind === "suggestion" ? "Совет по усилению" : "Состояние проверки";
  return <article className="px-3 py-2"><details className="group" onToggle={(event) => setExpanded(event.currentTarget.open)}>
    <summary className="flex cursor-pointer flex-wrap items-start gap-2 py-1 text-sm"><ChevronRight size={15} className="mt-0.5 shrink-0 transition-transform group-open:rotate-90" aria-hidden="true" /><span className="min-w-0 flex-1 break-words font-semibold text-white">{finding.title}</span><span className={`rounded-md border px-2 py-1 text-[11px] ${data?.kind === "warning" ? "border-amber-400/40 bg-amber-500/10 text-amber-100" : "border-slate-600 bg-slate-900 text-slate-300"}`}>{label}</span></summary>
    {expanded ? <div className="space-y-4 py-3 text-sm leading-6 [overflow-wrap:anywhere]">
      <div><h3 className="mb-1 font-semibold text-slate-100">Что обнаружено</h3><FindingDescription original={finding.description} reportId={reportId} findingId={finding.id} expanded={expanded} /></div>
      {data ? <div><h3 className="font-semibold text-slate-100">Почему это важно</h3><p className="text-slate-400">{data.impact}</p></div> : null}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3"><h3 className="font-semibold text-slate-100">Что проверить и сделать</h3><p className="mt-1 text-slate-200">{finding.recommendation}</p></div>
      {data ? <><p className="text-xs text-slate-500">{finding.category} · Код {data.ruleId} · {data.explanationKnown ? "Пояснение HCP по описанию правила CISOfy" : "Проверенного пояснения в справочнике пока нет"}. Критичность этого пункта Lynis не указал.</p><a href={data.reference} target="_blank" rel="noreferrer" className="inline-flex min-h-8 items-center text-xs text-sky-200 underline underline-offset-4">Описание проверки Lynis · {data.ruleId}</a><details className="rounded-lg border border-slate-800 p-3"><summary className="cursor-pointer text-xs font-semibold text-sky-200">Оригинальное сообщение и технические данные</summary><dl className="mt-2 space-y-2 text-xs text-slate-400"><div><dt>Сообщение</dt><dd lang="en" className="whitespace-pre-wrap">{data.message || "Не приведено"}</dd></div><div><dt>Контекст</dt><dd className="whitespace-pre-wrap">{data.details || "Не приведён"}</dd></div><div><dt>Предложение инструмента</dt><dd className="whitespace-pre-wrap">{data.solution || "Не приведено"}</dd></div></dl></details></> : finding.evidence ? <pre className="whitespace-pre-wrap text-xs text-slate-400">{finding.evidence}</pre> : null}
    </div> : null}
  </details></article>;
}

export function LynisFindingsView({ findings, reportId }: { findings: Finding[]; reportId: string }) {
  const [kind, setKind] = useState("all");
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const categories = useMemo(() => Array.from(new Set(findings.map((finding) => finding.category))), [findings]);
  const filtered = findings.filter((finding) => (kind === "all" || (finding.lynis?.kind ?? "execution") === kind)
    && (category === "all" || finding.category === category)
    && `${finding.title} ${finding.description} ${finding.recommendation} ${finding.lynis?.ruleId ?? ""} ${finding.lynis?.details ?? ""}`.toLocaleLowerCase("ru").includes(query.trim().toLocaleLowerCase("ru")));
  const pages = Math.max(1, Math.ceil(filtered.length / 25));
  const current = Math.min(page, pages);
  const labels: Record<string, string> = { all: "Все пункты", warning: "Предупреждения", suggestion: "Советы по усилению", execution: "Состояние проверки" };
  return <section className="space-y-3" aria-label="Результаты Lynis">
    <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4"><h2 className="font-semibold text-white">Предупреждения и рекомендации Lynis</h2><p className="mt-1 text-sm leading-6 text-slate-400">Предупреждения требуют проверки; советы предлагают дополнительное усиление. Они не являются списком подтверждённых CVE и не задают уровень критичности. Настройки сервера автоматически не изменяются.</p>
      <div className="mt-3 flex flex-wrap gap-2">{Object.entries(labels).filter(([value]) => value !== "execution" || findings.some((finding) => !finding.lynis)).map(([value, label]) => <Button key={value} variant="secondary" aria-pressed={kind === value} onClick={() => { setKind(value); setPage(1); }}>{label} · {value === "all" ? findings.length : findings.filter((finding) => (finding.lynis?.kind ?? "execution") === value).length}</Button>)}</div>
      <div className="mt-3 grid min-w-0 gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,250px)]"><label className="min-w-0 text-xs text-slate-400">Поиск по проблеме или коду<input type="search" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} className="mt-1 h-9 w-full border px-3 text-sm" placeholder="Например, DNS, SSH или GEN-0010" /></label><label className="min-w-0 text-xs text-slate-400">Категория<Select value={category} onValueChange={(value) => { setCategory(value); setPage(1); }} className="mt-1 w-full"><option value="all">Все категории</option>{categories.map((value) => <option key={value} value={value}>{value}</option>)}</Select></label></div>
    </div>
    <p aria-live="polite" className="text-xs text-slate-500">Показано {filtered.length ? (current - 1) * 25 + 1 : 0}–{Math.min(current * 25, filtered.length)} из {filtered.length}. Нажмите на название, чтобы увидеть описание и действия.</p>
    <div className="divide-y divide-slate-800 rounded-lg border border-slate-800 bg-slate-950/70">{filtered.slice((current - 1) * 25, current * 25).map((finding) => <LynisFindingRow key={finding.id} finding={finding} reportId={reportId} />)}</div>
    {!filtered.length ? <p className="py-3 text-sm text-slate-400">Нет пунктов для выбранных фильтров.</p> : null}
    {pages > 1 ? <nav aria-label="Страницы Lynis" className="flex items-center justify-between gap-3"><Button variant="secondary" disabled={current === 1} onClick={() => setPage(current - 1)}>Назад</Button><span className="text-xs text-slate-400">{current} / {pages}</span><Button variant="secondary" disabled={current === pages} onClick={() => setPage(current + 1)}>Далее</Button></nav> : null}
  </section>;
}
