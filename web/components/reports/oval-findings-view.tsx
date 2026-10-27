"use client";

import { useMemo, useState } from "react";
import { OvalFindingRow } from "@/components/reports/oval-finding-row";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import type { Finding } from "@/types";

type Level = "all" | "critical" | "high" | "medium" | "low" | "unknown";
const labels: Record<Level, string> = { all: "Все", critical: "Критический", high: "Высокий", medium: "Средний", low: "Низкий", unknown: "Не оценён" };
const priority: Record<Level, number> = { all: 0, critical: 5, high: 4, medium: 3, low: 2, unknown: 1 };
function levelOf(finding: Finding): Level {
  return finding.severityUnknown ? "unknown" : finding.severityAssessment?.level ?? (finding.risk === "info" ? "unknown" : finding.risk);
}

export function OvalFindingsView({ findings, reportId }: { findings: Finding[]; reportId: string }) {
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState<Level>("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const observations = useMemo(() => findings.filter((finding) => finding.status === "failed"), [findings]);
  const notes = findings.filter((finding) => finding.status !== "failed" && finding.id !== "astra_oval_scope");
  const counts = useMemo(() => observations.reduce((result, finding) => {
    result[levelOf(finding)] += 1;
    return result;
  }, { all: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }), [observations]);
  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("ru");
    return observations.filter((finding) => (level === "all" || levelOf(finding) === level)
      && (!query || `${finding.title}\n${finding.description}\n${finding.id}`.toLocaleLowerCase("ru").includes(query)))
      .sort((a, b) => priority[levelOf(b)] - priority[levelOf(a)] || a.title.localeCompare(b.title, "ru"));
  }, [observations, level, search]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pages);
  const start = (currentPage - 1) * pageSize;

  return <section className="space-y-4" aria-label="Обнаруженные уязвимости OVAL">
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
      <h2 className="text-lg font-semibold text-white">Обнаруженные уязвимости</h2>
      <p className="mt-2 text-sm leading-6 text-slate-400">Общее действие: проверьте бюллетени Astra и доступные обновления затронутых пакетов. После обновления повторите аудит. Разные определения одной CVE сохранены отдельно: они могут проверять разные пакеты или условия.</p>
      <div className="mt-4 flex flex-wrap gap-2">
        {(Object.keys(labels) as Level[]).map((value) => <button key={value} aria-pressed={level === value}
          onClick={() => { setLevel(value); setPage(1); }}
          className={`rounded-lg border px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 ${level === value ? "border-sky-300 bg-sky-300 text-slate-950" : "border-slate-700 bg-slate-900 text-slate-200"}`}>
          {labels[value]} · {value === "all" ? observations.length : counts[value]}
        </button>)}
      </div>
      <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-center">
        <input type="search" aria-label="Поиск CVE или пакета" placeholder="Поиск по CVE, пакету или описанию"
          value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} className="min-h-11 min-w-0 flex-1 rounded-xl border border-slate-700 px-3 py-2 text-sm" />
        <Select aria-label="Записей на странице" value={String(pageSize)} onValueChange={(value) => { setPageSize(Number(value)); setPage(1); }}>
          <option value="25">25 на странице</option><option value="50">50 на странице</option><option value="100">100 на странице</option>
        </Select>
      </div>
      <p className="mt-3 text-xs text-slate-400" role="status">Показано {filtered.length ? start + 1 : 0}–{Math.min(start + pageSize, filtered.length)} из {filtered.length} найденных записей</p>
    </div>
    <div className="divide-y divide-slate-800 rounded-xl border border-slate-800 bg-slate-950/70">
      {filtered.slice(start, start + pageSize).map((finding) => <OvalFindingRow key={finding.id} finding={finding} reportId={reportId} />)}
      {!filtered.length ? <p className="p-6 text-center text-sm text-slate-400">По выбранным условиям записей нет.</p> : null}
    </div>
    <nav aria-label="Страницы уязвимостей" className="flex items-center justify-between gap-3">
      <Button variant="secondary" disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Назад</Button>
      <span className="text-sm text-slate-400">{currentPage} / {pages}</span>
      <Button variant="secondary" disabled={currentPage >= pages} onClick={() => setPage(currentPage + 1)}>Далее</Button>
    </nav>
    {notes.length ? <details className="rounded-lg border border-amber-400/25 bg-slate-950/70 p-4"><summary className="cursor-pointer text-sm font-semibold text-amber-100">Требуют ручной проверки: {notes.length}</summary><div className="mt-3 space-y-3">{notes.map((finding) => <div key={finding.id}><p className="font-medium text-slate-200">{finding.title}</p><p className="mt-1 text-sm text-slate-400">{finding.description}</p>{finding.evidence ? <pre className="mt-2 whitespace-pre-wrap break-words text-xs text-slate-400">{finding.evidence}</pre> : null}</div>)}</div></details> : null}
  </section>;
}
