import Link from "next/link";
import { AlertTriangle } from "lucide-react";
import type { HostRiskSummary as RiskSummary } from "@/lib/host-risk-summary";

const bands = [
  { key: "critical", label: "Критические", shortLabel: "Крит.", color: "border-red-400/40 bg-red-500/15 text-red-100" },
  { key: "high", label: "Высокие", shortLabel: "Выс.", color: "border-orange-400/30 bg-orange-500/10 text-orange-100" },
  { key: "medium", label: "Средние", shortLabel: "Сред.", color: "border-amber-400/30 bg-amber-500/10 text-amber-100" },
  { key: "low", label: "Низкие", shortLabel: "Низ.", color: "border-sky-400/30 bg-sky-500/10 text-sky-100" },
  { key: "unknown", label: "Не оценены", shortLabel: "Без оценки", color: "border-slate-500/50 bg-slate-800/80 text-slate-100" },
] as const;

export function HostRiskSummary({ summary, hostAlias }: { summary?: RiskSummary; hostAlias: string }) {
  const href = `/reports/correlation/${encodeURIComponent(hostAlias)}`;
  if (!summary?.auditCount) return summary?.identityExcludedCount ? <Link href={href} prefetch={false} className="text-sm text-amber-100 underline">Нет проверок текущей идентичности · исторических источников: {summary.identityExcludedCount}</Link>
    : <p className="text-sm text-slate-400">Аудит ещё не выполнен</p>;
  const details = `Последние свежие проверки: ${summary.freshCount}. Информационных наблюдений: ${summary.info}. Неполных проверок: ${summary.partialCount}. Устаревших: ${summary.staleCount}.`;
  return <div className="min-w-[280px] max-w-80 space-y-1">
    {summary.identityExcludedCount ? <p className="text-xs text-amber-100">Отдельная история без совпадения идентичности: {summary.identityExcludedCount}</p> : null}
    {summary.freshCount ? <div className="flex flex-wrap items-center gap-1 whitespace-nowrap" aria-label={`Находки хоста ${hostAlias}`}>
      {bands.map(({ key, label, shortLabel, color }) => <Link key={key} href={`${href}?risk=${key}`} prefetch={false}
        aria-label={`${label}: ${summary[key]}`}
        title={key === "unknown" ? `${label}: ${summary[key]}. Источник не указал критичность. Это не означает низкий риск.` : `${label}: ${summary[key]}. По последним проверкам каждого инструмента и профиля.`}
        className={`inline-flex min-h-7 items-center gap-1.5 rounded-md border px-2 py-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 ${summary[key] ? color : "border-slate-800 bg-slate-950/40 text-slate-500"}`}>
        <span className="text-[11px]">{shortLabel}</span>
        <span className="text-xs font-semibold tabular-nums">{summary[key]}</span>
      </Link>)}
    </div> : <p className="text-sm text-amber-100">Нет доступных свежих результатов</p>}
    <div className="flex items-center gap-3 whitespace-nowrap text-[11px] leading-4">
      <Link href={href} prefetch={false} title={details} aria-label={`Сводка хоста ${hostAlias}. ${details}`} className="text-sky-200 underline underline-offset-4">Сводка · проверок: {summary.freshCount}</Link>
      {summary.partialCount || summary.staleCount ? <span title={details} className="inline-flex items-center gap-1 text-amber-100"><AlertTriangle size={12} aria-hidden="true" />{summary.partialCount ? `Неполных: ${summary.partialCount}` : null}{summary.partialCount && summary.staleCount ? " · " : null}{summary.staleCount ? `Устаревших: ${summary.staleCount}` : null}</span> : null}
    </div>
  </div>;
}
