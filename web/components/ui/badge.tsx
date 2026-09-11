import type { FindingStatus, RiskLevel } from "@/types";

const riskClasses: Record<RiskLevel, string> = {
  high: "border-red-400/40 bg-red-500/15 text-red-200",
  medium: "border-amber-400/40 bg-amber-500/15 text-amber-100",
  low: "border-sky-400/40 bg-sky-500/15 text-sky-100",
  info: "border-slate-400/40 bg-slate-500/15 text-slate-200",
};

const statusClasses: Record<FindingStatus, string> = {
  failed: "border-red-400/40 bg-red-500/15 text-red-200",
  passed: "border-emerald-400/40 bg-emerald-500/15 text-emerald-100",
  fixed: "border-emerald-400/40 bg-emerald-500/15 text-emerald-100",
  manual: "border-violet-400/40 bg-violet-500/15 text-violet-100",
};

const riskLabels: Record<RiskLevel, string> = {
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Инфо",
};

const statusLabels: Record<FindingStatus, string> = {
  failed: "Не пройдено",
  passed: "Пройдено",
  fixed: "Исправлено",
  manual: "Вручную",
};

export function RiskBadge({ risk, unknown = false }: { risk: RiskLevel; unknown?: boolean }) {
  return (
    <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold uppercase ${riskClasses[risk]}`}>
      {unknown ? "Риск не оценён" : riskLabels[risk]}
    </span>
  );
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold uppercase ${statusClasses[status]}`}>
      {statusLabels[status]}
    </span>
  );
}
