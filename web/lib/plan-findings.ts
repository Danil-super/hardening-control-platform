export type PlanFinding = { id: string; title: string; category: string; risk: string; description: string; recommendation: string; severityUnknown?: boolean; severityAssessment?: { level: string } | null };
export const planRiskLevels = [
  { id: "critical", label: "Критические", tone: "border-red-400/50 bg-red-500/15 text-red-100" },
  { id: "high", label: "Высокие", tone: "border-orange-400/40 bg-orange-500/10 text-orange-100" },
  { id: "medium", label: "Средние", tone: "border-amber-400/40 bg-amber-500/10 text-amber-100" },
  { id: "low", label: "Низкие", tone: "border-sky-400/40 bg-sky-500/10 text-sky-100" },
  { id: "unknown", label: "Не оценены", tone: "border-slate-500 bg-slate-800 text-slate-200" },
  { id: "info", label: "Информация", tone: "border-slate-600 bg-slate-900 text-slate-300" },
] as const;

export function planFindingRisk(finding: Pick<PlanFinding, "risk" | "severityUnknown" | "severityAssessment">) {
  return finding.severityUnknown ? "unknown" : finding.severityAssessment?.level === "critical" ? "critical" : finding.risk;
}

export function selectPlanFindings<T extends PlanFinding>(findings: T[], options: { risk: string; query: string }) {
  const query = options.query.trim().toLocaleLowerCase("ru");
  const rank = new Map<string, number>(planRiskLevels.map((level, index) => [level.id, index]));
  return findings.filter((finding) => (options.risk === "all" || planFindingRisk(finding) === options.risk)
    && (!query || `${finding.title} ${finding.category} ${finding.description} ${finding.recommendation}`.toLocaleLowerCase("ru").includes(query)))
    .sort((a, b) => (rank.get(planFindingRisk(a)) ?? 5) - (rank.get(planFindingRisk(b)) ?? 5));
}
