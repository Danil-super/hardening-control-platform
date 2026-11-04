/**
 * Current, source-bound host audit overview. Not a security score and not a
 * percentage of all CVEs, compliance controls or attack paths.
 */
export type DashboardHostEvidence = {
  alias: string;
  lastReport?: { createdAt: string | null } | null;
  riskSummary?: {
    critical: number; high: number; medium: number; low: number; unknown: number;
    auditCount: number; freshCount: number; partialCount: number; staleCount: number;
    identityExcludedCount?: number;
    lastSecurityAuditAt?: string | null;
    maxAgeHours: number;
  } | null;
};

export type DashboardHostState =
  "unknown_evidence" | "no_audit" | "stale" | "needs_review" | "has_fresh_evidence";
export type DashboardFilter = "all" | "fresh" | "review" | "no_fresh";
export type SeverityTotals = {
  critical: number; high: number; medium: number; low: number; unknown: number;
};
export type DashboardHostAssessment = {
  alias: string;
  state: DashboardHostState;
  stateLabel: string;
  detail: string;
  criticalHigh: number;
  unknown: number;
  severity: SeverityTotals;
  lastAuditAt: string | null;
};
const zero = (): SeverityTotals => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
const nonnegative = (value: unknown): number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;
const validCounter = (value: unknown) =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

export function describeHostAuditEvidence(host: DashboardHostEvidence): DashboardHostAssessment {
  const risk = host.riskSummary;
  // An old API or malformed projection does NOT justify "never audited".
  const counters = ["auditCount", "freshCount", "partialCount", "staleCount",
    "critical", "high", "medium", "low", "unknown", "maxAgeHours"] as const;
  const hasValidCounters = risk && counters.every(key => validCounter(risk[key]))
    && (risk.identityExcludedCount === undefined || validCounter(risk.identityExcludedCount));
  const lastAuditAt = typeof risk?.lastSecurityAuditAt === "string"
    && Number.isFinite(Date.parse(risk.lastSecurityAuditAt))
    ? risk.lastSecurityAuditAt : null;
  const auditCount = nonnegative(risk?.auditCount);
  const freshCount = nonnegative(risk?.freshCount);
  const partialCount = nonnegative(risk?.partialCount);
  const staleCount = nonnegative(risk?.staleCount);
  const identityExcluded = nonnegative(risk?.identityExcludedCount);
  const inconsistentCounters = freshCount > auditCount
    || staleCount > auditCount || partialCount > auditCount
    || freshCount + staleCount > auditCount
    || (freshCount < auditCount && partialCount === 0 && staleCount === 0);
  // Only current, countable observations. Stale/unknown reports must not
  // become a misleading "0 known CVEs" dashboard assertion.
  const currentSeverity = hasValidCounters && !inconsistentCounters && auditCount > 0
    && freshCount > 0 ? {
      critical: nonnegative(risk?.critical), high: nonnegative(risk?.high),
      medium: nonnegative(risk?.medium), low: nonnegative(risk?.low),
      unknown: nonnegative(risk?.unknown),
    } : zero();
  const make = (state: DashboardHostState, stateLabel: string, detail: string): DashboardHostAssessment => ({
    alias: host.alias, state, stateLabel, detail, severity: currentSeverity,
    criticalHigh: currentSeverity.critical + currentSeverity.high,
    unknown: currentSeverity.unknown, lastAuditAt,
  });
  if (!hasValidCounters) return make("unknown_evidence", "Статус не подтверждён",
    "Сводка отсутствует либо содержит некорректные счётчики. Проверьте исходные отчёты.");
  if (inconsistentCounters) return make("needs_review", "Требует уточнения",
    "Счётчики источников противоречат друг другу. Сохранённая область проверки не подтверждена.");
  if (identityExcluded && !freshCount) return make("needs_review", "История исключена по идентичности",
    "Исторические отчёты не соответствуют текущей идентичности хоста. Проверьте привязку актива и выполните новый аудит.");
  if (!auditCount) return make("no_audit", "Нет доказательств аудита",
    "Инвентаризация и сбор фактов не считаются аудитом безопасности.");
  if (!freshCount) return make("stale", "Нет свежей проверки",
    "Сохранённые проверки устарели либо свежесть и доступность источников не подтверждены.");
  if (partialCount || staleCount || identityExcluded) return make("needs_review", "Требует уточнения",
    "Есть свежие данные, но часть источников неполная, устарела или исключена по идентичности.");
  return make("has_fresh_evidence", "Есть свежие доказательства",
    "Последние применимые проверки в наблюдаемой области; полнота всех CVE не установлена.");
}

export function filterDashboardAssessments(assessed: DashboardHostAssessment[], filter: DashboardFilter) {
  return assessed.filter(host => filter === "all"
    || (filter === "fresh" && host.state === "has_fresh_evidence")
    || (filter === "review" && ["unknown_evidence", "needs_review"].includes(host.state))
    || (filter === "no_fresh" && ["no_audit", "stale"].includes(host.state)));
}

export function summarizeDashboardEvidence(hosts: DashboardHostEvidence[]) {
  const assessed = hosts.map(describeHostAuditEvidence);
  const severity = assessed.reduce((total, item) => ({
    critical: total.critical + item.severity.critical,
    high: total.high + item.severity.high,
    medium: total.medium + item.severity.medium,
    low: total.low + item.severity.low,
    unknown: total.unknown + item.severity.unknown,
  }), zero());
  return {
    totalHosts: assessed.length,
    freshEvidenceHosts: assessed.filter(x => x.state === "has_fresh_evidence").length,
    needsReviewHosts: assessed.filter(x => x.state === "needs_review" || x.state === "unknown_evidence").length,
    noFreshEvidenceHosts: assessed.filter(x => x.state === "no_audit" || x.state === "stale").length,
    hostsWithAudits: hosts.filter(x => nonnegative(x.riskSummary?.auditCount) > 0).length,
    criticalHighFindings: severity.critical + severity.high,
    unknownSeverityFindings: severity.unknown,
    severity,
    assessed,
  };
}
