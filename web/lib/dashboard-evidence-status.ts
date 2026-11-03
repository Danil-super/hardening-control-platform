/**
 * Evidence-aware overview of host assessment state.
 * Counts are NOT a security score, coverage percentage of CVEs or proof that
 * a host is secure. Only current, identity-bound security audit evidence counts.
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

export type DashboardHostAssessment = {
  alias: string;
  state: "no_audit" | "stale" | "needs_review" | "has_fresh_evidence";
  stateLabel: string;
  detail: string;
  criticalHigh: number;
  unknown: number;
  lastAuditAt: string | null;
};

const nonnegative = (value: unknown): number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;

export function describeHostAuditEvidence(host: DashboardHostEvidence): DashboardHostAssessment {
  const risk = host.riskSummary;
  const auditCount = nonnegative(risk?.auditCount);
  const freshCount = nonnegative(risk?.freshCount);
  const partialCount = nonnegative(risk?.partialCount);
  const staleCount = nonnegative(risk?.staleCount);
  const identityExcluded = nonnegative(risk?.identityExcludedCount);
  const criticalHigh = nonnegative(risk?.critical) + nonnegative(risk?.high);
  const unknown = nonnegative(risk?.unknown);
  // lastReport may be a facts or package-inventory run, not a security audit.
  const lastAuditAt = typeof risk?.lastSecurityAuditAt === "string"
    && Number.isFinite(Date.parse(risk.lastSecurityAuditAt))
    ? risk.lastSecurityAuditAt : null;
  if (!auditCount) return {
    alias: host.alias, state: "no_audit", stateLabel: "Нет доказательств аудита",
    detail: "Нет сохранённых проверок безопасности; инвентаризация и сбор фактов не считаются аудитом.",
    criticalHigh, unknown, lastAuditAt,
  };
  if (!freshCount) return {
    alias: host.alias, state: "stale", stateLabel: "Нет свежей проверки",
    detail: "Источники устарели, недоступны или не имеют подтверждённой свежести.",
    criticalHigh, unknown, lastAuditAt,
  };
  // Never call the observed scope complete if the source counters disagree.
  // A fresh source that cannot be accounted for is a coverage gap, not proof.
  const inconsistentCounters = freshCount > auditCount
    || staleCount > auditCount
    || partialCount > auditCount
    || freshCount + staleCount > auditCount
    || (freshCount < auditCount && partialCount === 0 && staleCount === 0);
  if (partialCount || staleCount || identityExcluded || inconsistentCounters) return {
    alias: host.alias, state: "needs_review", stateLabel: "Требует уточнения",
    detail: "Есть свежие данные, но часть источников неполная, устарела, исключена по идентичности либо учтена некорректно.",
    criticalHigh, unknown, lastAuditAt,
  };
  return {
    alias: host.alias, state: "has_fresh_evidence", stateLabel: "Есть свежие доказательства",
    detail: "Свежие сохранённые проверки в наблюдаемой области; полнота всех CVE не установлена.",
    criticalHigh, unknown, lastAuditAt,
  };
}

export function summarizeDashboardEvidence(hosts: DashboardHostEvidence[]) {
  const assessed = hosts.map(describeHostAuditEvidence);
  return {
    totalHosts: assessed.length,
    freshEvidenceHosts: assessed.filter(x => x.state === "has_fresh_evidence").length,
    needsReviewHosts: assessed.filter(x => x.state === "needs_review").length,
    noFreshEvidenceHosts: assessed.filter(x => x.state === "no_audit" || x.state === "stale").length,
    hostsWithAudits: hosts.filter(x => nonnegative(x.riskSummary?.auditCount) > 0).length,
    criticalHighFindings: assessed.reduce((sum, x) => sum + x.criticalHigh, 0),
    unknownSeverityFindings: assessed.reduce((sum, x) => sum + x.unknown, 0),
    assessed,
  };
}
