import { statSync } from "node:fs";
import { buildHostCorrelation, correlationMaxAgeHours, type CorrelatedFinding } from "@/lib/audit-correlation";
import { readAnsibleReport, targetAliasFromReport, reportTimestamp, type AnsibleReportSummary } from "@/lib/ansible-reports";
import { currentAssetBinding } from "@/lib/state-store";
import { explicitInventoryConnectionId } from "@/lib/inventory";

export type HostRiskSummary = {
  critical: number; high: number; medium: number; low: number; unknown: number; info: number;
  total: number; auditCount: number; freshCount: number; partialCount: number; staleCount: number;
  identityExcludedCount?: number;
  reviewSources: { reportId: string; mode: string; reason: string }[];
  unknownByTool: Record<string, number>;
  lastSecurityAuditAt: string | null;
  scope: "latest-per-tool-and-profile";
  maxAgeHours: number;
};

const cache = new Map<string, { signature: string; expiresAt: number; summary: HostRiskSummary }>();
export function riskBandOf(finding: CorrelatedFinding) {
  return finding.severityUnknown ? "unknown" : finding.severityAssessment?.level === "critical" ? "critical" : finding.risk;
}
export const isSecurityAudit = (mode: string) => !["facts", "events", "packages", "dependency-track"].includes(mode);

export function buildHostRiskSummary(hostAlias: string, reports: AnsibleReportSummary[]): HostRiskSummary {
  const sources = reports.filter((report) => targetAliasFromReport(report) === hostAlias && isSecurityAudit(report.mode));
  const minimumTime = Date.now() - correlationMaxAgeHours() * 3600_000;
  const binding = currentAssetBinding(hostAlias);
  const signature = JSON.stringify([correlationMaxAgeHours(), binding?.assetId, binding?.generation, explicitInventoryConnectionId(hostAlias), ...sources.map((report) => {
    const info = statSync(report.path);
    return [report.id, report.path, report.reportTimeValid, reportTimestamp(report) >= minimumTime, report.critical, report.high, report.medium, report.low, report.unknown, info.dev, info.ino, info.size, info.mtimeMs, info.ctimeMs];
  })]);
  const saved = cache.get(hostAlias);
  if (saved?.signature === signature && Date.now() < saved.expiresAt) return saved.summary;
  const correlation = buildHostCorrelation(hostAlias, reports);
  const coverage = correlation?.coverage.filter((item) => item.auditEvidence) ?? [];
  // Generic lastReport may be facts/package inventory. Only date actual,
  // current and available security audit evidence; exclude other assets.
  const reportsById = new Map(sources.map((report) => [report.id, report]));
  const lastAuditMs = coverage.reduce((latest, item) => {
    if (!item.current || !item.available || item.coverageIssues.some((issue) =>
      ["asset_identity_changed", "asset_connection_changed", "asset_binding_invalid",
       "legacy_identity_unknown"].includes(issue))) return latest;
    const report = reportsById.get(item.reportId);
    if (!report?.reportTimeValid) return latest;
    const observed = reportTimestamp(report);
    return Number.isFinite(observed) && observed >= 0 && observed < 8.64e15
      ? Math.max(latest, observed) : latest;
  }, -1);
  const summary: HostRiskSummary = {
    critical: 0, high: 0, medium: 0, low: 0, unknown: 0, info: 0, total: 0,
    auditCount: coverage.length, freshCount: coverage.filter((item) => item.fresh && item.available).length,
    partialCount: coverage.filter((item) => item.partial || !item.available).length,
    staleCount: coverage.filter((item) => !item.fresh).length,
    identityExcludedCount: correlation?.coverage.filter((item) => item.coverageIssues.some((issue) => ["asset_identity_changed", "asset_connection_changed", "asset_binding_invalid", "legacy_identity_unknown"].includes(issue))).length ?? 0,
    lastSecurityAuditAt: lastAuditMs >= 0 ? new Date(lastAuditMs).toISOString() : null,
    maxAgeHours: correlation?.maxAgeHours ?? 168, scope: "latest-per-tool-and-profile",
    reviewSources: [], unknownByTool: Object.create(null),
  };
  for (const source of correlation?.coverage ?? []) {
    const historical = source.coverageIssues.some(issue => ["asset_identity_changed", "asset_connection_changed", "asset_binding_invalid", "legacy_identity_unknown"].includes(issue));
    if (!historical && !(source.auditEvidence && (source.partial || !source.available || !source.fresh))) continue;
    let reason = historical ? "Исторический отчёт исключён: привязка к текущему хосту не подтверждена."
      : !source.fresh ? "Результат устарел или его дата не подтверждена." : "Проверка завершилась с ограничениями.";
    if (!historical && source.fresh) {
      const raw = readAnsibleReport(source.reportId)?.raw as { scanner?: { partialReasons?: unknown }; vulnerabilityScan?: { coverage?: { reasons?: unknown } } } | undefined;
      const reasons = raw?.scanner?.partialReasons ?? raw?.vulnerabilityScan?.coverage?.reasons;
      if (Array.isArray(reasons)) reason = reasons.find(value => typeof value === "string" && value.trim())?.slice(0, 600) ?? reason;
    }
    summary.reviewSources.push({ reportId: source.reportId, mode: source.mode, reason });
  }
  for (const finding of correlation?.findings ?? []) {
    summary.total += 1;
    summary[riskBandOf(finding)] += 1;
    if (riskBandOf(finding) === "unknown") {
      const modes = [...new Set(finding.sources.map(source => source.mode))];
      const mode = modes.length === 1 ? modes[0] : "multiple";
      summary.unknownByTool[mode] = (summary.unknownByTool[mode] ?? 0) + 1;
    }
  }
  const reportTimes = new Map(reports.map((report) => [report.id, report.createdAt ?? report.modifiedAt]));
  const expirations = coverage.filter((item) => item.fresh).map((item) => Date.parse(reportTimes.get(item.reportId) ?? "") + summary.maxAgeHours * 3600_000);
  if (cache.size >= 64) cache.delete(cache.keys().next().value!);
  cache.set(hostAlias, { signature, summary, expiresAt: Math.min(Infinity, ...expirations.filter(Number.isFinite)) });
  return summary;
}
