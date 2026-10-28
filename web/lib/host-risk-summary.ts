import { statSync } from "node:fs";
import { buildHostCorrelation, correlationMaxAgeHours, type CorrelatedFinding } from "@/lib/audit-correlation";
import { targetAliasFromReport, reportTimestamp, type AnsibleReportSummary } from "@/lib/ansible-reports";
import { currentAssetBinding } from "@/lib/state-store";
import { explicitInventoryConnectionId } from "@/lib/inventory";

export type HostRiskSummary = {
  critical: number; high: number; medium: number; low: number; unknown: number; info: number;
  total: number; auditCount: number; freshCount: number; partialCount: number; staleCount: number;
  identityExcludedCount?: number;
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
    return [report.id, report.path, report.reportTimeValid, reportTimestamp(report) >= minimumTime, info.dev, info.ino, info.size, info.mtimeMs, info.ctimeMs];
  })]);
  const saved = cache.get(hostAlias);
  if (saved?.signature === signature && Date.now() < saved.expiresAt) return saved.summary;
  const correlation = buildHostCorrelation(hostAlias, reports);
  const coverage = correlation?.coverage.filter((item) => item.auditEvidence) ?? [];
  const summary: HostRiskSummary = {
    critical: 0, high: 0, medium: 0, low: 0, unknown: 0, info: 0, total: 0,
    auditCount: coverage.length, freshCount: coverage.filter((item) => item.fresh && item.available).length,
    partialCount: coverage.filter((item) => item.partial || !item.available).length,
    staleCount: coverage.filter((item) => !item.fresh).length,
    identityExcludedCount: correlation?.coverage.filter((item) => item.coverageIssues.some((issue) => ["asset_identity_changed", "asset_connection_changed", "asset_binding_invalid", "legacy_identity_unknown"].includes(issue))).length ?? 0,
    maxAgeHours: correlation?.maxAgeHours ?? 168, scope: "latest-per-tool-and-profile",
  };
  for (const finding of correlation?.findings ?? []) {
    summary.total += 1;
    summary[riskBandOf(finding)] += 1;
  }
  const reportTimes = new Map(reports.map((report) => [report.id, report.createdAt ?? report.modifiedAt]));
  const expirations = coverage.filter((item) => item.fresh).map((item) => Date.parse(reportTimes.get(item.reportId) ?? "") + summary.maxAgeHours * 3600_000);
  if (cache.size >= 64) cache.delete(cache.keys().next().value!);
  cache.set(hostAlias, { signature, summary, expiresAt: Math.min(Infinity, ...expirations.filter(Number.isFinite)) });
  return summary;
}
