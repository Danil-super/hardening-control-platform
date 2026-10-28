import { listAnsibleReports, readAnsibleReport, targetAliasFromReport, reportTimestamp, reportScopeKey, type AnsibleReportSummary } from "@/lib/ansible-reports";
import type { Finding, FindingSource, RiskLevel } from "@/types";
import { nmapScopeIncludes, type NmapScanScope } from "@/lib/nmap-scope";
import { statSync } from "node:fs";
import { createHash } from "node:crypto";
import { assetEvidenceKey } from "@/lib/asset-binding";
import { currentAssetBinding } from "@/lib/state-store";
import { explicitInventoryConnectionId } from "@/lib/inventory";

export type CorrelationEvidence = {
  source: FindingSource;
  reportId: string;
  mode: string;
  createdAt: string | null;
  findingId: string;
  title: string;
  status: Finding["status"];
  evidence: string;
  partial: boolean;
};

export type CorrelatedFinding = {
  id: string;
  title: string;
  category: string;
  risk: RiskLevel;
  severityUnknown: boolean;
  severityAssessment?: Finding["severityAssessment"];
  status: Finding["status"];
  confidence: "observed" | "manual";
  sources: CorrelationEvidence[];
  description: string;
  recommendation: string;
};

export type CorrelationCoverage = {
  reportId: string;
  mode: string;
  profileId: string | null;
  createdAt: string | null;
  fresh: boolean;
  partial: boolean;
  available: boolean;
  validTime: boolean;
  auditEvidence: boolean;
  scopeKey: string;
  scopeKnown: boolean;
  contentId: string | null;
  scanScope: NmapScanScope | null;
  portCoverage: string | null;
  coverageComplete: boolean | null;
  current: boolean;
  supersededBy: string | null;
  coverageIssues: string[];
};

export type LostCoverage = {
  reportId: string; replacedByReportId: string; profileId: string | null; contentId: string | null;
  scopeKey: string; reason: "scope_changed" | "scope_unknown" | "rules_missing" | "ports_not_checked" | "ports_unverified" | "port_set_unknown"; ruleIds: string[];
  findingIds: string[];
  mode?: string; scanScope?: NmapScanScope | null;
};

function safeHostAlias(value: string) {
  return /^[a-zA-Z0-9_.:-]{1,96}$/.test(value);
}

export function correlationMaxAgeHours() {
  const requested = Number(process.env.HCP_CORRELATION_MAX_AGE_HOURS ?? "168");
  return Number.isFinite(requested) ? Math.min(24 * 90, Math.max(1, Math.floor(requested))) : 168;
}

function reportTime(report: AnsibleReportSummary) {
  return reportTimestamp(report);
}

function reportKey(report: AnsibleReportSummary) {
  const identity = assetEvidenceKey(report.assetBinding);
  return identity === "legacy" ? reportScopeKey(report) : `${identity}:${reportScopeKey(report)}`;
}

function sourceLabel(source: FindingSource) {
  const labels: Record<FindingSource, string> = {
    agentless: "Ansible",
    custom: "Ansible",
    ssh_audit: "ssh-audit",
    nmap: "Nmap",
    lynis: "Lynis",
    openscap: "OpenSCAP",
    trivy: "Trivy",
    greenbone: "Greenbone",
    dependency_track: "Dependency-Track",
  };
  return labels[source];
}

function cveFromFinding(finding: Finding) {
  const content = `${finding.title}\n${finding.evidence ?? ""}\n${finding.description}`;
  return content.match(/\bCVE-\d{4}-\d{4,8}\b/i)?.[0]?.toUpperCase() ?? null;
}

function portFromFinding(finding: Finding) {
  const content = `${finding.title}\n${finding.evidence ?? ""}`;
  const match = content.match(/\b(?:port=)?(tcp|udp)\/(\d{1,5})\b|\b(\d{1,5})\/(tcp|udp)\b/i);
  if (!match) return null;
  const protocol = (match[1] ?? match[4] ?? "").toLowerCase();
  const port = match[2] ?? match[3];
  return protocol && port ? `${protocol}/${port}` : null;
}

function identityForFinding(finding: Finding) {
  const cve = cveFromFinding(finding);
  const port = portFromFinding(finding);
  if (cve) {
    const packageName = finding.evidence?.match(/\bpackage=([^;\s]+)/)?.[1];
    // A CVE in two different packages or network services is not the same
    // finding, and a banner/CVE match is never proof of exploitability.
    const component = packageName ? `package:${packageName}` : port ? `service:${port}` : `${finding.source}:${finding.id}`;
    return { key: `cve:${cve}:${component}`, title: packageName ? `${cve} · ${packageName}` : finding.title, category: "Обнаруженные CVE" };
  }
  if (port) return { key: `network:${port}:${finding.source}:${finding.id}`, title: finding.title, category: "Сетевая поверхность" };
  const rule = finding.evidence?.match(/\brule=([^;\s]+)/)?.[1];
  if (rule) return { key: `rule:${rule}`, title: finding.title, category: finding.category };
  const oid = finding.evidence?.match(/\boid=([^;\s]+)/)?.[1];
  if (oid) return { key: `nvt:${oid}`, title: finding.title, category: finding.category };
  return { key: `${finding.source}:${finding.id}`, title: finding.title, category: finding.category };
}

function maxRisk(findings: Finding[]) {
  const weight: Record<RiskLevel, number> = { high: 3, medium: 2, low: 1, info: 0 };
  return findings.reduce<RiskLevel>((current, finding) => weight[finding.risk] > weight[current] ? finding.risk : current, "info");
}

function statusFor(findings: Finding[]) {
  if (findings.some((finding) => finding.status === "failed")) return "failed" as const;
  if (findings.some((finding) => finding.status === "manual")) return "manual" as const;
  return "passed" as const;
}

type HostCorrelation = {
  hostAlias: string; maxAgeHours: number; findings: CorrelatedFinding[]; coverage: CorrelationCoverage[];
  staleReports: CorrelationCoverage[]; freshReports: CorrelationCoverage[]; partialReports: CorrelationCoverage[];
  lostCoverage: LostCoverage[];
};
const correlationCache = new Map<string, { signature: string; result: HostCorrelation }>();

export function buildHostCorrelation(hostAlias: string, availableReports?: AnsibleReportSummary[]) {
  if (!safeHostAlias(hostAlias)) {
    return null;
  }
  const now = Date.now();
  const ageHours = correlationMaxAgeHours();
  const minimumTime = now - ageHours * 60 * 60 * 1000;
  const allReports = (availableReports ?? listAnsibleReports()).filter((report) => (
    targetAliasFromReport(report) === hostAlias
  ));
  const binding = currentAssetBinding(hostAlias);
  const configuredConnection = explicitInventoryConnectionId(hostAlias) ?? binding?.connectionId;
  const connectionChanged = Boolean(binding && configuredConnection !== binding.connectionId);
  const identityMatches = (report: AnsibleReportSummary) => !report.assetBindingInvalid && (!binding
    ? !report.assetBinding || report.assetBinding.status !== "unknown" || !configuredConnection || report.assetBinding.connectionId === configuredConnection
    : report.assetBinding?.status === "verified" ? !connectionChanged && report.assetBinding.assetId === binding.assetId
      : report.assetBinding?.status === "unknown" && report.assetBinding.aliasGeneration === binding.generation && report.assetBinding.connectionId === configuredConnection);
  const reports = allReports.filter(identityMatches);
  const signature = JSON.stringify([ageHours, binding?.assetId, binding?.generation, configuredConnection, allReports.map((report) => {
    const info = statSync(report.path, { throwIfNoEntry: false });
    return [report.id, report.path, reportKey(report), report.reportTimeValid, report.partial, report.available,
      reportTime(report) >= minimumTime, info?.dev, info?.ino, info?.size, info?.mtimeMs, info?.ctimeMs];
  })]);
  const cached = correlationCache.get(hostAlias);
  if (cached?.signature === signature) return cached.result;
  const latestByKind = new Map<string, AnsibleReportSummary>();
  for (const report of reports) {
    const key = reportKey(report);
    const previous = latestByKind.get(key);
    if (!previous || reportTime(report) > reportTime(previous)) latestByKind.set(key, report);
  }

  // One OpenSCAP policy is assigned to a host at a time. Keep earlier scopes
  // visible as lost coverage, never merge their old failures into a new policy
  // or interpret its passes as verification of a different content/profile.
  const latestOpenScap = reports.filter((report) => report.mode === "openscap" && report.reportTimeValid)
    .sort((a, b) => reportTime(b) - reportTime(a))[0]
    ?? reports.find((report) => report.mode === "openscap");
  const latestNmap = reports.filter((report) => report.mode === "nmap" && report.reportTimeValid)
    .sort((a, b) => reportTime(b) - reportTime(a))[0]
    ?? reports.find((report) => report.mode === "nmap");
  const isCurrent = (report: AnsibleReportSummary) => report.mode === "openscap" ? report.id === latestOpenScap?.id
    : report.mode !== "nmap" || report.id === latestNmap?.id;
  const lostCoverage: LostCoverage[] = [];
  const details = new Map<string, ReturnType<typeof readAnsibleReport>>();
  const detailFor = (report: AnsibleReportSummary) => {
    if (!details.has(report.id)) details.set(report.id, readAnsibleReport(report.id));
    return details.get(report.id);
  };
  const evaluatedRules = (report: AnsibleReportSummary) => new Map((detailFor(report)?.findings ?? [])
    .filter((finding) => ["passed", "failed", "fixed"].includes(finding.status))
    .flatMap((finding) => {
      const rule = finding.evidence?.match(/\brule=([^;\s]+)/)?.[1];
      // The adapter gives each nonempty XCCDF instance a stable finding ID.
      // One evaluated file must not stand in for every instance of its rule.
      const instance = finding.evidence?.match(/(?:^|;\s*)instance=([^;]*)/)?.[1]?.trim();
      return rule ? [[`${rule}\0${instance ? finding.id : ""}`, { rule, findingId: finding.id }] as const] : [];
    }));
  if (latestOpenScap) {
    for (const previous of latestByKind.values()) {
      if (previous.mode !== "openscap" || previous.id === latestOpenScap.id || !previous.reportTimeValid) continue;
      lostCoverage.push({ reportId: previous.id, replacedByReportId: latestOpenScap.id, profileId: previous.profileId,
        contentId: previous.contentId ?? null, scopeKey: reportKey(previous), ruleIds: [], findingIds: [],
        reason: previous.scopeKnown && latestOpenScap.scopeKnown ? "scope_changed" : "scope_unknown" });
    }
    if (latestOpenScap.scopeKnown) {
      const currentRules = evaluatedRules(latestOpenScap);
      for (const previous of reports) {
        if (previous.id === latestOpenScap.id || reportKey(previous) !== reportKey(latestOpenScap)
            || !previous.reportTimeValid || reportTime(previous) < minimumTime) continue;
        const missing = [...evaluatedRules(previous)].filter(([key]) => !currentRules.has(key)).map(([, value]) => value);
        if (missing.length) lostCoverage.push({ reportId: previous.id, replacedByReportId: latestOpenScap.id,
          profileId: previous.profileId, contentId: previous.contentId ?? null, scopeKey: reportKey(previous),
          reason: "rules_missing", ruleIds: [...new Set(missing.map((value) => value.rule))],
          findingIds: missing.map((value) => value.findingId) });
      }
    }
  }

  if (latestNmap) {
    for (const previous of latestByKind.values()) {
      if (previous.mode !== "nmap" || previous.id === latestNmap.id || !previous.reportTimeValid) continue;
      if (latestNmap.available && !latestNmap.partial && nmapScopeIncludes(latestNmap.scanScope, previous.scanScope)) continue;
      lostCoverage.push({ reportId: previous.id, replacedByReportId: latestNmap.id, profileId: previous.profileId,
        mode: "nmap", scanScope: previous.scanScope ?? null, contentId: null, scopeKey: reportKey(previous), ruleIds: [],
        findingIds: (detailFor(previous)?.findings ?? []).filter((finding) => !["passed", "fixed"].includes(finding.status)).map((finding) => finding.id),
        reason: !previous.scopeKnown || !latestNmap.scopeKnown ? "scope_unknown"
          : !latestNmap.available || latestNmap.partial ? "ports_unverified"
            : previous.scanScope === "top_100" && latestNmap.scanScope === "top_1000" ? "port_set_unknown" : "ports_not_checked" });
    }
  }

  const coverage = Array.from(latestByKind.values())
    // A complete full-TCP run covers earlier top-port scans. Do not display a
    // false historical gap for those scopes; all original reports stay saved.
    .filter((report) => report.mode !== "nmap" || isCurrent(report) || lostCoverage.some((loss) => loss.reportId === report.id))
    .map((report) => ({
    reportId: report.id,
    mode: report.mode,
    profileId: report.profileId,
    createdAt: report.createdAt,
    fresh: isCurrent(report) && report.reportTimeValid && reportTime(report) >= minimumTime,
    partial: report.partial || !isCurrent(report) || lostCoverage.some((loss) => loss.replacedByReportId === report.id
      && (loss.reason === "rules_missing" || report.mode === "nmap")),
    available: report.available,
    validTime: report.reportTimeValid,
    auditEvidence: isCurrent(report) && !["facts", "events", "packages", "dependency-track"].includes(report.mode),
    scopeKey: reportKey(report),
    scopeKnown: report.scopeKnown !== false,
    contentId: report.contentId ?? null,
    scanScope: report.scanScope ?? null,
    portCoverage: report.portCoverage ?? null,
    coverageComplete: report.coverageComplete ?? null,
    current: isCurrent(report),
    supersededBy: isCurrent(report) || !report.reportTimeValid ? null : (report.mode === "nmap" ? latestNmap?.id : latestOpenScap?.id) ?? null,
    coverageIssues: [
      ...(report.assetBinding?.status === "unknown" ? ["asset_identity_unverified"] : []),
      ...(!isCurrent(report) ? [report.reportTimeValid ? "scope_superseded" : "invalid_time"] : []),
      ...(report.scopeKnown === false ? ["scope_unknown"] : []),
      ...(lostCoverage.some((loss) => loss.replacedByReportId === report.id) ? ["previous_coverage_not_verified"] : []),
    ],
  }));
  // Keep excluded historical evidence visible without treating a former
  // machine (or an unbound legacy report) as the current asset's assessment.
  const excluded = new Map<string, AnsibleReportSummary>();
  for (const report of allReports.filter((item) => !identityMatches(item))) {
    const key = reportKey(report);
    if (!excluded.has(key) || reportTime(report) > reportTime(excluded.get(key)!)) excluded.set(key, report);
  }
  for (const report of excluded.values()) coverage.push({ reportId: report.id, mode: report.mode, profileId: report.profileId, createdAt: report.createdAt,
    fresh: false, partial: true, available: report.available, validTime: report.reportTimeValid, auditEvidence: false, scopeKey: reportKey(report),
    scopeKnown: report.scopeKnown !== false, contentId: report.contentId ?? null, scanScope: report.scanScope ?? null, portCoverage: report.portCoverage ?? null,
    coverageComplete: report.coverageComplete ?? null, current: false, supersededBy: null,
    coverageIssues: [report.assetBindingInvalid ? "asset_binding_invalid" : !report.assetBinding ? "legacy_identity_unknown"
      : connectionChanged ? "asset_connection_changed" : "asset_identity_changed"] });
  const grouped = new Map<string, { identity: ReturnType<typeof identityForFinding>; findings: Finding[]; sources: CorrelationEvidence[] }>();
  for (const report of latestByKind.values()) {
    if (!isCurrent(report) || !report.reportTimeValid || reportTime(report) < minimumTime || ["facts", "events", "packages", "dependency-track"].includes(report.mode)) continue;
    const detail = detailFor(report);
    if (!detail) continue;
    for (const finding of detail.findings) {
      if (finding.status === "passed" || finding.status === "fixed") continue;
      const identity = identityForFinding(finding);
      if (report.assetBinding) identity.key = `asset_finding_${createHash("sha256").update(`${assetEvidenceKey(report.assetBinding)}\0${identity.key}`).digest("hex")}`;
      const group = grouped.get(identity.key) ?? { identity, findings: [], sources: [] };
      group.findings.push(finding);
      group.sources.push({
        source: finding.source,
        reportId: report.id,
        mode: report.mode,
        createdAt: report.createdAt,
        findingId: finding.id,
        title: finding.title,
        status: finding.status,
        evidence: finding.evidence ?? "Нет дополнительного технического доказательства.",
        partial: coverage.find((item) => item.reportId === report.id)?.partial ?? report.partial,
      });
      grouped.set(identity.key, group);
    }
  }

  const findings = Array.from(grouped, ([key, group]): CorrelatedFinding => {
    const sources = group.sources.sort((left, right) => sourceLabel(left.source).localeCompare(sourceLabel(right.source), "ru"));
    const independentSources = new Set(sources.map((item) => item.source));
    const status = statusFor(group.findings);
    const confidence = status === "manual" || sources.some((source) => source.partial)
      ? "manual"
      : "observed";
    const sourceText = Array.from(independentSources).map(sourceLabel).join(", ");
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    const severityAssessment = group.findings.flatMap((finding) => finding.severityAssessment ? [finding.severityAssessment] : [])
      .sort((a, b) => severityOrder[b.level] - severityOrder[a.level])[0];
    return {
      id: key.replace(/[^a-zA-Z0-9_.:-]+/g, "_").slice(0, 160),
      title: group.identity.title,
      category: group.identity.category,
      risk: maxRisk(group.findings),
      severityUnknown: maxRisk(group.findings) === "info" && group.findings.some((finding) => finding.severityUnknown),
      severityAssessment,
      status,
      confidence,
      sources,
      description: group.findings.every((finding) => finding.source === "lynis") ? Array.from(new Set(group.findings.map((finding) => finding.description))).join("\n") : confidence === "manual"
          ? `Есть неполное или требующее ручной оценки доказательство из: ${sourceText}.`
          : `Признаки обнаружены: ${sourceText}. Совпадение идентификаторов не подтверждает применимость уязвимости; проверьте компонент, его версию и данные поставщика ОС.`,
      recommendation: group.findings[0]?.recommendation ?? "Проверьте техническое доказательство и назначьте владельца исправления.",
    };
  }).sort((left, right) => {
    const riskOrder: Record<RiskLevel, number> = { high: 3, medium: 2, low: 1, info: 0 };
    return riskOrder[right.risk] - riskOrder[left.risk]
      || Number(right.severityAssessment?.level === "critical") - Number(left.severityAssessment?.level === "critical")
      || right.sources.length - left.sources.length || left.title.localeCompare(right.title, "ru");
  });

  const result: HostCorrelation = {
    hostAlias,
    maxAgeHours: ageHours,
    findings,
    coverage,
    lostCoverage,
    staleReports: coverage.filter((item) => item.current && !item.fresh),
    freshReports: coverage.filter((item) => item.fresh && item.auditEvidence),
    partialReports: coverage.filter((item) => (item.auditEvidence || !item.current) && (item.partial || !item.fresh)),
  };
  const size = findings.reduce((total, finding) => total + finding.title.length + finding.description.length + finding.recommendation.length
    + finding.sources.reduce((sourceTotal, source) => sourceTotal + source.evidence.length, 0), 0);
  if (size <= 24 * 1024 * 1024) {
    if (correlationCache.size >= 2) correlationCache.delete(correlationCache.keys().next().value!);
    correlationCache.set(hostAlias, { signature, result });
  }
  return result;
}
