import { listAnsibleReports, readAnsibleReport, targetAliasFromReportFileName, type AnsibleReportSummary } from "@/lib/ansible-reports";
import type { Finding, FindingSource, RiskLevel } from "@/types";

export type CorrelationEvidence = {
  source: FindingSource;
  reportId: string;
  mode: string;
  createdAt: string | null;
  findingId: string;
  title: string;
  status: Finding["status"];
  evidence: string;
};

export type CorrelatedFinding = {
  id: string;
  title: string;
  category: string;
  risk: RiskLevel;
  status: Finding["status"];
  confidence: "confirmed" | "observed" | "manual";
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
};

function safeHostAlias(value: string) {
  return /^[a-zA-Z0-9_.:-]{1,96}$/.test(value);
}

function maxAgeHours() {
  const requested = Number(process.env.HCP_CORRELATION_MAX_AGE_HOURS ?? "168");
  return Number.isFinite(requested) ? Math.min(24 * 90, Math.max(1, Math.floor(requested))) : 168;
}

function reportTime(report: AnsibleReportSummary) {
  const timestamp = Date.parse(report.createdAt ?? report.modifiedAt);
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

function reportKey(report: AnsibleReportSummary) {
  return `${report.mode}:${report.profileId ?? "default"}`;
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
  if (cve) return { key: `cve:${cve}`, title: cve, category: "Подтверждённые CVE" };
  const port = portFromFinding(finding);
  if (port) return { key: `network:${port}`, title: `Сетевой сервис ${port}`, category: "Сетевая поверхность" };
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

export function buildHostCorrelation(hostAlias: string) {
  if (!safeHostAlias(hostAlias)) {
    return null;
  }
  const now = Date.now();
  const ageHours = maxAgeHours();
  const minimumTime = now - ageHours * 60 * 60 * 1000;
  const reports = listAnsibleReports().filter((report) => (
    targetAliasFromReportFileName(report.fileName, report.profileId, report.mode) === hostAlias
  ));
  const latestByKind = new Map<string, AnsibleReportSummary>();
  for (const report of reports) {
    const key = reportKey(report);
    if (!latestByKind.has(key)) latestByKind.set(key, report);
  }

  const coverage = Array.from(latestByKind.values()).map((report) => ({
    reportId: report.id,
    mode: report.mode,
    profileId: report.profileId,
    createdAt: report.createdAt,
    fresh: reportTime(report) >= minimumTime,
  }));
  const grouped = new Map<string, { identity: ReturnType<typeof identityForFinding>; findings: Finding[]; sources: CorrelationEvidence[] }>();
  for (const report of latestByKind.values()) {
    if (reportTime(report) < minimumTime) continue;
    const detail = readAnsibleReport(report.id);
    if (!detail) continue;
    for (const finding of detail.findings) {
      if (finding.status === "passed" || finding.status === "fixed") continue;
      const identity = identityForFinding(finding);
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
      });
      grouped.set(identity.key, group);
    }
  }

  const findings = Array.from(grouped, ([key, group]): CorrelatedFinding => {
    const sources = group.sources.sort((left, right) => sourceLabel(left.source).localeCompare(sourceLabel(right.source), "ru"));
    const independentSources = new Set(sources.map((item) => item.source));
    const status = statusFor(group.findings);
    const confidence = status === "manual"
      ? "manual"
      : independentSources.size > 1 ? "confirmed" : "observed";
    const sourceText = Array.from(independentSources).map(sourceLabel).join(", ");
    return {
      id: key.replace(/[^a-zA-Z0-9_.:-]+/g, "_").slice(0, 160),
      title: group.identity.title,
      category: group.identity.category,
      risk: maxRisk(group.findings),
      status,
      confidence,
      sources,
      description: confidence === "confirmed"
        ? `Проблема подтверждена независимыми источниками: ${sourceText}.`
        : confidence === "manual"
          ? `Есть неполное или требующее ручной оценки доказательство из: ${sourceText}.`
          : `Проблема обнаружена источником: ${sourceText}. Для повышения уверенности сопоставьте её с ролью хоста и данными поставщика ОС.`,
      recommendation: group.findings[0]?.recommendation ?? "Проверьте техническое доказательство и назначьте владельца исправления.",
    };
  }).sort((left, right) => {
    const riskOrder: Record<RiskLevel, number> = { high: 3, medium: 2, low: 1, info: 0 };
    return riskOrder[right.risk] - riskOrder[left.risk] || right.sources.length - left.sources.length || left.title.localeCompare(right.title, "ru");
  });

  return {
    hostAlias,
    maxAgeHours: ageHours,
    findings,
    coverage,
    staleReports: coverage.filter((item) => !item.fresh),
    freshReports: coverage.filter((item) => item.fresh),
  };
}
