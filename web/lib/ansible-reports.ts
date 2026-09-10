import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import type { Finding } from "@/types";

export type AnsibleReportSummary = {
  id: string;
  fileName: string;
  path: string;
  createdAt: string | null;
  modifiedAt: string;
  host: string;
  inventoryHost: string | null;
  partial: boolean;
  needsReview: boolean;
  available: boolean;
  reportTimeValid: boolean;
  profileId: string | null;
  mode: string;
  score: number | null;
  high: number;
  medium: number;
  low: number;
  info: number;
  findingsCount: number;
  eventsCount: number;
};

export type AnsibleReportDetail = AnsibleReportSummary & {
  hostname: string | null;
  os: string | null;
  findings: Finding[];
  events: Array<{
    source?: string;
    message?: string;
  }>;
  raw: unknown;
};

type ReportJson = {
  inventoryHost?: string;
  createdAt?: string;
  hostname?: string;
  os?: string;
  profileId?: string;
  mode?: string;
  summary?: Partial<Record<"score" | "high" | "medium" | "low" | "info" | "total", number>> & {
    severity?: string;
  };
  scanner?: {
    hardeningIndex?: unknown;
    partial?: boolean;
    available?: boolean;
    error?: unknown;
  };
  vulnerabilityScan?: { partial?: boolean };
  packageInventory?: { error?: string };
  partial?: boolean;
  findings?: Finding[];
  events?: Array<{
    source?: string;
    message?: string;
  }>;
};

export function getRepoRoot() {
  return path.resolve(process.cwd(), "..");
}

export function getReportsDir(repoRoot = getRepoRoot()) {
  return process.env.HCP_REPORTS_DIR ? path.resolve(process.env.HCP_REPORTS_DIR) : path.join(repoRoot, "ansible", "reports");
}

export function reportIdFromFileName(fileName: string) {
  return fileName.replace(/\.json$/i, "");
}

export function fileNameFromReportId(reportId: string) {
  if (!/^[a-zA-Z0-9_.:-]+$/.test(reportId)) {
    return null;
  }
  return reportId.endsWith(".json") ? reportId : `${reportId}.json`;
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Report files are named `<inventory-alias>-<type>-<run-id>.json`.
 * The optional run-id keeps reports generated before report history was added
 * compatible with the current UI.
 */
export function targetAliasFromReportFileName(fileName: string, profileId: string | null, mode: string) {
  const reportId = reportIdFromFileName(fileName);
  const reportKinds: Record<string, string> = {
    facts: "facts",
    events: "events",
    packages: "packages",
    vulnerabilities: "vulnerabilities",
    "ssh-audit": "ssh-audit",
    nmap: "nmap",
    lynis: "lynis",
    openscap: "openscap",
    greenbone: "greenbone",
    "dependency-track": "dependency-track",
  };
  const kind = reportKinds[mode];
  if (kind) {
    return reportId.replace(new RegExp(`^(.*)-${kind}(?:-(?:run|schedule)-[a-zA-Z0-9_.:-]+)?$`, "i"), "$1");
  }
  if (profileId) {
    return reportId.replace(new RegExp(`^(.*)-${escapeRegExp(profileId)}(?:-(?:run|schedule)-[a-zA-Z0-9_.:-]+)?$`, "i"), "$1");
  }
  return reportId;
}

export function targetAliasFromReport(report: Pick<AnsibleReportSummary, "inventoryHost" | "fileName" | "profileId" | "mode">) {
  return report.inventoryHost ?? targetAliasFromReportFileName(report.fileName, report.profileId, report.mode);
}

export function reportTimestamp(report: Pick<AnsibleReportSummary, "createdAt" | "modifiedAt">, now = Date.now()) {
  const timestamp = Date.parse(report.createdAt ?? report.modifiedAt);
  // Invalid or future dates may remain in history, but never outrank a real run.
  return Number.isFinite(timestamp) && timestamp <= now ? timestamp : 0;
}

function numberOrNull(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100 ? value : null;
}

function scoreFromReport(parsed: ReportJson, mode: string) {
  // Only these checks define a configuration score. Historical CVE scores
  // were derived from finding counts and must not be presented as protection.
  if (mode !== "agentless" && mode !== "lynis") return null;
  const summaryScore = numberOrNull(parsed.summary?.score);
  if (summaryScore !== null) {
    return summaryScore;
  }
  // Reports written before the Lynis score normalization still contain the
  // original value in scanner.hardeningIndex.  Keep report history useful
  // without requiring users to rerun those audits.
  return mode === "lynis" ? numberOrNull(parsed.scanner?.hardeningIndex) : null;
}

function isFinding(value: unknown): value is Finding {
  if (!value || typeof value !== "object") return false;
  const item = value as Record<string, unknown>;
  return ["id", "title", "description", "recommendation", "category", "profileId"].every((key) => typeof item[key] === "string")
    && ["high", "medium", "low", "info"].includes(String(item.risk))
    && ["failed", "passed", "manual", "fixed"].includes(String(item.status))
    && ["agentless", "custom", "ssh_audit", "nmap", "lynis", "openscap", "trivy", "greenbone", "dependency_track"].includes(String(item.source))
    && (item.evidence === undefined || typeof item.evidence === "string");
}

function readReportJson(reportPath: string): ReportJson | null {
  try {
    const value = JSON.parse(readFileSync(reportPath, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    if (["createdAt", "hostname", "os", "profileId", "mode", "inventoryHost"].some((key) => value[key] != null && typeof value[key] !== "string")) return null;
    if (value.inventoryHost != null && !/^[a-zA-Z0-9_.:-]{1,96}$/.test(value.inventoryHost)) return null;
    return value as ReportJson;
  } catch {
    return null;
  }
}

function buildReportSummary(fileName: string, fullPath: string): AnsibleReportSummary | null {
  const parsed = readReportJson(fullPath);
  if (!parsed) {
    return null;
  }

  const stats = statSync(fullPath);
  const mode = parsed.mode ?? "agentless";
  const profileId = parsed.profileId ?? null;
  const findings = Array.isArray(parsed.findings) ? parsed.findings.filter(isFinding) : [];
  const events = Array.isArray(parsed.events) ? parsed.events : [];
  const createdAt = typeof parsed.createdAt === "string" ? parsed.createdAt : null;
  const inventoryHost = typeof parsed.inventoryHost === "string" && /^[a-zA-Z0-9_.:-]{1,96}$/.test(parsed.inventoryHost)
    ? parsed.inventoryHost : null;
  const available = parsed.scanner?.available !== false;
  const partial = !available || parsed.partial === true || parsed.scanner?.partial === true || Boolean(parsed.scanner?.error)
    || parsed.vulnerabilityScan?.partial === true || Boolean(parsed.packageInventory?.error)
    || (parsed.findings !== undefined && (!Array.isArray(parsed.findings) || findings.length !== parsed.findings.length))
    || mode === "dependency-track";
  const needsReview = findings.some((finding) => finding.status === "manual");
  const reportTimeValid = reportTimestamp({ createdAt, modifiedAt: stats.mtime.toISOString() }) > 0;

  return {
    id: reportIdFromFileName(fileName),
    fileName,
    path: fullPath,
    createdAt,
    modifiedAt: stats.mtime.toISOString(),
    host: parsed.hostname ?? targetAliasFromReportFileName(fileName, profileId, mode),
    inventoryHost,
    available,
    partial,
    needsReview,
    reportTimeValid,
    profileId,
    mode,
    score: partial || !reportTimeValid ? null : scoreFromReport(parsed, mode),
    high: findings.filter((finding) => finding.status === "failed" && finding.risk === "high").length,
    medium: findings.filter((finding) => finding.status === "failed" && finding.risk === "medium").length,
    low: findings.filter((finding) => finding.status === "failed" && finding.risk === "low").length,
    info: findings.filter((finding) => finding.risk === "info").length,
    findingsCount: findings.length,
    eventsCount: events.length,
  };
}

export function listAnsibleReports() {
  const reportsDir = getReportsDir();
  if (!existsSync(reportsDir)) {
    return [];
  }

  return readdirSync(reportsDir)
    .filter((fileName) => fileName.endsWith(".json"))
    .map((fileName) => {
      const fullPath = path.join(reportsDir, fileName);
      try { return buildReportSummary(fileName, fullPath); } catch { return null; }
    })
    .filter((report): report is AnsibleReportSummary => Boolean(report))
    .sort((left, right) => {
      const leftTime = reportTimestamp(left);
      const rightTime = reportTimestamp(right);
      return rightTime - leftTime;
    });
}

export function readAnsibleReport(reportId: string): AnsibleReportDetail | null {
  const fileName = fileNameFromReportId(reportId);
  if (!fileName) {
    return null;
  }

  const reportsDir = getReportsDir();
  const reportPath = path.join(reportsDir, fileName);
  if (!reportPath.startsWith(reportsDir + path.sep) || !existsSync(reportPath)) {
    return null;
  }

  const parsed = readReportJson(reportPath);
  const summary = buildReportSummary(fileName, reportPath);
  if (!parsed || !summary) {
    return null;
  }

  return {
    ...summary,
    hostname: parsed.hostname ?? null,
    os: parsed.os ?? null,
    findings: Array.isArray(parsed.findings) ? parsed.findings.filter(isFinding) : [],
    events: Array.isArray(parsed.events) ? parsed.events : [],
    raw: parsed,
  };
}
