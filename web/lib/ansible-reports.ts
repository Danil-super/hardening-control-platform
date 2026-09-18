import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
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

export type AnsibleReportDependent = {
  id: string;
  mode: string;
  reason: "package_inventory" | "cve_report";
};

export type DeletedAnsibleReport = {
  id: string;
  hostAlias: string;
  mode: string;
  sbomRemoved: boolean;
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
    "astra-oval": "astra-oval",
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
    && (item.severityUnknown === undefined || typeof item.severityUnknown === "boolean")
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

function record(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function sbomFileFromReport(report: Pick<AnsibleReportDetail, "mode" | "raw">) {
  if (report.mode !== "vulnerabilities") return null;
  const candidate = record(record(report.raw).vulnerabilityScan).sbomFile;
  return typeof candidate === "string" && /^[A-Za-z0-9_.:-]{1,180}$/.test(candidate) ? candidate : null;
}

/**
 * Reports may form a short evidence chain: package inventory -> CVE scan ->
 * optional Dependency-Track delivery.  A source report cannot disappear while
 * a saved later report still points to it.
 */
export function listAnsibleReportDependents(reportId: string): AnsibleReportDependent[] {
  if (!fileNameFromReportId(reportId)) return [];
  const dependents: AnsibleReportDependent[] = [];
  for (const summary of listAnsibleReports()) {
    const report = readAnsibleReport(summary.id);
    if (!report) continue;
    const raw = record(report.raw);
    const vulnerabilityScan = record(raw.vulnerabilityScan);
    if (vulnerabilityScan.sourcePackageReportId === reportId) {
      dependents.push({ id: report.id, mode: report.mode, reason: "package_inventory" });
      continue;
    }
    const scanner = record(raw.scanner);
    if (scanner.sourceCveReport === reportId) {
      dependents.push({ id: report.id, mode: report.mode, reason: "cve_report" });
    }
  }
  return dependents;
}

function stateDirectoryForReports() {
  const repoRoot = getRepoRoot();
  return process.env.HCP_STATE_DIR ? path.resolve(process.env.HCP_STATE_DIR) : path.join(repoRoot, "ansible");
}

/**
 * Removes a standalone raw audit result. Callers must check persisted plan and
 * remediation references first. The immutable action journal is deliberately
 * not removed. A CycloneDX SBOM is removed only when no other report uses it.
 */
export function deleteAnsibleReport(reportId: string): DeletedAnsibleReport | null {
  const report = readAnsibleReport(reportId);
  if (!report) return null;
  const fileName = fileNameFromReportId(reportId);
  if (!fileName) return null;

  const reportsDir = getReportsDir();
  const reportPath = path.join(reportsDir, fileName);
  if (!reportPath.startsWith(reportsDir + path.sep)) return null;
  const reportInfo = lstatSync(reportPath, { throwIfNoEntry: false });
  if (!reportInfo || !reportInfo.isFile() || reportInfo.isSymbolicLink()) {
    throw new Error("Файл отчёта недоступен или имеет недопустимый тип.");
  }

  const sbomFile = sbomFileFromReport(report);
  const sbomDir = path.join(stateDirectoryForReports(), "sbom");
  const sbomPath = sbomFile ? path.join(sbomDir, sbomFile) : null;
  if (sbomPath && !sbomPath.startsWith(sbomDir + path.sep)) {
    throw new Error("Путь CycloneDX SBOM недопустим.");
  }
  const sbomInfo = sbomPath ? lstatSync(sbomPath, { throwIfNoEntry: false }) : null;
  if (sbomInfo && (!sbomInfo.isFile() || sbomInfo.isSymbolicLink())) {
    throw new Error("Файл CycloneDX SBOM недоступен или имеет недопустимый тип.");
  }
  const sbomUsedElsewhere = sbomFile
    ? listAnsibleReports().some((candidate) => {
      if (candidate.id === report.id) return false;
      const detail = readAnsibleReport(candidate.id);
      return detail ? sbomFileFromReport(detail) === sbomFile : false;
    })
    : false;

  rmSync(reportPath, { force: false });
  if (sbomPath && sbomInfo && !sbomUsedElsewhere) {
    rmSync(sbomPath, { force: false });
  }

  return {
    id: report.id,
    hostAlias: targetAliasFromReport(report),
    mode: report.mode,
    sbomRemoved: Boolean(sbomPath && sbomInfo && !sbomUsedElsewhere),
  };
}

/** SHA-256 of the exact JSON file referenced by an audit decision/export. */
export function hashAnsibleReport(reportId: string) {
  const fileName = fileNameFromReportId(reportId);
  if (!fileName) return null;
  const reportsDir = getReportsDir();
  const reportPath = path.join(reportsDir, fileName);
  if (!reportPath.startsWith(reportsDir + path.sep) || !existsSync(reportPath)) return null;
  try {
    const data = readFileSync(reportPath);
    return createHash("sha256").update(data).digest("hex");
  } catch {
    return null;
  }
}
