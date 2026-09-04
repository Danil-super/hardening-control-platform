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
  };
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
    return reportId.replace(new RegExp(`-${kind}(?:-[a-zA-Z0-9_.:-]+)?$`, "i"), "");
  }
  if (profileId) {
    return reportId.replace(new RegExp(`-${escapeRegExp(profileId)}(?:-[a-zA-Z0-9_.:-]+)?$`, "i"), "");
  }
  return reportId;
}

function numberOrZero(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function numberOrNull(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function scoreFromReport(parsed: ReportJson, mode: string) {
  const summaryScore = numberOrNull(parsed.summary?.score);
  if (summaryScore !== null) {
    return summaryScore;
  }
  // Reports written before the Lynis score normalization still contain the
  // original value in scanner.hardeningIndex.  Keep report history useful
  // without requiring users to rerun those audits.
  return mode === "lynis" ? numberOrNull(parsed.scanner?.hardeningIndex) : null;
}

function readReportJson(reportPath: string): ReportJson | null {
  try {
    return JSON.parse(readFileSync(reportPath, "utf8")) as ReportJson;
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
  const summary = parsed.summary ?? {};
  const findings = Array.isArray(parsed.findings) ? parsed.findings : [];
  const events = Array.isArray(parsed.events) ? parsed.events : [];

  return {
    id: reportIdFromFileName(fileName),
    fileName,
    path: fullPath,
    createdAt: parsed.createdAt ?? null,
    modifiedAt: stats.mtime.toISOString(),
    host: parsed.hostname ?? targetAliasFromReportFileName(fileName, profileId, mode),
    profileId,
    mode,
    score: scoreFromReport(parsed, mode),
    high: numberOrZero(summary.high),
    medium: numberOrZero(summary.medium),
    low: numberOrZero(summary.low),
    info: numberOrZero(summary.info),
    findingsCount: findings.length,
    eventsCount: events.length || numberOrZero(summary.total),
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
      return buildReportSummary(fileName, fullPath);
    })
    .filter((report): report is AnsibleReportSummary => Boolean(report))
    .sort((left, right) => {
      const leftTime = Date.parse(left.createdAt ?? left.modifiedAt);
      const rightTime = Date.parse(right.createdAt ?? right.modifiedAt);
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
    findings: Array.isArray(parsed.findings) ? parsed.findings : [],
    events: Array.isArray(parsed.events) ? parsed.events : [],
    raw: parsed,
  };
}
