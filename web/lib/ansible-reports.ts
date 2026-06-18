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
  return path.join(repoRoot, "ansible", "reports");
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

function hostFromFileName(fileName: string, profileId: string | null, mode: string) {
  if (mode === "events") {
    return fileName.replace(/-events\.json$/i, "");
  }
  if (profileId && fileName.endsWith(`-${profileId}.json`)) {
    return fileName.slice(0, -`-${profileId}.json`.length);
  }
  return reportIdFromFileName(fileName);
}

function numberOrZero(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function numberOrNull(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
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
    host: parsed.hostname ?? hostFromFileName(fileName, profileId, mode),
    profileId,
    mode,
    score: numberOrNull(summary.score),
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
