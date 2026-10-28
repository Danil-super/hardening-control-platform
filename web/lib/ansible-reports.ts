import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import type { Finding } from "@/types";
import { getArchivedRecordIds, type ArchiveView } from "@/lib/state-store";
import { normalizeLynisFindings } from "@/lib/lynis-findings";
import { normalizeNmapScope, nmapPortCoverage, type NmapScanScope } from "@/lib/nmap-scope";
import { parseAssetBinding, sameAssetEvidence, type AssetBinding } from "@/lib/asset-binding";

export type AnsibleReportSummary = {
  id: string;
  fileName: string;
  path: string;
  createdAt: string | null;
  observedAt?: string | null;
  importedAt?: string | null;
  modifiedAt: string;
  host: string;
  inventoryHost: string | null;
  assetBinding?: AssetBinding | null;
  assetBindingInvalid?: boolean;
  partial: boolean;
  needsReview: boolean;
  available: boolean;
  reportTimeValid: boolean;
  profileId: string | null;
  contentId?: string | null;
  scopeKey?: string;
  scopeKnown?: boolean;
  scanScope?: NmapScanScope | null;
  portCoverage?: string | null;
  coverageComplete?: boolean | null;
  mode: string;
  score: number | null;
  high: number;
  critical: number;
  unknown: number;
  medium: number;
  low: number;
  info: number;
  findingsCount: number;
  eventsCount: number;
  lynisWarnings?: number;
  lynisSuggestions?: number;
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
  reason: "package_inventory" | "cve_report" | "dependency_track_delivery";
};

export type DeletedAnsibleReport = {
  id: string;
  hostAlias: string;
  mode: string;
  sbomRemoved: boolean;
};

type ReportJson = {
  assetBinding?: unknown;
  inventoryHost?: string;
  createdAt?: string;
  observedAt?: string | null;
  importedAt?: string | null;
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
    definitionResults?: unknown;
    profile?: unknown;
    contentIdentity?: unknown;
    datastreamChecksum?: unknown;
    scanStartedAt?: unknown;
    scanEndedAt?: unknown;
    observationTimeValid?: unknown;
    scanScope?: unknown;
    portCoverage?: unknown;
    coverageComplete?: unknown;
    database?: { sha256?: unknown };
  };
  vulnerabilityScan?: { partial?: boolean };
  packageInventory?: { error?: string; partial?: boolean; partialReasons?: string[] };
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
    "dependency-track-analysis": "dependency-track-analysis",
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

export function reportTimestamp(report: Pick<AnsibleReportSummary, "createdAt" | "modifiedAt" | "observedAt">, now = Date.now()) {
  // An explicitly unknown observation time must never fall back to import or mtime.
  const timestamp = Date.parse(report.observedAt !== undefined ? report.observedAt ?? "" : report.createdAt ?? report.modifiedAt);
  // Invalid or future dates may remain in history, but never outrank a real run.
  return Number.isFinite(timestamp) && timestamp <= now ? timestamp : 0;
}

/** Content changes or different XCCDF profiles cannot verify each other. Unknown
 * legacy scopes remain individually identifiable but are never compatible. */
export function reportScopeKey(report: Pick<AnsibleReportSummary, "mode" | "profileId" | "id" | "contentId" | "scanScope">) {
  if (report.mode === "nmap") return report.scanScope ? `nmap:${report.scanScope}` : `nmap:unknown:${report.id}`;
  if (report.mode !== "openscap") return `${report.mode}:${report.profileId ?? "default"}`;
  return report.profileId && report.profileId !== "openscap" && report.contentId
    ? `openscap:${encodeURIComponent(report.profileId)}:${report.contentId}`
    : `openscap:unknown:${report.id}`;
}

export function reportScopesCompatible(left: AnsibleReportSummary, right: AnsibleReportSummary) {
  if (left.assetBindingInvalid || right.assetBindingInvalid || !sameAssetEvidence(left.assetBinding, right.assetBinding)) return false;
  return left.mode === right.mode && (!["openscap", "nmap"].includes(left.mode) || left.scopeKnown === true && right.scopeKnown === true)
    && (left.mode !== "astra-oval" || Boolean(left.contentId) && left.contentId === right.contentId)
    && reportScopeKey(left) === reportScopeKey(right);
}

function importedScanTime(value: unknown) {
  if (typeof value !== "string") return null;
  const parts = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/);
  if (!parts) return null;
  const [, year, month, day, hour, minute, second] = parts.map(Number);
  if (month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate()
      || hour > 23 || minute > 59 || second > 59) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function greenboneObservation(parsed: ReportJson) {
  const importedAt = parsed.importedAt ?? parsed.createdAt ?? null;
  const imported = importedScanTime(importedAt);
  const end = importedScanTime(parsed.scanner?.scanEndedAt ?? parsed.observedAt);
  const start = importedScanTime(parsed.scanner?.scanStartedAt);
  const declaredEnd = parsed.observedAt === undefined ? end : importedScanTime(parsed.observedAt);
  const valid = parsed.scanner?.observationTimeValid !== false && end !== null && end > 0
    && end <= Math.min(Date.now(), imported ?? Date.now()) && declaredEnd === end
    && (!parsed.scanner?.scanStartedAt || start !== null && start <= end);
  return { observedAt: valid ? new Date(end!).toISOString() : null, importedAt };
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
    && (item.severityAssessment === undefined || (item.severityAssessment !== null && typeof item.severityAssessment === "object"
      && ["critical", "high", "medium", "low"].includes(String((item.severityAssessment as Record<string, unknown>).level))
      && ["oval_metadata", "chromium_description", "scanner_metadata"].includes(String((item.severityAssessment as Record<string, unknown>).source))))
    && ["failed", "passed", "manual", "fixed"].includes(String(item.status))
    && ["agentless", "custom", "ssh_audit", "nmap", "lynis", "openscap", "trivy", "greenbone", "dependency_track"].includes(String(item.source))
    && (item.evidence === undefined || typeof item.evidence === "string");
}

/** Interpret explicit vendor labels only; never infer CVSS from prose. Historical
 * source JSON stays intact, including its digest and original classification. */
export function normalizeOvalFinding(finding: Finding, vendorMetadata?: { vendorSeverity?: unknown }): Finding {
  if (finding.profileId !== "astra-oval" || finding.source !== "openscap" || finding.status !== "failed") return finding;
  let metadata: unknown = vendorMetadata?.vendorSeverity;
  if (!vendorMetadata) {
    try { metadata = JSON.parse(finding.evidence ?? "{}").vendorSeverity; } catch {
      // Current adapters retain an explicit assessment even when criteria make
      // the evidence excerpt too long to remain valid JSON.
      if (finding.severityAssessment?.source === "oval_metadata") metadata = finding.severityAssessment.level;
    }
  }
  const levels: Record<string, "critical" | "high" | "medium" | "low"> = { critical: "critical", high: "high", important: "high", medium: "medium", moderate: "medium", low: "low" };
  let level = typeof metadata === "string" ? levels[metadata.trim().toLowerCase()] : undefined;
  let source: "oval_metadata" | "chromium_description" = "oval_metadata";
  // Chromium's own explicit label is not an Astra/CVSS assessment. Require the
  // component and exact named field, and reject conflicting labels.
  if (!metadata && /\b(?:chromium|chrome)\b/i.test(finding.title)) {
    const matches = Array.from(finding.description.matchAll(/\(Chromium security severity:\s*(Critical|High|Medium|Low)\)/gi), (match) => match[1].toLowerCase());
    const unique = new Set(matches);
    if (unique.size === 1) { level = levels[matches[0]]; source = "chromium_description"; }
  }
  if (!level) return { ...finding, risk: "info", severityUnknown: true, severityAssessment: undefined };
  return { ...finding, risk: level === "critical" ? "high" : level, severityUnknown: false, severityAssessment: { level, source } };
}

function reportFindings(parsed: ReportJson) {
  const metadata = new Map<string, { vendorSeverity?: unknown }>();
  if (parsed.mode === "astra-oval" && Array.isArray(parsed.scanner?.definitionResults)) {
    for (const definition of parsed.scanner.definitionResults) {
      if (definition && typeof definition === "object" && typeof definition.id === "string") metadata.set(definition.id, definition);
    }
  }
  return Array.isArray(parsed.findings) ? normalizeLynisFindings(parsed.findings.filter(isFinding)).map((finding) => {
    const normalized = normalizeOvalFinding(finding, metadata.get(finding.id));
    // Older Trivy/XCCDF adapters kept Critical in their structured evidence but
    // folded it into the high-priority band. Recover the explicit scanner label
    // without interpreting arbitrary prose or unversioned numerical scores.
    if (normalized.status === "failed" && normalized.risk === "high" && !normalized.severityUnknown && !normalized.severityAssessment
        && (normalized.source === "trivy" || (normalized.source === "openscap" && normalized.profileId !== "astra-oval"))
        && /(?:^|;\s*)severity=critical(?:;|$)/i.test(normalized.evidence ?? "")) {
      return { ...normalized, severityAssessment: { level: "critical" as const, source: "scanner_metadata" as const } };
    }
    if (normalized.source === "trivy" && normalized.status === "failed" && normalized.risk === "info"
        && (/(?:^|;\s*)severity=unknown(?:;|$)/i.test(normalized.evidence ?? "")
          || (!/(?:^|;\s*)severity=/i.test(normalized.evidence ?? "") && /\bCVE-\d{4}-\d{4,}\b/.test(normalized.title)))) {
      return { ...normalized, severityUnknown: true };
    }
    return normalized;
  }) : [];
}

function readReportJson(reportPath: string): ReportJson | null {
  try {
    const value = JSON.parse(readFileSync(reportPath, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    if (["createdAt", "observedAt", "importedAt", "hostname", "os", "profileId", "mode", "inventoryHost"].some((key) => value[key] != null && typeof value[key] !== "string")) return null;
    if (value.inventoryHost != null && !/^[a-zA-Z0-9_.:-]{1,96}$/.test(value.inventoryHost)) return null;
    return value as ReportJson;
  } catch {
    return null;
  }
}

function buildReportSummary(fileName: string, fullPath: string, parsed = readReportJson(fullPath)): AnsibleReportSummary | null {
  if (!parsed) {
    return null;
  }

  const stats = statSync(fullPath);
  const mode = parsed.mode ?? "agentless";
  // Older adapters stored only "openscap" at the top level. Read their actual
  // evaluated profile and content digest without rewriting historical evidence.
  const profileId = mode === "openscap" && typeof parsed.scanner?.profile === "string" && parsed.scanner.profile
    ? parsed.scanner.profile : parsed.profileId ?? null;
  const digest = mode === "astra-oval" && typeof parsed.scanner?.database?.sha256 === "string"
    ? `sha256:${parsed.scanner.database.sha256}` : parsed.scanner?.contentIdentity ?? parsed.scanner?.datastreamChecksum;
  const contentId = ["openscap", "astra-oval"].includes(mode) && typeof digest === "string" && /^(?:sha256|bundle-sha256):[a-fA-F0-9]{64}$/.test(digest)
    ? digest.toLowerCase() : null;
  let scanScope = mode === "nmap" ? normalizeNmapScope(parsed.scanner?.scanScope) : null;
  if (scanScope && (parsed.scanner?.portCoverage !== undefined && parsed.scanner.portCoverage !== nmapPortCoverage(scanScope)
      || parsed.scanner?.coverageComplete !== undefined && parsed.scanner.coverageComplete !== (scanScope === "full_tcp"))) scanScope = null;
  const scopeKnown = mode === "openscap" ? Boolean(profileId && profileId !== "openscap" && contentId) : mode !== "nmap" || Boolean(scanScope);
  const findings = reportFindings(parsed);
  const events = Array.isArray(parsed.events) ? parsed.events : [];
  const observation: Pick<AnsibleReportSummary, "observedAt" | "importedAt"> = mode === "greenbone" ? greenboneObservation(parsed) : {};
  const createdAt = mode === "greenbone" ? observation.observedAt ?? null : typeof parsed.createdAt === "string" ? parsed.createdAt : null;
  const inventoryHost = typeof parsed.inventoryHost === "string" && /^[a-zA-Z0-9_.:-]{1,96}$/.test(parsed.inventoryHost)
    ? parsed.inventoryHost : null;
  const candidateBinding = parseAssetBinding(parsed.assetBinding);
  const assetBinding = candidateBinding?.alias === inventoryHost ? candidateBinding : null;
  const assetBindingInvalid = parsed.assetBinding != null && !assetBinding;
  const available = parsed.scanner?.available !== false;
  const partial = assetBindingInvalid || !available || parsed.partial === true || parsed.scanner?.partial === true || Boolean(parsed.scanner?.error)
    || parsed.vulnerabilityScan?.partial === true || Boolean(parsed.packageInventory?.error) || parsed.packageInventory?.partial === true
    || (parsed.findings !== undefined && (!Array.isArray(parsed.findings) || findings.length !== parsed.findings.length))
    || ["dependency-track", "dependency-track-analysis"].includes(mode) || !scopeKnown || mode === "greenbone" && !observation.observedAt;
  const needsReview = assetBindingInvalid || !scopeKnown || mode === "greenbone" && !observation.observedAt || findings.some((finding) => finding.status === "manual");
  const reportTimeValid = reportTimestamp({ createdAt, modifiedAt: stats.mtime.toISOString(), ...observation }) > 0;

  return {
    id: reportIdFromFileName(fileName),
    fileName,
    path: fullPath,
    createdAt,
    ...observation,
    modifiedAt: stats.mtime.toISOString(),
    host: parsed.hostname ?? targetAliasFromReportFileName(fileName, profileId, mode),
    inventoryHost,
    assetBinding, assetBindingInvalid,
    available,
    partial,
    needsReview,
    reportTimeValid,
    profileId,
    contentId,
    scopeKnown,
    scanScope,
    portCoverage: nmapPortCoverage(scanScope),
    coverageComplete: mode === "nmap" && scanScope ? scanScope === "full_tcp" : null,
    scopeKey: reportScopeKey({ id: reportIdFromFileName(fileName), mode, profileId, contentId, scanScope }),
    mode,
    score: partial || !reportTimeValid ? null : scoreFromReport(parsed, mode),
    high: findings.filter((finding) => finding.status === "failed" && finding.risk === "high").length,
    critical: findings.filter((finding) => finding.status === "failed" && !finding.severityUnknown && finding.severityAssessment?.level === "critical").length,
    unknown: findings.filter((finding) => ["failed", "manual"].includes(finding.status) && finding.severityUnknown).length,
    medium: findings.filter((finding) => finding.status === "failed" && finding.risk === "medium").length,
    low: findings.filter((finding) => finding.status === "failed" && finding.risk === "low").length,
    info: findings.filter((finding) => finding.risk === "info").length,
    findingsCount: findings.length,
    eventsCount: events.length,
    ...(mode === "lynis" ? { lynisWarnings: findings.filter((finding) => finding.lynis?.kind === "warning").length,
      lynisSuggestions: findings.filter((finding) => finding.lynis?.kind === "suggestion").length } : {}),
  };
}

const summaryCache = new Map<string, { signature: string; summary: AnsibleReportSummary }>();
function cachedReportSummary(fileName: string, fullPath: string) {
  const info = statSync(fullPath);
  const signature = `${info.ino}:${info.size}:${info.mtimeMs}:${info.ctimeMs}`;
  const cached = summaryCache.get(fullPath);
  if (cached?.signature === signature && reportTimestamp(cached.summary) > 0) return { ...cached.summary };
  const summary = buildReportSummary(fileName, fullPath);
  // Future/invalid timestamps must be re-evaluated as time passes. Only keep
  // compact, already valid summaries; never retain the raw OVAL evidence tree.
  if (summary?.reportTimeValid) {
    if (summaryCache.size >= 256) summaryCache.delete(summaryCache.keys().next().value!);
    summaryCache.set(fullPath, { signature, summary });
  } else summaryCache.delete(fullPath);
  return summary;
}

export function listAnsibleReports(view: ArchiveView = "active") {
  const reportsDir = getReportsDir();
  if (!existsSync(reportsDir)) {
    return [];
  }

  const archived = getArchivedRecordIds("report");
  return readdirSync(reportsDir)
    .filter((fileName) => fileName.endsWith(".json"))
    .filter((fileName) => view === "all" || archived.has(fileName.slice(0, -5)) === (view === "archive"))
    .map((fileName) => {
      const fullPath = path.join(reportsDir, fileName);
      try { return cachedReportSummary(fileName, fullPath); } catch { return null; }
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
  const summary = buildReportSummary(fileName, reportPath, parsed);
  if (!parsed || !summary) {
    return null;
  }

  return {
    ...summary,
    hostname: parsed.hostname ?? null,
    os: parsed.os ?? null,
    findings: reportFindings(parsed),
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
  for (const summary of listAnsibleReports("all")) {
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
    } else if (scanner.deliveryReportId === reportId) {
      dependents.push({ id: report.id, mode: report.mode, reason: "dependency_track_delivery" });
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
    ? listAnsibleReports("all").some((candidate) => {
      if (candidate.id === report.id) return false;
      const detail = readAnsibleReport(candidate.id);
      return detail ? sbomFileFromReport(detail) === sbomFile : false;
    })
    : false;

  // The per-run scanner config has the same generated stem as its SBOM.
  // Derive this path inside the managed directory; never delete a path supplied
  // through sourceEvidence or another imported report field.
  const configPath = sbomPath && sbomFile?.endsWith(".cdx.json") && !sbomUsedElsewhere
    ? sbomPath.replace(/\.cdx\.json$/, ".trivy-config.yaml") : null;
  const configInfo = configPath ? lstatSync(configPath, { throwIfNoEntry: false }) : null;
  if (configInfo && (!configInfo.isFile() || configInfo.isSymbolicLink())) {
    throw new Error("Файл конфигурации этого сканирования имеет недопустимый тип.");
  }

  rmSync(reportPath, { force: false });
  if (sbomPath && sbomInfo && !sbomUsedElsewhere) {
    rmSync(sbomPath, { force: false });
  }
  if (configPath && configInfo) rmSync(configPath, { force: false });

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
