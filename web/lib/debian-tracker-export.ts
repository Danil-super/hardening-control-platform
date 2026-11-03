/**
 * Immutable final-report projection of *original* Debian Trivy CVE observations.
 * No scanner re-run, advisory access, network IO, remediation or vendor attestation.
 */
export const MAX_DEBIAN_TRACKER_EXPORT_RECORDS = 4096;
const SHA = /^[a-f0-9]{64}$/;
const CVE = /^CVE-\d{4}-\d{4,}$/;
const VERSION = /^[A-Za-z0-9.+~:-]{1,256}$/;
const SOURCE = /^[a-z0-9][a-z0-9+.-]{0,179}$/;
const RELEASE = /^(bullseye|bookworm|trixie)$/;
const STATUS = new Set(["provisional", "unavailable"]);
const VERDICT = new Set(["affected", "fixed_or_not_affected", "needs_review", "unknown"]);
const PIN_MODE = new Set(["independently-specified-sha256", "observed-at-capture"]);
const FINDING_STATUS = new Set(["failed", "passed", "fixed", "manual"]);
const SCANNER_VERDICT = new Set(["affected", "not_affected", "under_investigation", "unknown"]);

function object(raw: unknown): Record<string, unknown> | null {
  return raw && typeof raw === "object" && !Array.isArray(raw) ? raw as Record<string, unknown> : null;
}
function bounded(raw: unknown, max: number): raw is string {
  return typeof raw === "string" && raw.length > 0 && raw.length <= max
    && !/[\x00-\x1f\x7f]/.test(raw);
}
function utc(raw: unknown): raw is string {
  if (typeof raw !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(raw)) return false;
  const ms = Date.parse(raw);
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 19) === raw.slice(0, 19);
}

export type DebianTrackerExportRecord = {
  schemaVersion: 1;
  sourceReportId: string;
  sourceReportSha256: string;
  findingId: string;
  cveId: string;
  packageName: string;
  installedVersion: string;
  sourcePackage: string;
  sourceVersion: string;
  release: string;
  scannerStatus: string;
  trivyApplicability: string;
  candidateStatus: "provisional" | "unavailable";
  candidateVerdict: "affected" | "fixed_or_not_affected" | "needs_review" | "unknown";
  candidateReason: string;
  fixedVersion: string | null;
  fullSnapshotSha256: string;
  derivedExcerptSha256: string | null;
  capturedAt: string;
  pinMode: "independently-specified-sha256" | "observed-at-capture";
  conflictingWithTrivy: boolean;
  trustedVerdict: "unknown";
  publisherAuthenticated: false;
  publisherFreshnessVerified: false;
  remediationAuthorized: false;
};

export type DebianTrackerExportSource = {
  reportId: string;
  reportSha256: string;
  findings: unknown;
};

function tuple(source: { reportId: string; reportSha256: string }, finding: Record<string, unknown>,
  cv: Record<string, unknown>, pkg: Record<string, unknown>, advisory: Record<string, unknown>,
  preview: Record<string, unknown>): string {
  return JSON.stringify([source.reportId, source.reportSha256, finding.id, advisory.id,
    pkg.name, pkg.installedVersion, preview.sourcePackage, preview.sourceVersion, preview.release,
    preview.fullSnapshotSha256, preview.derivedExcerptSha256, preview.candidateVerdict]);
}

/**
 * Fail the entire export for invalid or ambiguous evidence, rather than
 * omitting a finding or replacing the original Trivy conclusion.
 */
export function projectDebianTrackerEvidence(sources: DebianTrackerExportSource[]): DebianTrackerExportRecord[] {
  const output: DebianTrackerExportRecord[] = [];
  const identities = new Set<string>();
  for (const source of sources) {
    if (!bounded(source.reportId, 180) || !SHA.test(source.reportSha256)) {
      throw new Error("Недопустимая идентичность исходного CVE-отчёта Debian.");
    }
    if (!Array.isArray(source.findings)) throw new Error("Невозможно проверить состав исходных CVE-находок Debian.");
    for (const rawFinding of source.findings) {
      const finding = object(rawFinding);
      if (!finding || finding.debianTrackerPreview === undefined) continue;
      const preview = object(finding.debianTrackerPreview);
      const cv = object(finding.cveApplicability);
      const pkg = object(cv?.package);
      const advisory = object(cv?.advisory);
      const distro = object(cv?.distribution);
      if (!preview || !cv || !pkg || !advisory || !distro
        || finding.source !== "trivy" || !bounded(finding.id, 256)
        || !FINDING_STATUS.has(String(finding.status))
        || distro.id !== "debian" || !["11", "12", "13"].includes(String(distro.versionId))
        || pkg.manager !== "dpkg" || pkg.provenance !== "distribution-maintainer"
        || advisory.sourceMatch !== "matched"
        || !bounded(pkg.name, 180) || !bounded(pkg.installedVersion, 256)
        || !CVE.test(String(advisory.id)) || !SOURCE.test(String(preview.sourcePackage))
        || !VERSION.test(String(preview.sourceVersion))
        || pkg.sourceName !== preview.sourcePackage || pkg.sourceVersion !== preview.sourceVersion
        || !RELEASE.test(String(preview.release))
        || ({ "11": "bullseye", "12": "bookworm", "13": "trixie" } as Record<string, string>)[String(distro.versionId)] !== preview.release
        || preview.schemaVersion !== 1
        || !STATUS.has(String(preview.status)) || !VERDICT.has(String(preview.candidateVerdict))
        || !SCANNER_VERDICT.has(String(cv.verdict)) || !bounded(preview.reason, 120)
        || !SHA.test(String(preview.fullSnapshotSha256))
        || !(preview.derivedExcerptSha256 === null || SHA.test(String(preview.derivedExcerptSha256)))
        || !(preview.fixedVersion === null || VERSION.test(String(preview.fixedVersion)) || preview.fixedVersion === "0")
        || !utc(preview.capturedAt) || !PIN_MODE.has(String(preview.pinMode))
        || typeof preview.conflictingWithTrivy !== "boolean"
        || preview.publisherAuthenticated !== false || preview.publisherFreshnessVerified !== false
        || preview.remediationAuthorized !== false || preview.trustedVerdict !== "unknown"
        || (preview.status === "unavailable" && preview.candidateVerdict !== "unknown")
        || (preview.status === "provisional" && preview.derivedExcerptSha256 === null)
        || (["affected", "fixed_or_not_affected"].includes(String(preview.candidateVerdict)) && preview.fixedVersion === null)
        || preview.conflictingWithTrivy !== (preview.status === "provisional"
          && ((cv.verdict === "affected" && preview.candidateVerdict === "fixed_or_not_affected")
           || (cv.verdict === "not_affected" && preview.candidateVerdict === "affected")))) {
        throw new Error("Некорректное предварительное Debian-доказательство: экспорт остановлен.");
      }
      const id = JSON.stringify([source.reportId, finding.id]);
      if (identities.has(id)) throw new Error("Дублирующаяся Debian CVE-находка в исходном отчёте.");
      identities.add(id);
      if (output.length >= MAX_DEBIAN_TRACKER_EXPORT_RECORDS) {
        throw new Error("Превышен лимит Debian-доказательств: нельзя обрезать итоговый отчёт.");
      }
      output.push({
        schemaVersion: 1, sourceReportId: source.reportId, sourceReportSha256: source.reportSha256,
        findingId: finding.id as string, cveId: advisory.id as string,
        packageName: pkg.name as string, installedVersion: pkg.installedVersion as string,
        sourcePackage: preview.sourcePackage as string, sourceVersion: preview.sourceVersion as string,
        release: preview.release as string, scannerStatus: finding.status as string,
        trivyApplicability: cv.verdict as string, candidateStatus: preview.status as DebianTrackerExportRecord["candidateStatus"],
        candidateVerdict: preview.candidateVerdict as DebianTrackerExportRecord["candidateVerdict"],
        candidateReason: preview.reason as string, fixedVersion: preview.fixedVersion as string | null,
        fullSnapshotSha256: preview.fullSnapshotSha256 as string, derivedExcerptSha256: preview.derivedExcerptSha256 as string | null,
        capturedAt: preview.capturedAt as string, pinMode: preview.pinMode as DebianTrackerExportRecord["pinMode"],
        conflictingWithTrivy: preview.conflictingWithTrivy as boolean,
        trustedVerdict: "unknown", publisherAuthenticated: false, publisherFreshnessVerified: false,
        remediationAuthorized: false,
      });
    }
  }
  output.sort((a, b) => a.sourceReportId.localeCompare(b.sourceReportId) || a.findingId.localeCompare(b.findingId));
  assertDebianTrackerEvidenceMultiset(sources, output);
  return output;
}

/**
 * Independently check the exact multiset of source identity + CVE + package +
 * version + candidate provenance, including repeats. No correlation dedup.
 * Allows stored snapshots to be independently audited after projection.
 */
export function assertDebianTrackerEvidenceMultiset(sources: DebianTrackerExportSource[], exported: DebianTrackerExportRecord[]): void {
  const expected = new Map<string, number>();
  const actual = new Map<string, number>();
  const add = (map: Map<string, number>, key: string) => map.set(key, (map.get(key) ?? 0) + 1);
  for (const source of sources) {
    if (!Array.isArray(source.findings)) throw new Error("CVE source findings are not an array.");
    for (const value of source.findings) {
      const finding = object(value);
      if (!finding || finding.debianTrackerPreview === undefined) continue;
      const cv = object(finding.cveApplicability);
      const pkg = object(cv?.package);
      const advisory = object(cv?.advisory);
      const preview = object(finding.debianTrackerPreview);
      if (!cv || !pkg || !advisory || !preview) throw new Error("Malformed source Debian CVE record.");
      add(expected, tuple(source, finding, cv, pkg, advisory, preview));
    }
  }
  for (const record of exported) {
    add(actual, JSON.stringify([record.sourceReportId, record.sourceReportSha256, record.findingId,
      record.cveId, record.packageName, record.installedVersion, record.sourcePackage,
      record.sourceVersion, record.release, record.fullSnapshotSha256, record.derivedExcerptSha256,
      record.candidateVerdict]));
  }
  if (expected.size !== actual.size || [...expected].some(([key, count]) => actual.get(key) !== count)) {
    throw new Error("Потеря, дублирование либо подмена Debian CVE-доказательств в проекции.");
  }
}
