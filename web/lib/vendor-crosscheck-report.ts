/**
 * Bounded immutable projection of the *original* CVE report observations
 * into the final project-report snapshot and PDF. Never infer vendor trust.
 * No network access and no advisory file reads are performed here.
 */
export type VendorAdvisoryExportRecord = {
  sourceReportId: string;
  sourceReportSha256: string;
  findingId: string;
  cveId: string;
  packageName: string;
  installedVersion: string;
  sourcePackage: string;
  sourceVersion: string;
  scannerStatus: string;
  trivyApplicability: string;
  candidateVerdict: string;
  candidateStatus: string;
  candidateReason: string;
  snapshotSha256: string;
  sourceRevision: string | null;
  conflictingWithTrivy: boolean;
  trustedVerdict: "unknown";
  publisherAuthenticated: false;
  remediationAuthorized: false;
};

export const MAX_VENDOR_ADVISORY_EXPORT_RECORDS = 4096;
const SHA = /^[a-f0-9]{64}$/;
const CVE = /^CVE-\d{4}-\d{4,}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const statuses = ["provisional", "unavailable"];
const candidates = ["affected", "fixed_or_not_affected", "needs_review", "unknown"];

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function bounded(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max
    && !/[\x00-\x1f\x7f]/.test(value);
}

/** A malformed embedded evidence record fails the entire export; it is never silently dropped. */
export function projectVendorAdvisoryEvidence(sources: Array<{
  reportId: string;
  reportSha256: string;
  findings: unknown;
}>): VendorAdvisoryExportRecord[] {
  const result: VendorAdvisoryExportRecord[] = [];
  const identities = new Set<string>();
  for (const source of sources) {
    if (!SHA.test(source.reportSha256) || !bounded(source.reportId, 180)) {
      throw new Error("Исходный CVE-отчёт не имеет проверяемой идентичности для экспорта OSV.");
    }
    if (!Array.isArray(source.findings)) throw new Error("Исходные CVE-находки имеют недопустимый формат.");
    for (const raw of source.findings) {
      const finding = record(raw);
      if (!finding || finding.ubuntuOsvPreview === undefined) continue;
      const preview = record(finding.ubuntuOsvPreview);
      const applicability = record(finding.cveApplicability);
      const advisory = record(applicability?.advisory);
      const pkg = record(applicability?.package);
      if (!preview || !applicability || !advisory || !pkg
        || finding.source !== "trivy"
        || !bounded(finding.id, 256)
        || !["failed", "manual", "passed", "fixed"].includes(String(finding.status))
        || !CVE.test(String(advisory.id))
        || !bounded(pkg.name, 180) || !bounded(pkg.installedVersion, 256)
        || !bounded(preview.sourcePackage, 180) || !bounded(preview.sourceVersion, 256)
        || preview.sourcePackage !== pkg.sourceName || preview.sourceVersion !== pkg.sourceVersion
        || !statuses.includes(String(preview.status))
        || !candidates.includes(String(preview.candidateVerdict))
        || !bounded(preview.reason, 120)
        || !SHA.test(String(preview.snapshotSha256))
        || (preview.sourceRevision !== null && !GIT_COMMIT.test(String(preview.sourceRevision)))
        || preview.trustedVerdict !== "unknown"
        || preview.publisherAuthenticated !== false
        || preview.remediationAuthorized !== false
        || typeof preview.conflictingWithTrivy !== "boolean"
        || !bounded(applicability.verdict, 80)) {
        throw new Error("Невозможно безопасно включить некорректное OSV-доказательство в итоговый отчёт.");
      }
      const key = JSON.stringify([source.reportId, finding.id]);
      if (identities.has(key)) throw new Error("Повторяющийся идентификатор OSV-находки в исходном отчёте.");
      identities.add(key);
      if (result.length >= MAX_VENDOR_ADVISORY_EXPORT_RECORDS) {
        throw new Error("Лимит OSV-доказательств итогового PDF превышен; экспорт не должен скрывать часть наблюдений.");
      }
      result.push({
        sourceReportId: source.reportId,
        sourceReportSha256: source.reportSha256,
        findingId: finding.id as string,
        cveId: advisory.id as string,
        packageName: pkg.name as string,
        installedVersion: pkg.installedVersion as string,
        sourcePackage: preview.sourcePackage as string,
        sourceVersion: preview.sourceVersion as string,
        scannerStatus: finding.status as string,
        trivyApplicability: applicability.verdict as string,
        candidateVerdict: preview.candidateVerdict as string,
        candidateStatus: preview.status as string,
        candidateReason: preview.reason as string,
        snapshotSha256: preview.snapshotSha256 as string,
        sourceRevision: preview.sourceRevision as string | null,
        conflictingWithTrivy: preview.conflictingWithTrivy as boolean,
        trustedVerdict: "unknown",
        publisherAuthenticated: false,
        remediationAuthorized: false,
      });
    }
  }
  result.sort((a, b) => a.sourceReportId.localeCompare(b.sourceReportId)
    || a.findingId.localeCompare(b.findingId));
  return result;
}
