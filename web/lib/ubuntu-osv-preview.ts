import type { Finding } from "@/types";
import { readPinnedAdvisorySnapshot } from "@/lib/vendor-advisory-snapshot";
import { evaluatePinnedUbuntuCrossCheck } from "@/lib/ubuntu-pinned-crosscheck";
import { evaluateUbuntuOsvLifecycle, type UbuntuOsvLifecycle } from "@/lib/ubuntu-osv-lifecycle";

export type UbuntuOsvPreviewStatus = "provisional" | "unavailable";
export type UbuntuOsvPreview = {
  schemaVersion: 1;
  status: UbuntuOsvPreviewStatus;
  reason: string;
  candidateVerdict: "affected" | "fixed_or_not_affected" | "needs_review" | "unknown";
  trustedVerdict: "unknown";
  snapshotSha256: string;
  sourceRevision: string | null;
  sourcePackage: string;
  sourceVersion: string;
  conflictingWithTrivy: boolean;
  publisherAuthenticated: false;
  remediationAuthorized: false;
  lifecycle?: UbuntuOsvLifecycle;
};

export type UbuntuOsvPreviewSummary = {
  schemaVersion: 1;
  state: "disabled" | "invalid_catalog" | "invalid_policy" | "enabled";
  configuredCves: number;
  annotatedFindings: number;
  candidateAffected: number;
  candidateFixed: number;
  candidateNeedsReview: number;
  candidateUnknown: number;
  conflictingWithTrivy: number;
  unavailable: number;
  withdrawn: number;
  staleImport: number;
  invalidTimestamps: number;
  budgetExhausted: boolean;
  note: string;
};

const CVE = /^CVE-\d{4}-\d{4,}$/;
const SHA = /^[a-f0-9]{64}$/;
const MAX_CATALOG_BYTES = 24 * 1024;
const MAX_CVES = 128;
const MAX_EVALUATIONS = 512;

function catalogEntries(raw: string): Map<string, string> {
  if (Buffer.byteLength(raw, "utf8") > MAX_CATALOG_BYTES) throw new Error("catalog_size");
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("catalog_format");
  const entries = Object.entries(parsed);
  if (entries.length === 0 || entries.length > MAX_CVES) throw new Error("catalog_limit");
  for (const [cve, sha] of entries) {
    if (!CVE.test(cve) || typeof sha !== "string" || !SHA.test(sha)) throw new Error("catalog_entry");
  }
  return new Map(entries as [string, string][]);
}

const note = "Предварительная сверка с локальными снимками Ubuntu OSV. " +
  "SHA-256 и Git-ревизия не подтверждают подпись Canonical или полноту данных; " +
  "исходная оценка Trivy и возможность исправления не изменяются.";

function summary(state: UbuntuOsvPreviewSummary["state"], configuredCves: number): UbuntuOsvPreviewSummary {
  return {
    schemaVersion: 1, state, configuredCves,
    annotatedFindings: 0, candidateAffected: 0, candidateFixed: 0,
    candidateNeedsReview: 0, candidateUnknown: 0, conflictingWithTrivy: 0,
    unavailable: 0, withdrawn: 0, staleImport: 0, invalidTimestamps: 0, budgetExhausted: false, note,
  };
}

/**
 * Optional, offline and explicitly opt-in, report evidence. No network and
 * no host writes. A preview must NEVER change a finding's scanner status,
 * score, coverage or remediation entitlement.
 *
 * A configured pin is only examined for exact Ubuntu, distro-source-compatible
 * Trivy findings with recognized source package metadata.
 */
export function annotateUbuntuOsvPreview(input: {
  findings: Finding[];
  stateRoot: string;
  osId: string;
  release: string;
  inventoryComplete: boolean;
  catalogJson?: string;
  maxImportAgeHours?: number;
}): { findings: Finding[]; summary: UbuntuOsvPreviewSummary | null } {
  if (!input.catalogJson) return { findings: input.findings, summary: null };
  if (input.maxImportAgeHours !== undefined && (!Number.isInteger(input.maxImportAgeHours)
    || input.maxImportAgeHours < 1 || input.maxImportAgeHours > 8760)) {
    return { findings: input.findings, summary: summary("invalid_policy", 0) };
  }
  let catalog: Map<string, string>;
  try { catalog = catalogEntries(input.catalogJson); }
  catch {
    return { findings: input.findings, summary: summary("invalid_catalog", 0) };
  }
  const reportSummary = summary("enabled", catalog.size);
  if (input.osId !== "ubuntu") return { findings: input.findings, summary: reportSummary };

  // Cache identical CVE×source×source-version checks for DEB multiarch and
  // repeated observations. An explicit upper bound prevents thousands of
  // filesystem reads/dpkg subprocesses in very large Trivy reports.
  const cache = new Map<string, UbuntuOsvPreview>();
  const annotated = input.findings.map((finding) => {
    const cv = finding.cveApplicability;
    const id = cv?.advisory.id ?? "";
    const sha = catalog.get(id);
    if (!cv || !sha || finding.source !== "trivy" || cv.distribution.id !== "ubuntu"
      || cv.distribution.versionId !== input.release
      || cv.package.provenance !== "distribution-maintainer"
      || cv.advisory.sourceMatch !== "matched"
      || !cv.package.sourceName || !cv.package.sourceVersion
      || !CVE.test(id)) return finding;

    const key = JSON.stringify([id, sha, cv.package.sourceName, cv.package.sourceVersion]);
    let preview = cache.get(key);
    if (!preview) {
      if (cache.size >= MAX_EVALUATIONS) {
        reportSummary.budgetExhausted = true;
        return finding;
      }
      let result: ReturnType<typeof evaluatePinnedUbuntuCrossCheck> | null = null;
      let sourceRevision: string | null = null;
      let lifecycle: UbuntuOsvLifecycle | undefined;
      try {
        const snapshot = readPinnedAdvisorySnapshot(input.stateRoot, sha);
        // A purely local, operator-provided digest must never pretend to
        // be an independently acquired Canonical reference.
        if (snapshot.manifest.sourceReference?.kind === "canonical-github-pinned-revision") {
          sourceRevision = snapshot.manifest.sourceReference.revision;
          const record: unknown = JSON.parse(snapshot.rawJson);
          lifecycle = evaluateUbuntuOsvLifecycle({
            importedAt: snapshot.manifest.importedAt,
            record: record && typeof record === "object" && !Array.isArray(record) ? record as Record<string, unknown> : {},
            revision: sourceRevision,
            maxImportAgeHours: input.maxImportAgeHours,
          });
          if (lifecycle.candidateAllowed) result = evaluatePinnedUbuntuCrossCheck({
            stateRoot: input.stateRoot, snapshotSha256: sha,
            osId: input.osId, release: input.release, cveId: id,
            sourcePackage: cv.package.sourceName, sourceVersion: cv.package.sourceVersion,
            inventoryComplete: input.inventoryComplete,
          });
        }
      } catch {
        // Invalid or missing snapshots remain visible as unavailable.
      }
      const candidateVerdict = result?.candidateVerdict ?? "unknown";
      const contradicts = result?.status === "provisional" && (
        (cv.verdict === "affected" && candidateVerdict === "fixed_or_not_affected")
        || (cv.verdict === "not_affected" && candidateVerdict === "affected")
      );
      preview = {
        schemaVersion: 1,
        status: lifecycle && !lifecycle.candidateAllowed ? "unavailable" : result?.status ?? "unavailable",
        reason: lifecycle && !lifecycle.candidateAllowed ? lifecycle.reason : result?.reason ?? "pinned_canonical_snapshot_unavailable",
        candidateVerdict, trustedVerdict: "unknown", snapshotSha256: sha,
        sourceRevision, sourcePackage: cv.package.sourceName,
        sourceVersion: cv.package.sourceVersion,
        conflictingWithTrivy: contradicts, publisherAuthenticated: false,
        remediationAuthorized: false,
        ...(lifecycle ? { lifecycle } : {}),
      };
      cache.set(key, preview);
    }
    reportSummary.annotatedFindings++;
    if (preview.status === "unavailable") reportSummary.unavailable++;
    if (preview.lifecycle?.state === "withdrawn_record") reportSummary.withdrawn++;
    if (preview.lifecycle?.state === "stale_import") reportSummary.staleImport++;
    if (preview.lifecycle && ["invalid_timestamps", "future_timestamps"].includes(preview.lifecycle.state)) reportSummary.invalidTimestamps++;
    if (preview.candidateVerdict === "affected") reportSummary.candidateAffected++;
    else if (preview.candidateVerdict === "fixed_or_not_affected") reportSummary.candidateFixed++;
    else if (preview.candidateVerdict === "needs_review") reportSummary.candidateNeedsReview++;
    else reportSummary.candidateUnknown++;
    if (preview.conflictingWithTrivy) reportSummary.conflictingWithTrivy++;
    return { ...finding, ubuntuOsvPreview: preview };
  });
  return { findings: annotated, summary: reportSummary };
}
