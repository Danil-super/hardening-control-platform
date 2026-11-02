import { readPinnedAdvisorySnapshot } from "@/lib/vendor-advisory-snapshot";
import { parseUbuntuOsvSnapshot, evaluateUbuntuOsv, type UbuntuOsvEvaluation } from "@/lib/ubuntu-osv-crosscheck";

/**
 * A source-digest-pinned *preliminary* vendor comparison. Not an authenticated
 * Canonical advisory, and not a security/remediation verdict.
 *
 * Deliberately not invoked by scan jobs, report normalization or UI yet.
 */
export type PinnedUbuntuCrossCheckInput = {
  stateRoot: string;
  snapshotSha256: string;
  osId: string;
  release: string;
  cveId: string;
  sourcePackage: string;
  sourceVersion: string;
  inventoryComplete: boolean;
};

export type PinnedUbuntuCrossCheck = {
  schemaVersion: 1;
  status: "provisional" | "unavailable";
  reason: string;
  candidateVerdict: UbuntuOsvEvaluation["verdict"];
  trustedVerdict: "unknown";
  source: "ubuntu-osv-cve";
  snapshotSha256: string | null;
  recordId: string | null;
  importedAt: string | null;
  publishedAt: null;
  publisherAuthenticated: false;
  publisherFreshnessVerified: false;
  remediationAuthorized: false;
  evaluation: UbuntuOsvEvaluation | null;
};

function unavailable(reason: string): PinnedUbuntuCrossCheck {
  return {
    schemaVersion: 1, status: "unavailable", reason, candidateVerdict: "unknown",
    trustedVerdict: "unknown", source: "ubuntu-osv-cve",
    snapshotSha256: null, recordId: null, importedAt: null, publishedAt: null,
    publisherAuthenticated: false, publisherFreshnessVerified: false,
    remediationAuthorized: false, evaluation: null,
  };
}

/**
 * Read the exact stored bytes and evaluate the matching Canonical OSV
 * source-package record using native dpkg version ordering.
 *
 * The local import timestamp is NOT the advisory publication timestamp.
 * A pinned SHA-256 does not authenticate the publisher; the outcome must
 * remain provisional even when the candidate says fixed_or_not_affected.
 */
export function evaluatePinnedUbuntuCrossCheck(input: PinnedUbuntuCrossCheckInput): PinnedUbuntuCrossCheck {
  if (input.osId !== "ubuntu") return unavailable("unsupported_exact_os_identity");
  if (input.inventoryComplete !== true) return unavailable("incomplete_source_inventory");
  if (!/^CVE-\d{4}-\d{4,}$/.test(input.cveId)
    || !/^\d{2}\.\d{2}$/.test(input.release)) return unavailable("invalid_target_identity");
  try {
    const source = readPinnedAdvisorySnapshot(input.stateRoot, input.snapshotSha256);
    const expectedRecord = `UBUNTU-${input.cveId}`;
    if (source.manifest.recordId !== expectedRecord) return unavailable("advisory_identity_mismatch");
    if (source.manifest.publisherAuthenticated !== false) return unavailable("publisher_trust_claim_unsupported");
    // Parse again rather than trusting the vault's minimal JSON identifier check.
    const snapshot = parseUbuntuOsvSnapshot(source.rawJson, source.manifest.sha256);
    const evaluation = evaluateUbuntuOsv(snapshot, {
      cveId: input.cveId,
      release: input.release,
      sourcePackage: input.sourcePackage,
      sourceVersion: input.sourceVersion,
    });
    // Expose the useful source/version comparison, while refusing to treat an
    // unsigned record as an independently confirmed vendor fix.
    return {
      schemaVersion: 1,
      status: "provisional",
      reason: evaluation.reason,
      candidateVerdict: evaluation.verdict,
      trustedVerdict: "unknown",
      source: "ubuntu-osv-cve",
      snapshotSha256: source.manifest.sha256,
      recordId: source.manifest.recordId,
      importedAt: source.manifest.importedAt,
      publishedAt: null,
      publisherAuthenticated: false,
      publisherFreshnessVerified: false,
      remediationAuthorized: false,
      evaluation,
    };
  } catch {
    // Could be missing, unreadable, stale, altered, oversized or invalid OSV.
    // Do not propagate paths or the untrusted advisory content into the UI.
    return unavailable("pinned_snapshot_unavailable_or_invalid");
  }
}
