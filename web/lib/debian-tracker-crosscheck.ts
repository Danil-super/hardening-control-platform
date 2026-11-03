import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

/**
 * Isolated, read-only evaluator for an operator-provided, one-package/one-CVE
 * excerpt of Debian Security Tracker's UNSTABLE JSON export.
 *
 * NOT a parser for the full tracker export. The excerpt digest does not prove
 * the upstream feed's completeness, publisher identity, freshness, or that a
 * host's installed package originated from Debian.
 */
export const DEBIAN_TRACKER_EXCERPT_MAX_BYTES = 128 * 1024;
export const DEBIAN_TRACKER_ADAPTER_VERSION = "debian-tracker-excerpt-v1";

type JsonRecord = Record<string, unknown>;
type ReleaseEntry = JsonRecord;
export type DebianTrackerExcerpt = {
  schemaVersion: 1;
  adapterVersion: typeof DEBIAN_TRACKER_ADAPTER_VERSION;
  sourcePackage: string;
  cveId: string;
  releases: Record<string, ReleaseEntry>;
  sha256: string;
  integrity: "sha256-matched-publisher-unverified";
};

export type DebianTrackerCandidateVerdict =
  | "affected" | "fixed_or_not_affected" | "needs_review" | "unknown";

export type DebianTrackerEvaluation = {
  schemaVersion: 1;
  adapterVersion: typeof DEBIAN_TRACKER_ADAPTER_VERSION;
  status: "provisional" | "unavailable";
  reason: string;
  candidateVerdict: DebianTrackerCandidateVerdict;
  trustedVerdict: "unknown";
  source: "debian-security-tracker-json-excerpt";
  cveId: string;
  sourcePackage: string;
  sourceVersion: string;
  release: string;
  trackerStatus: string | null;
  fixedVersion: string | null;
  snapshotSha256: string | null;
  publisherAuthenticated: false;
  publisherFreshnessVerified: false;
  remediationAuthorized: false;
};

function object(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function sourceName(value: unknown): value is string {
  return typeof value === "string" && value.length <= 180
    && /^[a-z0-9][a-z0-9+.-]*$/.test(value);
}

function cveName(value: unknown): value is string {
  return typeof value === "string" && /^CVE-\d{4}-\d{4,}$/.test(value) && value.length <= 32;
}

function releaseName(value: unknown): value is string {
  return typeof value === "string" && value.length <= 32
    && /^[a-z][a-z0-9-]*$/.test(value);
}

function dpkgVersion(value: unknown): value is string {
  return typeof value === "string" && value.length <= 256
    && /^[A-Za-z0-9.+~:-]+$/.test(value);
}

function compareDebianVersions(installed: string, fixed: string): "lt" | "ge" | null {
  if (!dpkgVersion(installed) || !dpkgVersion(fixed)) return null;
  const invoke = (op: "lt" | "ge") => {
    const result = spawnSync("/usr/bin/dpkg", ["--compare-versions", installed, op, fixed], {
      timeout: 3000, encoding: "utf8", maxBuffer: 65536, windowsHide: true,
    });
    if (result.error || result.signal || (result.status !== 0 && result.status !== 1)) return null;
    return result.status === 0;
  };
  const lt = invoke("lt");
  const ge = invoke("ge");
  if (lt === null || ge === null || lt === ge) return null;
  return lt ? "lt" : "ge";
}

/**
 * Input is a bounded JSON object containing exactly one source package and
 * one CVE subtree copied from the tracker; it is NOT the complete official
 * data/json export. A matching digest authenticates neither the excerpt's
 * extraction process nor the upstream publisher.
 */
export function parseDebianTrackerExcerpt(rawJson: string, expectedSha256: string): DebianTrackerExcerpt {
  if (!/^[a-f0-9]{64}$/.test(expectedSha256)) throw new Error("Invalid Debian tracker SHA-256");
  const bytes = Buffer.byteLength(rawJson, "utf8");
  if (bytes < 2 || bytes > DEBIAN_TRACKER_EXCERPT_MAX_BYTES) throw new Error("Debian tracker excerpt exceeds size limit");
  if (createHash("sha256").update(rawJson, "utf8").digest("hex") !== expectedSha256) {
    throw new Error("Debian tracker excerpt differs from the pinned SHA-256");
  }
  const parsed: unknown = JSON.parse(rawJson);
  if (!object(parsed)) throw new Error("Invalid Debian tracker excerpt root");
  const sourcePackages = Object.keys(parsed);
  if (sourcePackages.length !== 1 || !sourceName(sourcePackages[0])) {
    throw new Error("Debian tracker excerpt must contain exactly one valid source package");
  }
  const packageEntries = parsed[sourcePackages[0]];
  if (!object(packageEntries)) throw new Error("Invalid Debian tracker source package entry");
  const cves = Object.keys(packageEntries);
  if (cves.length !== 1 || !cveName(cves[0])) {
    throw new Error("Debian tracker excerpt must contain exactly one CVE");
  }
  const entry = packageEntries[cves[0]];
  if (!object(entry) || !object(entry.releases)) throw new Error("Invalid Debian tracker CVE entry");
  const releases = entry.releases;
  const releaseNames = Object.keys(releases);
  if (releaseNames.length === 0 || releaseNames.length > 32
    || releaseNames.some((name) => !releaseName(name) || !object(releases[name]))) {
    throw new Error("Invalid Debian tracker releases schema");
  }
  return {
    schemaVersion: 1, adapterVersion: DEBIAN_TRACKER_ADAPTER_VERSION,
    sourcePackage: sourcePackages[0], cveId: cves[0],
    releases: releases as Record<string, ReleaseEntry>, sha256: expectedSha256,
    integrity: "sha256-matched-publisher-unverified",
  };
}

export function evaluateDebianTrackerExcerpt(
  snapshot: DebianTrackerExcerpt,
  input: {
    osId: string; inventoryComplete: boolean;
    cveId: string; release: string; sourcePackage: string; sourceVersion: string;
  },
): DebianTrackerEvaluation {
  const base: DebianTrackerEvaluation = {
    schemaVersion: 1, adapterVersion: DEBIAN_TRACKER_ADAPTER_VERSION,
    status: "unavailable", reason: "insufficient_vendor_evidence",
    candidateVerdict: "unknown", trustedVerdict: "unknown",
    source: "debian-security-tracker-json-excerpt",
    cveId: input.cveId, release: input.release,
    sourcePackage: input.sourcePackage, sourceVersion: input.sourceVersion,
    trackerStatus: null, fixedVersion: null, snapshotSha256: null,
    publisherAuthenticated: false, publisherFreshnessVerified: false, remediationAuthorized: false,
  };
  if (input.osId !== "debian") return { ...base, reason: "unsupported_exact_os_identity" };
  if (input.inventoryComplete !== true) return { ...base, reason: "incomplete_source_inventory" };
  if (!cveName(input.cveId) || !releaseName(input.release)
    || !sourceName(input.sourcePackage) || !dpkgVersion(input.sourceVersion)) {
    return { ...base, reason: "invalid_target_identity" };
  }
  if (snapshot.schemaVersion !== 1 || snapshot.adapterVersion !== DEBIAN_TRACKER_ADAPTER_VERSION
    || snapshot.integrity !== "sha256-matched-publisher-unverified"
    || !/^[a-f0-9]{64}$/.test(snapshot.sha256)
    || !object(snapshot.releases)) {
    return { ...base, reason: "invalid_excerpt_identity" };
  }
  if (snapshot.sourcePackage !== input.sourcePackage) return { ...base, reason: "source_package_mismatch" };
  if (snapshot.cveId !== input.cveId) return { ...base, reason: "cve_identity_mismatch" };
  if (!Object.hasOwn(snapshot.releases, input.release)) {
    return { ...base, reason: "source_release_not_listed", snapshotSha256: snapshot.sha256 };
  }
  const release = snapshot.releases[input.release];
  if (!object(release)) return { ...base, reason: "invalid_release_entry" };
  const status = release.status;
  const fixed = release.fixed_version;
  const evidence = {
    ...base, status: "provisional" as const, snapshotSha256: snapshot.sha256,
    trackerStatus: typeof status === "string" && status.length <= 64 ? status : null,
    fixedVersion: typeof fixed === "string" && fixed.length <= 256 ? fixed : null,
  };
  if (status === "undetermined") {
    return { ...evidence, reason: "tracker_status_undetermined", candidateVerdict: "needs_review" };
  }
  if (status === "open") {
    return { ...evidence, reason: "tracker_open_no_safe_fixed_conclusion", candidateVerdict: "needs_review" };
  }
  if (status !== "resolved") return { ...evidence, reason: "unsupported_tracker_status" };
  if (fixed === "0") {
    return { ...evidence, reason: "tracker_explicit_not_affected_sentinel",
      candidateVerdict: "fixed_or_not_affected" };
  }
  if (!dpkgVersion(fixed)) {
    return { ...evidence, reason: "resolved_without_valid_fixed_version" };
  }
  const ordering = compareDebianVersions(input.sourceVersion, fixed);
  if (ordering === null) return { ...evidence, reason: "native_dpkg_version_comparison_unavailable" };
  return ordering === "lt"
    ? { ...evidence, reason: "source_version_before_tracker_fixed", candidateVerdict: "affected" }
    : { ...evidence, reason: "source_version_at_or_after_tracker_fixed", candidateVerdict: "fixed_or_not_affected" };
}
