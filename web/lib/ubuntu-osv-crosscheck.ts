import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

/**
 * Ubuntu CVE OSV records describe source packages in exact release ecosystems.
 * This module is deliberately offline: callers must separately establish source
 * provenance, freshness and the trust policy for each immutable snapshot.
 */
export const UBUNTU_OSV_MAX_BYTES = 8 * 1024 * 1024;

export type UbuntuOsvSnapshot = {
  record: Record<string, unknown>;
  sha256: string;
  bytes: number;
  integrity: "digest-matched-publisher-unverified";
};

export type UbuntuOsvVerdict = "affected" | "fixed_or_not_affected" | "needs_review" | "unknown";
export type UbuntuOsvEvaluation = {
  schemaVersion: 1;
  verdict: UbuntuOsvVerdict;
  reason: string;
  cveId: string;
  sourcePackage: string;
  sourceVersion: string;
  release: string;
  fixedVersion: string | null;
  snapshotSha256: string;
  provenance: "publisher-unverified";
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function packageVersion(value: unknown): value is string {
  // Debian versions permit epoch, tilde and distro backport revisions. Use
  // argv, not a shell; reject control characters and arbitrary large strings.
  return typeof value === "string" && value.length > 0 && value.length <= 256
    && /^[A-Za-z0-9.+~:-]+$/.test(value);
}

function sourceName(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 180
    && /^[a-z0-9][a-z0-9+.-]*$/.test(value);
}

/** Compare Debian-native versions; do not use semver or lexical ordering. */
function dpkgCompareVersions(a: string, op: "lt" | "ge", b: string): boolean | null {
  if (!packageVersion(a) || !packageVersion(b)) return null;
  const result = spawnSync("/usr/bin/dpkg", ["--compare-versions", a, op, b], {
    encoding: "utf8", timeout: 3000, maxBuffer: 65536, windowsHide: true,
  });
  if (result.error || result.signal || ![0, 1].includes(result.status ?? -1)) return null;
  return result.status === 0;
}

export function parseUbuntuOsvSnapshot(rawJson: string, expectedSha256: string): UbuntuOsvSnapshot {
  if (!/^[a-f0-9]{64}$/.test(expectedSha256)) throw new Error("Ubuntu OSV expected SHA-256 is invalid");
  const bytes = Buffer.byteLength(rawJson, "utf8");
  if (bytes === 0 || bytes > UBUNTU_OSV_MAX_BYTES) throw new Error("Ubuntu OSV exceeds the bounded snapshot size");
  const sha256 = createHash("sha256").update(rawJson, "utf8").digest("hex");
  if (sha256 !== expectedSha256) throw new Error("Ubuntu OSV snapshot differs from independently pinned digest");
  const record: unknown = JSON.parse(rawJson);
  if (!isRecord(record) || typeof record.id !== "string" || !/^UBUNTU-CVE-\d{4}-\d{4,}$/.test(record.id)
      || !Array.isArray(record.affected) || record.affected.length > 3000
      || !Array.isArray(record.upstream) || !record.upstream.includes(record.id.replace(/^UBUNTU-/, ""))
      || typeof record.schema_version !== "string" || !/^1\.\d+\.\d+$/.test(record.schema_version)) {
    throw new Error("Ubuntu OSV record has an unsupported CVE schema or identity");
  }
  return { record, sha256, bytes, integrity: "digest-matched-publisher-unverified" };
}

export function evaluateUbuntuOsv(
  snapshot: UbuntuOsvSnapshot,
  input: { cveId: string; release: string; sourcePackage: string; sourceVersion: string },
): UbuntuOsvEvaluation {
  const base = {
    schemaVersion: 1 as const, verdict: "unknown" as UbuntuOsvVerdict, reason: "insufficient_vendor_evidence",
    cveId: input.cveId, sourcePackage: input.sourcePackage,
    sourceVersion: input.sourceVersion, release: input.release,
    fixedVersion: null as string | null, snapshotSha256: snapshot.sha256,
    provenance: "publisher-unverified" as const,
  };
  if (!/^CVE-\d{4}-\d{4,}$/.test(input.cveId) || !/^\d{2}\.\d{2}$/.test(input.release)
    || !sourceName(input.sourcePackage) || !packageVersion(input.sourceVersion)) {
    return { ...base, reason: "invalid_target_identity" };
  }
  if (snapshot.integrity !== "digest-matched-publisher-unverified"
    || !/^[a-f0-9]{64}$/.test(snapshot.sha256) || !isRecord(snapshot.record)
    || snapshot.record.id !== `UBUNTU-${input.cveId}`) {
    return { ...base, reason: "snapshot_identity_mismatch" };
  }
  const affected = snapshot.record.affected;
  if (!Array.isArray(affected) || affected.length > 3000) return { ...base, reason: "snapshot_schema_unsupported" };
  const matches = affected.filter((item) => {
    if (!isRecord(item) || !isRecord(item.package)) return false;
    return item.package.name === input.sourcePackage
      && item.package.ecosystem === `Ubuntu:${input.release}:LTS`;
  });
  // Missing package/release data cannot prove "not affected" because it might
  // represent an omitted suite, an ESM-only package, or incomplete CVE data.
  if (matches.length === 0) return { ...base, reason: "source_release_not_listed" };
  if (matches.length !== 1) return { ...base, verdict: "needs_review", reason: "duplicate_source_release_entries" };
  const entry = matches[0] as Record<string, unknown>;
  const ranges = entry.ranges;
  if (!Array.isArray(ranges) || ranges.length !== 1 || !isRecord(ranges[0]) || ranges[0].type !== "ECOSYSTEM") {
    return { ...base, reason: "unsupported_version_range" };
  }
  const events = ranges[0].events;
  if (!Array.isArray(events) || events.length < 1 || events.length > 2 || !events.every(isRecord)
    || events[0].introduced !== "0") {
    return { ...base, reason: "unsupported_version_events" };
  }
  if (events.length === 2) {
    const fixedVersion = events[1].fixed;
    if (!packageVersion(fixedVersion) || Object.keys(events[1]).length !== 1) return { ...base, reason: "unsupported_fixed_version" };
    const lower = dpkgCompareVersions(input.sourceVersion, "lt", fixedVersion);
    const greaterEqual = dpkgCompareVersions(input.sourceVersion, "ge", fixedVersion);
    if (lower === null || greaterEqual === null || lower === greaterEqual) return { ...base, reason: "native_version_comparison_unavailable" };
    return {
      ...base, verdict: lower ? "affected" : "fixed_or_not_affected",
      reason: lower ? "native_source_version_before_fixed" : "native_source_version_at_or_after_fixed",
      fixedVersion,
    };
  }
  // Canonical lists affected source package versions separately. With no
  // fixed event, a known affected *exact* version is evidence of affectedness,
  // but another version must remain unknown (not presumed fixed).
  if (!Array.isArray(entry.versions) || entry.versions.length > 50000 || !entry.versions.every(packageVersion)) {
    return { ...base, reason: "no_fixed_version_and_affected_versions_unusable" };
  }
  return entry.versions.includes(input.sourceVersion)
    ? { ...base, verdict: "affected", reason: "exact_affected_source_version_in_ubuntu_osv" }
    : { ...base, verdict: "unknown", reason: "no_fixed_version_or_exact_affected_version" };
}
