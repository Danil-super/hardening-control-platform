import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["debian-tracker-export"]);
const { projectDebianTrackerEvidence, assertDebianTrackerEvidenceMultiset,
  MAX_DEBIAN_TRACKER_EXPORT_RECORDS } = await import(compiled.url("debian-tracker-export"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));
const sha = "a".repeat(64);
const fullSha = "b".repeat(64);
const derivedSha = "c".repeat(64);

function finding(id = "trivy_CVE-2024-6119_one") {
  return {
    id, source: "trivy", status: "failed",
    cveApplicability: {
      verdict: "affected", distribution: { id: "debian", versionId: "12" },
      advisory: { id: "CVE-2024-6119", sourceMatch: "matched" },
      package: { name: "libssl3", installedVersion: "3.0.14-1~deb12u2", manager: "dpkg",
        provenance: "distribution-maintainer", sourceName: "openssl",
        sourceVersion: "3.0.14-1~deb12u2" },
    },
    debianTrackerPreview: {
      schemaVersion: 1, status: "provisional", reason: "source_version_at_or_after_tracker_fixed",
      candidateVerdict: "fixed_or_not_affected", trustedVerdict: "unknown",
      sourcePackage: "openssl", sourceVersion: "3.0.14-1~deb12u2",
      release: "bookworm", fixedVersion: "3.0.14-1~deb12u2",
      fullSnapshotSha256: fullSha, derivedExcerptSha256: derivedSha,
      capturedAt: "2026-11-03T14:30:00.000Z", pinMode: "observed-at-capture",
      conflictingWithTrivy: true, publisherAuthenticated: false,
      publisherFreshnessVerified: false, remediationAuthorized: false,
    },
  };
}
const sources = findings => [{ reportId: "debian-12-cve-run", reportSha256: sha, findings }];

test("preserves every original CVE×package×source-version tuple, full/excerpt hashes and disagreement", () => {
  const records = projectDebianTrackerEvidence(sources([finding("a"), finding("b")]));
  assert.equal(records.length, 2);
  assert.deepEqual(records.map(x => x.findingId), ["a", "b"]);
  assert.ok(records.every(x => x.cveId === "CVE-2024-6119" && x.sourcePackage === "openssl"));
  assert.ok(records.every(x => x.sourceReportSha256 === sha && x.fullSnapshotSha256 === fullSha && x.derivedExcerptSha256 === derivedSha));
  assert.ok(records.every(x => x.trivyApplicability === "affected" && x.candidateVerdict === "fixed_or_not_affected" && x.conflictingWithTrivy));
  assert.ok(records.every(x => x.publisherAuthenticated === false && x.publisherFreshnessVerified === false
    && x.remediationAuthorized === false && x.trustedVerdict === "unknown"));
  assertDebianTrackerEvidenceMultiset(sources([finding("a"), finding("b")]), records);
  assert.throws(() => assertDebianTrackerEvidenceMultiset(sources([finding("a"), finding("b")]), records.slice(0, 1)), /Потеря/);
  assert.throws(() => assertDebianTrackerEvidenceMultiset(sources([finding("a")]), [records[0], records[0]]), /Потеря/);
  assert.throws(() => assertDebianTrackerEvidenceMultiset(sources([finding("a")]), [{ ...records[0], sourceVersion: "0" }]), /Потеря/);
});

test("unavailable record remains unknown and never asserts a clean host", () => {
  const f = finding("missing");
  f.debianTrackerPreview = {
    ...f.debianTrackerPreview, status: "unavailable", candidateVerdict: "unknown",
    reason: "cve_not_listed_unknown_not_clean", fixedVersion: null, derivedExcerptSha256: null,
    conflictingWithTrivy: false,
  };
  const records = projectDebianTrackerEvidence(sources([f]));
  assert.equal(records.length, 1);
  assert.equal(records[0].candidateVerdict, "unknown");
  assert.equal(records[0].candidateStatus, "unavailable");
  assert.equal(records[0].derivedExcerptSha256, null);
});

test("invalid source claims, spoofed distro, wrong record status, false trust and contradictions fail closed", () => {
  const base = finding("x");
  const modify = (part, changes) => ({ ...base, [part]: { ...base[part], ...changes } });
  const scenarios = [
    modify("debianTrackerPreview", { trustedVerdict: "fixed_or_not_affected" }),
    modify("debianTrackerPreview", { publisherAuthenticated: true }),
    modify("debianTrackerPreview", { publisherFreshnessVerified: true }),
    modify("debianTrackerPreview", { remediationAuthorized: true }),
    modify("debianTrackerPreview", { derivedExcerptSha256: "../etc/passwd" }),
    modify("debianTrackerPreview", { release: "trixie" }),
    modify("debianTrackerPreview", { conflictingWithTrivy: false }),
    modify("debianTrackerPreview", { status: "unavailable" }),
    modify("debianTrackerPreview", { capturedAt: "2026-02-30T12:00:00Z" }),
    modify("cveApplicability", { distribution: { id: "astra", versionId: "12" } }),
    modify("cveApplicability", { package: { ...base.cveApplicability.package, provenance: "third-party" } }),
    modify("cveApplicability", { advisory: { ...base.cveApplicability.advisory, sourceMatch: "mismatch" } }),
  ];
  for (const scenario of scenarios) assert.throws(() => projectDebianTrackerEvidence(sources([scenario])), /Некорректное/);
  assert.throws(() => projectDebianTrackerEvidence(sources([base, base])), /Дублирующаяся/);
  assert.throws(() => projectDebianTrackerEvidence([{ ...sources([base])[0], reportSha256: "bad" }]), /идентичность/);
});

test("global bound fails entire export rather than silently dropping CVE findings", () => {
  assert.equal(MAX_DEBIAN_TRACKER_EXPORT_RECORDS, 4096);
  assert.throws(() => projectDebianTrackerEvidence(sources(
    Array.from({ length: MAX_DEBIAN_TRACKER_EXPORT_RECORDS + 1 }, (_, i) => finding("trivy-" + i))
  )), /лимит/);
});
