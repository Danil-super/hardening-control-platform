import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["vendor-crosscheck-report"]);
const { projectVendorAdvisoryEvidence, MAX_VENDOR_ADVISORY_EXPORT_RECORDS } =
  await import(compiled.url("vendor-crosscheck-report"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const sha = "a".repeat(64);
const cve = "CVE-2024-6119";

function finding(id = "trivy_CVE-2024-6119_abcdef") {
  return {
    id, source: "trivy", status: "failed",
    cveApplicability: {
      verdict: "affected",
      advisory: { id: cve },
      package: { name: "libssl3t64", installedVersion: "3.0.13-0ubuntu3", sourceName: "openssl", sourceVersion: "3.0.13-0ubuntu3" },
    },
    ubuntuOsvPreview: {
      schemaVersion: 1, status: "provisional", reason: "native_source_version_at_or_after_fixed",
      candidateVerdict: "fixed_or_not_affected", trustedVerdict: "unknown",
      sourcePackage: "openssl", sourceVersion: "3.0.13-0ubuntu3",
      snapshotSha256: "b".repeat(64), sourceRevision: "c".repeat(40),
      conflictingWithTrivy: true, publisherAuthenticated: false, remediationAuthorized: false,
    },
  };
}

test("OSV project projection preserves exact finding identities and evidence without asserting publisher trust", () => {
  const sources = [{ reportId: "host-vulnerabilities-1", reportSha256: sha, findings: [finding("trivy-1"), finding("trivy-2")] }];
  const result = projectVendorAdvisoryEvidence(sources);
  assert.equal(result.length, 2);
  assert.deepEqual(result.map(x => x.findingId), ["trivy-1", "trivy-2"]);
  assert.deepEqual(result.map(x => x.sourceReportSha256), [sha, sha]);
  assert.deepEqual(result.map(x => x.cveId), [cve, cve]);
  assert.deepEqual(result.map(x => x.candidateVerdict), ["fixed_or_not_affected", "fixed_or_not_affected"]);
  assert.ok(result.every(x => x.trivyApplicability === "affected" && x.scannerStatus === "failed"));
  assert.ok(result.every(x => x.trustedVerdict === "unknown" && x.publisherAuthenticated === false && x.remediationAuthorized === false));
  assert.equal(projectVendorAdvisoryEvidence([{ reportId: "host-other", reportSha256: sha, findings: [ { ...finding(), ubuntuOsvPreview: undefined } ] }]).length, 0);
});

test("malformed OSV projection, duplicated IDs and false authority claims fail instead of disappearing", () => {
  const base = finding();
  const source = (items) => [{ reportId: "host-vulnerabilities-1", reportSha256: sha, findings: items }];
  assert.throws(() => projectVendorAdvisoryEvidence(source([base, base])), /Повторяющийся/);
  assert.throws(() => projectVendorAdvisoryEvidence(source([{ ...base, ubuntuOsvPreview: { ...base.ubuntuOsvPreview, publisherAuthenticated: true } }])), /некорректное/);
  assert.throws(() => projectVendorAdvisoryEvidence(source([{ ...base, ubuntuOsvPreview: { ...base.ubuntuOsvPreview, trustedVerdict: "fixed_or_not_affected" } }])), /некорректное/);
  assert.throws(() => projectVendorAdvisoryEvidence(source([{ ...base, ubuntuOsvPreview: { ...base.ubuntuOsvPreview, sourceRevision: "../../etc/passwd" } }])), /некорректное/);
  assert.throws(() => projectVendorAdvisoryEvidence([{ reportId: "host-vulnerabilities-1", reportSha256: "x", findings: [base] }]), /идентичности/);
});

test("bounded export rejects overflow rather than truncating CVE records", () => {
  assert.equal(MAX_VENDOR_ADVISORY_EXPORT_RECORDS, 4096);
  const records = Array.from({ length: MAX_VENDOR_ADVISORY_EXPORT_RECORDS + 1 }, (_, i) => finding("trivy-" + String(i)));
  assert.throws(() => projectVendorAdvisoryEvidence([{ reportId: "host-vulnerabilities-1", reportSha256: sha, findings: records }]), /Лимит/);
});
