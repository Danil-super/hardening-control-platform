import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ubuntu-pinned-crosscheck"]);
const { evaluatePinnedUbuntuCrossCheck } = await import(compiled.url("ubuntu-pinned-crosscheck"));
const { importPinnedUbuntuOsvSnapshot } = await import(compiled.url("vendor-advisory-snapshot"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

// Deliberately local contract fixtures; no claim that these bytes were signed
// or delivered by Canonical.
function fixture(t, { fixedVersion = "3.0.13-0ubuntu3.4" } = {}) {
  const root = mkdtempSync(path.join(tmpdir(), "hcp-ubuntu-vendor-bridge-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const id = "UBUNTU-CVE-2024-6119";
  const osv = {
    schema_version: "1.7.0", id, upstream: ["CVE-2024-6119"],
    affected: [{
      package: { name: "openssl", ecosystem: "Ubuntu:24.04:LTS" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, ...(fixedVersion ? [{ fixed: fixedVersion }] : [])] }],
      versions: ["3.0.13-0ubuntu3", "3.0.13-0ubuntu3.1"],
    }],
  };
  const rawJson = JSON.stringify(osv);
  const sha256 = createHash("sha256").update(rawJson).digest("hex");
  importPinnedUbuntuOsvSnapshot({ root, recordId: id, rawJson, expectedSha256: sha256 });
  const input = {
    stateRoot: root, snapshotSha256: sha256,
    osId: "ubuntu", release: "24.04", cveId: "CVE-2024-6119",
    sourcePackage: "openssl", sourceVersion: "3.0.13-0ubuntu3",
    inventoryComplete: true,
  };
  return { root, sha256, rawJson, input, check: (override = {}) => evaluatePinnedUbuntuCrossCheck({ ...input, ...override }) };
}

test("pinned snapshot + real dpkg compare yields provisional affected, never verified", t => {
  const f = fixture(t);
  const check = f.check();
  assert.equal(check.status, "provisional");
  assert.equal(check.candidateVerdict, "affected");
  assert.equal(check.trustedVerdict, "unknown");
  assert.equal(check.evaluation.sourcePackage, "openssl");
  assert.equal(check.evaluation.fixedVersion, "3.0.13-0ubuntu3.4");
  assert.equal(check.snapshotSha256, f.sha256);
  assert.equal(check.publisherAuthenticated, false);
  assert.equal(check.publisherFreshnessVerified, false);
  assert.equal(check.publishedAt, null);
  assert.equal(check.remediationAuthorized, false);
});

test("backported fixed version is provisional, not authorization for remediation", t => {
  const f = fixture(t);
  for (const version of ["3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.10", "1:3.0.13-0ubuntu3"]) {
    const check = f.check({ sourceVersion: version });
    assert.equal(check.candidateVerdict, "fixed_or_not_affected");
    assert.equal(check.trustedVerdict, "unknown");
    assert.equal(check.remediationAuthorized, false);
  }
});

test("exact OS and release, source rather than binary name, and complete inventory are required", t => {
  const f = fixture(t);
  assert.equal(f.check({ osId: "astra" }).reason, "unsupported_exact_os_identity");
  assert.equal(f.check({ inventoryComplete: false }).reason, "incomplete_source_inventory");
  assert.equal(f.check({ sourcePackage: "libssl3t64" }).candidateVerdict, "unknown");
  assert.equal(f.check({ release: "22.04" }).candidateVerdict, "unknown");
  assert.equal(f.check({ cveId: "CVE-2025-12345" }).reason, "advisory_identity_mismatch");
});

test("no fixed event yields only a provisional needs-review decision", t => {
  const f = fixture(t, { fixedVersion: null });
  assert.equal(f.check().candidateVerdict, "needs_review");
  assert.equal(f.check().trustedVerdict, "unknown");
  assert.equal(f.check({ sourceVersion: "3.0.13-0ubuntu3.9" }).candidateVerdict, "unknown");
});

test("corrupted stored advisory cannot be interpreted as an official clean verdict", t => {
  const f = fixture(t);
  const filename = path.join(f.root, "vendor-advisory-snapshots", "v1", f.sha256 + ".json");
  writeFileSync(filename, f.rawJson + " ", "utf8");
  const check = f.check();
  assert.equal(check.status, "unavailable");
  assert.equal(check.candidateVerdict, "unknown");
  assert.equal(check.trustedVerdict, "unknown");
  assert.equal(check.reason, "pinned_snapshot_unavailable_or_invalid");
});

test("invalid future import time cannot create a trusted advisory assessment", t => {
  const f = fixture(t);
  const manifest = path.join(f.root, "vendor-advisory-snapshots", "v1", f.sha256 + ".manifest.json");
  const payload = JSON.parse(readFileSync(manifest, "utf8"));
  payload.importedAt = "2099-01-01T00:00:00Z";
  writeFileSync(manifest, JSON.stringify(payload));
  const check = f.check();
  assert.equal(check.status, "unavailable");
  assert.equal(check.reason, "invalid_import_timestamp");
  assert.equal(check.remediationAuthorized, false);
});
