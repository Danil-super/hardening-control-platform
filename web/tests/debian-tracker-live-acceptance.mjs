/**
 * Disposable live compatibility acceptance of an actual Debian Security Tracker
 * export. This is deliberately NOT a unit test, scheduled updater or authority
 * claim. Run from the controlled GitHub Action or manually on a disposable host.
 *
 * No raw tracker data or private host inventory is written to CI artifacts.
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["debian-tracker-snapshot"]);
const stateRoot = mkdtempSync(path.join(tmpdir(), "hcp-debian-live-"));
const log = (key, value) => console.log(JSON.stringify({ stage: key, ...value }));

try {
  const {
    DEBIAN_TRACKER_URL, importDebianTrackerFullSnapshot,
    readPinnedDebianTrackerFullSnapshot, evaluatePinnedDebianTrackerFullSnapshot,
  } = await import(compiled.url("debian-tracker-snapshot"));
  const manifest = await importDebianTrackerFullSnapshot({ stateRoot });
  assert.equal(manifest.sourceUrl, DEBIAN_TRACKER_URL);
  assert.match(manifest.sha256, /^[a-f0-9]{64}$/);
  assert.equal(manifest.pinMode, "observed-at-capture");
  assert.equal(manifest.publisherAuthenticated, false);
  assert.equal(manifest.publisherFreshnessVerified, false);
  assert.equal(manifest.remediationAuthorized, false);
  assert.ok(manifest.sourcePackageCount > 1000, "Unexpectedly small full export");
  assert.ok(manifest.issueCount > manifest.sourcePackageCount, "Unexpectedly sparse full export");
  log("download-and-immutable-capture", {
    sha256: manifest.sha256, bytes: manifest.bytes,
    sourcePackageCount: manifest.sourcePackageCount, issueCount: manifest.issueCount,
    pinMode: manifest.pinMode, publisherAuthenticated: manifest.publisherAuthenticated,
  });

  const { data, manifest: stored } = readPinnedDebianTrackerFullSnapshot(stateRoot, manifest.sha256);
  assert.deepEqual(stored, manifest);
  assert.ok(data.openssl && typeof data.openssl === "object", "Real openssl source package not found");
  const cve = data.openssl["CVE-2024-6119"];
  assert.ok(cve && typeof cve === "object", "Real openssl/CVE-2024-6119 not found");
  assert.ok(cve.releases?.bookworm, "Debian 12/bookworm CVE release missing");
  const observed = cve.releases.bookworm;
  log("actual-debian-advisory-record", {
    sourcePackage: "openssl", cveId: "CVE-2024-6119",
    release: "bookworm", status: observed.status,
    fixedVersion: observed.fixed_version ?? null,
  });

  const evaluate = sourceVersion => evaluatePinnedDebianTrackerFullSnapshot({
    stateRoot, snapshotSha256: manifest.sha256, osId: "debian",
    inventoryComplete: true, sourcePackage: "openssl",
    cveId: "CVE-2024-6119", release: "bookworm", sourceVersion,
  });
  const before = evaluate("3.0.14-1~deb12u1");
  const fixed = evaluate("3.0.14-1~deb12u2");
  const wrongDistro = evaluatePinnedDebianTrackerFullSnapshot({
    stateRoot, snapshotSha256: manifest.sha256, osId: "ubuntu",
    inventoryComplete: true, sourcePackage: "openssl",
    cveId: "CVE-2024-6119", release: "bookworm", sourceVersion: "3.0.14-1~deb12u2",
  });
  for (const result of [before, fixed, wrongDistro]) {
    assert.equal(result.trustedVerdict, "unknown");
    assert.equal(result.publisherAuthenticated, false);
    assert.equal(result.publisherFreshnessVerified, false);
    assert.equal(result.remediationAuthorized, false);
  }
  assert.equal(wrongDistro.status, "unavailable");
  assert.equal(wrongDistro.candidateVerdict, "unknown");
  assert.equal(wrongDistro.reason, "unsupported_exact_os_identity");
  assert.equal(before.fullSnapshotSha256, manifest.sha256);
  assert.equal(fixed.fullSnapshotSha256, manifest.sha256);
  assert.match(before.derivedExcerptSha256, /^[a-f0-9]{64}$/);
  assert.equal(before.derivedExcerptSha256, fixed.derivedExcerptSha256);
  assert.equal(before.candidateVerdict, "affected",
    "Unexpected Debian source version applicability: review live tracker status/threshold");
  assert.equal(fixed.candidateVerdict, "fixed_or_not_affected",
    "Expected historical Debian fixed source version must pass");
  log("native-source-backport-crosscheck", {
    before: before.candidateVerdict, after: fixed.candidateVerdict,
    observedFixedVersion: fixed.fixedVersion,
    excerptSha256: fixed.derivedExcerptSha256,
    trustedVerdict: fixed.trustedVerdict, remediationAuthorized: fixed.remediationAuthorized,
  });
} finally {
  rmSync(stateRoot, { force: true, recursive: true });
  rmSync(compiled.directory, { force: true, recursive: true });
}
