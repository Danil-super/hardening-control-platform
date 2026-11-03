import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["debian-package-index-evidence"]);
const { summarizeDebianPackageIndexes } = await import(compiled.url("debian-package-index-evidence"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));
const os = { ID: "debian", VERSION_ID: "12", VERSION_CODENAME: "bookworm" };
const example = () => ({
  schemaVersion: 1, status: "locally_hash_matched", releaseCodename: "bookworm",
  candidateIndexes: 2, matchedIndexes: 2, missingSignedHashes: 0,
  mismatchedIndexes: 0,
  indexRecords: [
    { suite: "bookworm", component: "main", architecture: "amd64",
      releaseSha256: "a".repeat(64), packagesSha256: "b".repeat(64), packagesBytes: 123456 },
    { suite: "bookworm-security", component: "main", architecture: "amd64",
      releaseSha256: "c".repeat(64), packagesSha256: "d".repeat(64), packagesBytes: 3456 },
  ],
  verifiedAgainstLocallySignedRelease: true,
  publisherAuthenticated: false, keyringIndependentlyAuthenticated: false,
  publisherFreshnessVerified: false, installedPackageOriginVerified: false,
  remediationAuthorized: false,
  scope: "cached-debian-packages-uncompressed-sha256-locally-signed-release-v1",
});
test("signed local Packages index hash chain stays host scoped and package origin unknown", () => {
  const result = summarizeDebianPackageIndexes(example(), os);
  assert.equal(result.status, "locally_hash_matched");
  assert.equal(result.candidateIndexes, 2);
  assert.equal(result.matchedIndexes, 2);
  assert.equal(result.indexRecords.length, 2);
  assert.equal(result.verifiedAgainstLocallySignedRelease, true);
  assert.equal(result.publisherAuthenticated, false);
  assert.equal(result.keyringIndependentlyAuthenticated, false);
  assert.equal(result.publisherFreshnessVerified, false);
  assert.equal(result.installedPackageOriginVerified, false);
  assert.equal(result.remediationAuthorized, false);
  assert.match(result.note, /не удостоверены/i);
});
test("non-Debian or exact distro mismatch never inherits Debian index evidence", () => {
  for (const id of ["astra", "ubuntu", "astralinux", "debian-derived"]) {
    assert.equal(summarizeDebianPackageIndexes(example(), { ...os, ID: id, ID_LIKE: "debian" }), null);
  }
});
test("missing, partial, budget and corrupt evidence cannot assert local index integrity", () => {
  const absent = summarizeDebianPackageIndexes(undefined, os);
  assert.equal(absent.status, "not_collected");
  assert.equal(absent.verifiedAgainstLocallySignedRelease, false);
  const partial = { ...example(), status: "partial", candidateIndexes: 3, matchedIndexes: 2,
    missingSignedHashes: 1, verifiedAgainstLocallySignedRelease: false };
  assert.equal(summarizeDebianPackageIndexes(partial, os).status, "partial");
  const overBudget = { ...example(), status: "budget_exceeded", candidateIndexes: 9, matchedIndexes: 0,
    missingSignedHashes: 0, mismatchedIndexes: 0, verifiedAgainstLocallySignedRelease: false, indexRecords: [] };
  assert.equal(summarizeDebianPackageIndexes(overBudget, os).status, "budget_exceeded");
  const corrupt = { ...example(), status: "unavailable", candidateIndexes: 0, matchedIndexes: 0,
    missingSignedHashes: 0, mismatchedIndexes: 0, verifiedAgainstLocallySignedRelease: false, indexRecords: [] };
  assert.equal(summarizeDebianPackageIndexes(corrupt, os).status, "unavailable");
});
test("fake independent publisher, installed-origin claim, truncation and hash substitution are rejected", () => {
  const changes = [
    { publisherAuthenticated: true }, { keyringIndependentlyAuthenticated: true },
    { publisherFreshnessVerified: true }, { installedPackageOriginVerified: true },
    { remediationAuthorized: true }, { verifiedAgainstLocallySignedRelease: false },
    { releaseCodename: "trixie" }, { candidateIndexes: 1 }, { matchedIndexes: 1 },
    { missingSignedHashes: 1 }, { status: "unverified-but-trusted" },
    { scope: "installed-package-authorized" },
    { indexRecords: [example().indexRecords[0]] },
    { indexRecords: [{ ...example().indexRecords[0], packagesSha256: "../../etc/passwd" }, example().indexRecords[1]] },
    { indexRecords: [{ ...example().indexRecords[0], suite: "trixie" }, example().indexRecords[1]] },
    { indexRecords: [{ ...example().indexRecords[0], component: "../secret" }, example().indexRecords[1]] },
  ];
  for (const item of changes) {
    const result = summarizeDebianPackageIndexes({ ...example(), ...item }, os);
    assert.equal(result.status, "invalid", JSON.stringify(item));
    assert.equal(result.publisherAuthenticated, false);
    assert.equal(result.installedPackageOriginVerified, false);
    assert.equal(result.remediationAuthorized, false);
    assert.equal(result.verifiedAgainstLocallySignedRelease, false);
  }
});
