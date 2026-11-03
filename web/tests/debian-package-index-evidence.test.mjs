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

const exampleCandidates = () => ({
  schemaVersion: 1, status: "candidate_record_match",
  eligibleInstalled: 125, exactInstalledVersionCandidates: 73,
  matchedIdentitySha256: "e".repeat(64),
  scope: "installed-dpkg-version-in-locally-verified-Packages-record-v1",
  publisherAuthenticated: false, installedPackageOriginVerified: false,
  remediationAuthorized: false,
});
test("exact installed-version candidates are projected without package-origin authority", () => {
  const candidate = summarizeDebianPackageIndexes(
    { ...example(), installedVersionCandidates: exampleCandidates() }, os);
  assert.equal(candidate.status, "locally_hash_matched");
  assert.equal(candidate.installedVersionCandidates?.status, "candidate_record_match");
  assert.equal(candidate.installedVersionCandidates?.exactInstalledVersionCandidates, 73);
  assert.equal(candidate.installedVersionCandidates?.eligibleInstalled, 125);
  assert.equal(candidate.installedVersionCandidates?.publisherAuthenticated, false);
  assert.equal(candidate.installedVersionCandidates?.installedPackageOriginVerified, false);
  assert.equal(candidate.installedVersionCandidates?.remediationAuthorized, false);
  // Vulnerability browser revalidates an already projected CVE report value.
  assert.deepEqual(summarizeDebianPackageIndexes(candidate, os), candidate);
});
test("candidate evidence rejects forged trust flags, count inflation and incomplete hash gates", () => {
  const modifications = [
    { publisherAuthenticated: true }, { installedPackageOriginVerified: true },
    { remediationAuthorized: true }, { exactInstalledVersionCandidates: 126 },
    { eligibleInstalled: -1 }, { matchedIdentitySha256: "../../secret" },
    { scope: "installed-deb-is-authentic" }, { status: "validated-installed-archive" },
  ];
  for (const mutation of modifications) {
    const result = summarizeDebianPackageIndexes(
      { ...example(), installedVersionCandidates: { ...exampleCandidates(), ...mutation } }, os);
    assert.equal(result.status, "invalid", JSON.stringify(mutation));
    assert.equal(result.installedPackageOriginVerified, false);
  }
  const partial = { ...example(), status: "partial", candidateIndexes: 3,
    matchedIndexes: 2, missingSignedHashes: 1, verifiedAgainstLocallySignedRelease: false,
    installedVersionCandidates: exampleCandidates() };
  assert.equal(summarizeDebianPackageIndexes(partial, os).status, "invalid");
  const noMatch = { ...exampleCandidates(), status: "no_exact_match",
    exactInstalledVersionCandidates: 0 };
  assert.equal(summarizeDebianPackageIndexes(
    { ...example(), installedVersionCandidates: noMatch }, os).installedVersionCandidates?.status,
  "no_exact_match");
});

const archiveExample = () => ({
  schemaVersion: 1, status: "locally_hash_matched",
  eligibleInstalled: 125, candidateArchives: 2, matchedArchives: 2,
  mismatchedArchives: 0, missingIndexHashes: 0, ambiguousIndexHashes: 0,
  verifiedArchiveSha256: ["a".repeat(64), "b".repeat(64)],
  scope: "cached-deb-sha256-locally-verified-Packages-record-only-v1",
  publisherAuthenticated: false, installedPackageOriginVerified: false,
  remediationAuthorized: false,
});
test("bounded cached .deb digests survive strict CVE projection without claiming installed origin", () => {
  const input = { ...example(), installedVersionCandidates: exampleCandidates(),
    cachedArchiveEvidence: archiveExample() };
  const result = summarizeDebianPackageIndexes(input, os);
  assert.equal(result.status, "locally_hash_matched");
  assert.equal(result.cachedArchiveEvidence?.status, "locally_hash_matched");
  assert.equal(result.cachedArchiveEvidence?.matchedArchives, 2);
  assert.equal(result.cachedArchiveEvidence?.verifiedArchiveSha256.length, 2);
  assert.equal(result.cachedArchiveEvidence?.publisherAuthenticated, false);
  assert.equal(result.cachedArchiveEvidence?.installedPackageOriginVerified, false);
  assert.equal(result.cachedArchiveEvidence?.remediationAuthorized, false);
  assert.deepEqual(summarizeDebianPackageIndexes(result, os), result);
});
test("cached archives cannot forge authority, unbounded counts or partial successes", () => {
  for (const change of [
    { publisherAuthenticated: true }, { installedPackageOriginVerified: true },
    { remediationAuthorized: true }, { matchedArchives: 3 },
    { candidateArchives: -1 }, { verifiedArchiveSha256: ["../../etc/passwd"] },
    { verifiedArchiveSha256: ["f".repeat(64)] }, { scope: "signed-installed-package" },
    { status: "authenticated-origin" },
  ]) {
    const result = summarizeDebianPackageIndexes(
      { ...example(), cachedArchiveEvidence: { ...archiveExample(), ...change } }, os);
    assert.equal(result.status, "invalid", JSON.stringify(change));
  }
  const noCache = { ...archiveExample(), status: "no_cached_archives",
    candidateArchives: 0, matchedArchives: 0, verifiedArchiveSha256: [] };
  assert.equal(summarizeDebianPackageIndexes(
    { ...example(), cachedArchiveEvidence: noCache }, os).cachedArchiveEvidence?.status,
  "no_cached_archives");
  const partial = { ...example(), status: "partial", verifiedAgainstLocallySignedRelease: false,
    candidateIndexes: 3, missingSignedHashes: 1, cachedArchiveEvidence: archiveExample() };
  assert.equal(summarizeDebianPackageIndexes(partial, os).status, "invalid");
});
