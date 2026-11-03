import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["debian-apt-provenance"]);
const { summarizeDebianAptRepositoryEvidence } = await import(compiled.url("debian-apt-provenance"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));
const osRelease = { ID: "debian", VERSION_ID: "12", VERSION_CODENAME: "bookworm" };
const valid = () => ({
  schemaVersion: 1, status: "observed", releaseCodename: "bookworm",
  indexEntries: 2, debianLabelEntries: 2, otherLabelEntries: 0, unknownLabelEntries: 0,
  suites: ["bookworm", "bookworm-security"], releaseLabels: ["Debian"],
  suiteConsistent: true, policySha256: "a".repeat(64),
  publisherAuthenticated: false, repositorySignatureVerified: false,
  installedPackageOriginVerified: false,
  scope: "apt-cache-policy-index-metadata-only; no-installed-origin-or-signature-attestation",
});

test("host-scoped Debian APT policy evidence never authenticates installed packages, signatures or advisories", () => {
  const result = summarizeDebianAptRepositoryEvidence(valid(), osRelease);
  assert.equal(result.state, "observed");
  assert.equal(result.indexEntries, 2);
  assert.equal(result.debianLabelEntries, 2);
  assert.deepEqual(result.suites, ["bookworm", "bookworm-security"]);
  assert.equal(result.policySha256, "a".repeat(64));
  assert.equal(result.suiteConsistent, true);
  assert.equal(result.provenanceScope, "configured-apt-indexes-only");
  assert.equal(result.publisherAuthenticated, false);
  assert.equal(result.repositorySignatureVerified, false);
  assert.equal(result.installedPackageOriginVerified, false);
  assert.match(result.note, /не подтверждение/);
});

test("foreign OS, derivatives and Ubuntu do not inherit Debian repository metadata", () => {
  for (const os of [
    { ID: "astra", ID_LIKE: "debian", VERSION_ID: "12", VERSION_CODENAME: "bookworm" },
    { ID: "ubuntu", VERSION_ID: "24.04", VERSION_CODENAME: "bookworm" },
    { ID: "debian-like", VERSION_ID: "12", VERSION_CODENAME: "bookworm" },
  ]) assert.equal(summarizeDebianAptRepositoryEvidence(valid(), os), null);
});

test("missing/ambiguous source evidence stays unverified, never becomes a clean result", () => {
  const missing = summarizeDebianAptRepositoryEvidence(undefined, osRelease);
  assert.equal(missing.state, "not_collected");
  assert.equal(missing.suiteConsistent, false);
  assert.equal(missing.installedPackageOriginVerified, false);
  const unavailable = valid();
  Object.assign(unavailable, {
    status: "unavailable", indexEntries: 0, debianLabelEntries: 0, suites: [],
    releaseLabels: [], suiteConsistent: false, policySha256: null,
  });
  assert.equal(summarizeDebianAptRepositoryEvidence(unavailable, osRelease).state, "unavailable");
  const ambiguous = { ...unavailable, status: "ambiguous", policySha256: "f".repeat(64) };
  assert.equal(summarizeDebianAptRepositoryEvidence(ambiguous, osRelease).state, "ambiguous");
});

test("forged trust, malformed counters, secret-bearing labels or mismatched release fail closed", () => {
  const cases = [
    { publisherAuthenticated: true },
    { repositorySignatureVerified: true },
    { installedPackageOriginVerified: true },
    { releaseCodename: "trixie" },
    { status: "verified" },
    { indexEntries: 1 },
    { suites: ["bookworm", "https://secrets.example"] },
    { releaseLabels: ["https://user:token@example.test"] },
    { policySha256: "../../etc/passwd" },
    { suiteConsistent: "true" },
    { scope: "signed-package-archive" },
    { schemaVersion: 2 },
  ];
  for (const change of cases) {
    const result = summarizeDebianAptRepositoryEvidence({ ...valid(), ...change }, osRelease);
    assert.equal(result.state, "invalid", JSON.stringify(change));
    assert.equal(result.publisherAuthenticated, false);
    assert.equal(result.repositorySignatureVerified, false);
    assert.equal(result.installedPackageOriginVerified, false);
    assert.equal(result.policySha256, null);
  }
});
