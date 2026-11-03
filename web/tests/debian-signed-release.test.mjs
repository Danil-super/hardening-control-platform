import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["debian-signed-release"]);
const { summarizeDebianSignedReleases } = await import(compiled.url("debian-signed-release"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const os = { ID: "debian", VERSION_ID: "12", VERSION_CODENAME: "bookworm" };
const valid = () => ({
  schemaVersion: 1, status: "verified_with_local_keyring",
  releaseCodename: "bookworm", candidateFiles: 2, validLocalSignatures: 2,
  invalidOrUnverifiable: 0, signedReleases: ["bookworm", "bookworm-security"],
  signerFingerprints: ["a".repeat(40)], inReleaseSha256: ["b".repeat(64), "c".repeat(64)],
  localKeyringSha256: "d".repeat(64), localSignatureVerified: true,
  publisherAuthenticated: false, publisherFreshnessVerified: false,
  packageIndexHashesVerified: false, installedPackageOriginVerified: false,
  remediationAuthorized: false,
  scope: "cached-inrelease-gpgv-installed-archive-keyring-only",
});

test("local InRelease gpgv state is never certified Debian publisher or installed package provenance", () => {
  const evidence = summarizeDebianSignedReleases(valid(), os);
  assert.equal(evidence.status, "verified_with_local_keyring");
  assert.equal(evidence.validLocalSignatures, 2);
  assert.equal(evidence.localSignatureVerified, true);
  assert.equal(evidence.publisherAuthenticated, false);
  assert.equal(evidence.publisherFreshnessVerified, false);
  assert.equal(evidence.packageIndexHashesVerified, false);
  assert.equal(evidence.installedPackageOriginVerified, false);
  assert.equal(evidence.remediationAuthorized, false);
  assert.deepEqual(evidence.signedReleases, ["bookworm", "bookworm-security"]);
  assert.match(evidence.note, /не установлена/);
});

test("Astra, Ubuntu and derivative OS cannot inherit the Debian local keyring", () => {
  for (const id of ["astra", "astralinux", "ubuntu", "custom"]) {
    assert.equal(summarizeDebianSignedReleases(valid(), { ...os, ID: id, ID_LIKE: "debian" }), null);
  }
});

test("missing, failed or old collection cannot be interpreted as a verified signature", () => {
  const missing = summarizeDebianSignedReleases(undefined, os);
  assert.equal(missing.status, "not_collected");
  assert.equal(missing.localSignatureVerified, false);
  const absent = { ...valid(), status: "unavailable", candidateFiles: 0, validLocalSignatures: 0,
    invalidOrUnverifiable: 0, signedReleases: [], signerFingerprints: [], inReleaseSha256: [],
    localSignatureVerified: false, localKeyringSha256: null };
  assert.equal(summarizeDebianSignedReleases(absent, os).status, "unavailable");
  const partial = { ...valid(), status: "partial", validLocalSignatures: 1, invalidOrUnverifiable: 1,
    inReleaseSha256: ["b".repeat(64)], localSignatureVerified: false };
  assert.equal(summarizeDebianSignedReleases(partial, os).status, "partial");
  assert.equal(summarizeDebianSignedReleases(partial, os).packageIndexHashesVerified, false);
});

test("spurious authority, unsupported release or tampered digest fails entirely", () => {
  const changes = [
    { publisherAuthenticated: true }, { publisherFreshnessVerified: true },
    { packageIndexHashesVerified: true }, { installedPackageOriginVerified: true },
    { remediationAuthorized: true }, { localSignatureVerified: false },
    { validLocalSignatures: 1 }, { candidateFiles: 0 }, { inReleaseSha256: [] },
    { signerFingerprints: ["../../private"] }, { signedReleases: ["trixie"] },
    { localKeyringSha256: "not-a-digest" }, { status: "trusted" },
    { scope: "official-debian-package-authenticated" },
  ];
  for (const change of changes) {
    const result = summarizeDebianSignedReleases({ ...valid(), ...change }, os);
    assert.equal(result.status, "invalid", JSON.stringify(change));
    assert.equal(result.localSignatureVerified, false);
    assert.equal(result.publisherAuthenticated, false);
    assert.equal(result.installedPackageOriginVerified, false);
  }
});
