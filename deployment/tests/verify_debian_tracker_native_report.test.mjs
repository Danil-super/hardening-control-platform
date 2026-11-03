import assert from "node:assert/strict";
import test from "node:test";
import { checkNativeSources, checkSyntheticControl } from "./verify_debian_tracker_native_report.mjs";

const source = () => ({
  mode: "packages",
  packageInventory: {
    manager: "dpkg", osRelease: { ID: "debian", VERSION_ID: "12", VERSION_CODENAME: "bookworm" },
    packageCount: 2, partial: false,
    debianSignedReleases: { schemaVersion: 1, status: "verified_with_local_keyring",
      candidateFiles: 1, validLocalSignatures: 1, localSignatureVerified: true,
      localKeyringSha256: "d".repeat(64), inReleaseSha256: ["b".repeat(64)],
      publisherAuthenticated: false, publisherFreshnessVerified: false,
      packageIndexHashesVerified: false, installedPackageOriginVerified: false,
      remediationAuthorized: false },
    debianPackageIndexes: {
      schemaVersion: 1, status: "locally_hash_matched",
      candidateIndexes: 1, matchedIndexes: 1, missingSignedHashes: 0, mismatchedIndexes: 0,
      indexRecords: [{ suite: "bookworm", component: "main", architecture: "amd64",
        releaseSha256: "b".repeat(64), packagesSha256: "e".repeat(64), packagesBytes: 100 }],
      verifiedAgainstLocallySignedRelease: true,
      installedVersionCandidates: {
        schemaVersion: 1, status: "candidate_record_match",
        eligibleInstalled: 2, exactInstalledVersionCandidates: 2,
        matchedIdentitySha256: "f".repeat(64),
        scope: "installed-dpkg-version-in-locally-verified-Packages-record-v1",
        publisherAuthenticated: false, installedPackageOriginVerified: false,
        remediationAuthorized: false,
      },
      cachedArchiveEvidence: {
        schemaVersion: 1, status: "no_cached_archives",
        eligibleInstalled: 2, candidateArchives: 0, matchedArchives: 0,
        mismatchedArchives: 0, missingIndexHashes: 0, ambiguousIndexHashes: 0,
        verifiedArchiveSha256: [],
        scope: "cached-deb-sha256-locally-verified-Packages-record-only-v1",
        publisherAuthenticated: false, installedPackageOriginVerified: false,
        remediationAuthorized: false,
      },
      publisherAuthenticated: false, keyringIndependentlyAuthenticated: false,
      publisherFreshnessVerified: false, installedPackageOriginVerified: false,
      remediationAuthorized: false,
    },
    aptRepositories: { schemaVersion: 1, status: "observed", releaseCodename: "bookworm",
      indexEntries: 1, policySha256: "a".repeat(64),
      publisherAuthenticated: false, repositorySignatureVerified: false,
      installedPackageOriginVerified: false },
  },
  packages: [
    { name: "libssl3:amd64", manager: "dpkg", sourceName: "openssl",
      sourceVersion: "3.0.14-1~deb12u2", sourceEpochKnown: true,
      dpkgStatus: "ii ", maintainer: "Debian OpenSSL Team", origin: "" },
    { name: "openssl:amd64", manager: "dpkg", sourceName: "openssl",
      sourceVersion: "3.0.14-1~deb12u2", sourceEpochKnown: true,
      dpkgStatus: "ii ", maintainer: "Debian OpenSSL Team", origin: "" },
  ],
});
const protocol = () => ({
  status: "passed", distribution: "debian", acceleration: "kvm",
  syntheticOsIdentity: false, publicationPrivacyVerified: true,
  checks: [{ name: "Production dpkg collector equals all eight independent native fields",
    detail: { allEightNativeFieldsEqual: true } },
    { name: "Debian APT index metadata SHA equals independent native apt-cache policy",
      detail: { sha256: "a".repeat(64), repositorySignatureVerified: false,
        installedPackageOriginVerified: false } },
    { name: "Cached Debian InRelease signatures verified by native gpgv with local keyring only",
      detail: { localKeyringSha256: "d".repeat(64), inReleaseSha256: ["b".repeat(64)] } },
    { name: "Native installed dpkg versions have exact matching records in hash-verified cached Packages",
      detail: { eligibleInstalled: 2, exactInstalledVersionCandidates: 2,
        matchedIdentitySha256: "f".repeat(64), publisherAuthenticated: false,
        installedPackageOriginVerified: false, remediationAuthorized: false } },
    { name: "Native optional cached Debian archives preserve conservative local SHA256 evidence",
      detail: { status: "no_cached_archives", candidateArchives: 0, matchedArchives: 0,
        verifiedArchiveSha256: [], installedPackageOriginVerified: false,
        remediationAuthorized: false } },
    { name: "Native Debian cached Packages SHA256 matches locally signed InRelease records",
      detail: { matchedIndexes: 1,
        verifiedIndexes: [{ suite: "bookworm", component: "main", architecture: "amd64",
          releaseSha256: "b".repeat(64), packagesSha256: "e".repeat(64), packagesBytes: 100 }] } }],
});
const labelled = () => ({
  inventoryHost: "acceptance-debian-control-vulnerable",
  packageInventory: { osRelease: { ID: "debian", VERSION_CODENAME: "bookworm" } },
  acceptanceFixture: {
    synthetic: true, installedPackage: false, cve: "CVE-2024-6119", expectedCve: true,
  },
  packages: [{ sourceName: "openssl", sourceVersion: "3.0.14-1~deb12u1" }],
});
const matching = () => ({
  status: "passed", nativeInventoryEvaluated: true, controlsOnly: false,
  cases: [{ name: "control-vulnerable", nativeMatches: [{}], hcpMatches: [{}] }],
});

test("requires independently checked, actual guest dpkg source versions and never authenticates publisher", () => {
  const result = checkNativeSources(source(), protocol());
  assert.equal(result.recordCount, 2);
  assert.deepEqual(result.versions, ["3.0.14-1~deb12u2"]);
  assert.equal(result.publisherSignedPackageProvenanceVerified, false);
  assert.equal(result.aptPolicySha256, "a".repeat(64));
  assert.equal(result.locallyVerifiedSignatures, 1);
  assert.equal(result.localKeyringSha256, "d".repeat(64));
  assert.equal(result.verifiedLocalPackageIndexes, 1);
  assert.equal(result.exactInstalledVersionCandidates, 2);
  assert.equal(result.locallyMatchedCachedArchives, 0);
});
test("never treats an Ubuntu/Astra identity, incomplete inventory or fake VM as native Debian proof", () => {
  for (const changed of [
    { packageInventory: { ...source().packageInventory, osRelease: { ID: "astra", VERSION_ID: "12", VERSION_CODENAME: "bookworm" } } },
    { packageInventory: { ...source().packageInventory, partial: true } },
    { packageInventory: { ...source().packageInventory, packageCount: 1 } },
  ]) assert.throws(() => checkNativeSources({ ...source(), ...changed }, protocol()));
  for (const vm of [
    { ...protocol(), syntheticOsIdentity: true },
    { ...protocol(), publicationPrivacyVerified: false },
    { ...protocol(), checks: [] },
  ]) assert.throws(() => checkNativeSources(source(), vm));
});
test("rejects missing source package, unavailable native source epoch or unconfigured dpkg records", () => {
  const noOpenSsl = source();
  noOpenSsl.packages.forEach(x => { x.sourceName = "other"; });
  assert.throws(() => checkNativeSources(noOpenSsl, protocol()));
  for (const change of [{ sourceEpochKnown: false }, { sourceVersion: "3.0.14;echo" },
    { dpkgStatus: "rc " }, { maintainer: "" }]) {
    const invalid = source();
    Object.assign(invalid.packages[0], change);
    assert.throws(() => checkNativeSources(invalid, protocol()));
  }
});
test("APT metadata cannot create signed installed-package provenance in the native gate", () => {
  for (const apt of [
    { ...source().packageInventory.aptRepositories, repositorySignatureVerified: true },
    { ...source().packageInventory.aptRepositories, installedPackageOriginVerified: true },
    { ...source().packageInventory.aptRepositories, policySha256: "f".repeat(64) },
  ]) {
    const inv = source();
    inv.packageInventory.aptRepositories = apt;
    assert.throws(() => checkNativeSources(inv, protocol()));
  }
  assert.throws(() => checkNativeSources(source(), {
    ...protocol(), checks: protocol().checks.slice(0, 1),
  }));
});

test("native local signatures never authorize issuer authenticity or package origin", () => {
  for (const change of [{ publisherAuthenticated: true }, { packageIndexHashesVerified: true },
    { installedPackageOriginVerified: true }, { remediationAuthorized: true },
    { localKeyringSha256: "a".repeat(64) }, { localSignatureVerified: false }]) {
    const native = source();
    native.packageInventory.debianSignedReleases = {
      ...native.packageInventory.debianSignedReleases, ...change,
    };
    assert.throws(() => checkNativeSources(native, protocol()));
  }
  const vm = protocol();
  vm.checks.pop();
  assert.throws(() => checkNativeSources(source(), vm));
});

test("native signed Packages SHA256 evidence cannot assert installed archive or publisher authenticity", () => {
  for (const change of [
    { publisherAuthenticated: true },
    { keyringIndependentlyAuthenticated: true },
    { installedPackageOriginVerified: true },
    { remediationAuthorized: true },
    { verifiedAgainstLocallySignedRelease: false },
    { installedVersionCandidates: { ...source().packageInventory.debianPackageIndexes.installedVersionCandidates,
      installedPackageOriginVerified: true } },
    { cachedArchiveEvidence: { ...source().packageInventory.debianPackageIndexes.cachedArchiveEvidence,
      installedPackageOriginVerified: true } },
    { indexRecords: [{ ...source().packageInventory.debianPackageIndexes.indexRecords[0], packagesSha256: "f".repeat(64) }] },
  ]) {
    const native = source();
    native.packageInventory.debianPackageIndexes = { ...native.packageInventory.debianPackageIndexes, ...change };
    assert.throws(() => checkNativeSources(native, protocol()));
  }
  assert.throws(() => checkNativeSources(source(), {
    ...protocol(), checks: protocol().checks.slice(0, 2),
  }));
});

test("synthetic vulnerable metadata remains labelled and cannot pose as an installed VM package", () => {
  assert.equal(checkSyntheticControl(labelled(), matching()), 1);
  assert.throws(() => checkSyntheticControl({ ...labelled(), acceptanceFixture: {
    ...labelled().acceptanceFixture, installedPackage: true,
  } }, matching()));
  assert.throws(() => checkSyntheticControl({ ...labelled(), acceptanceFixture: {
    ...labelled().acceptanceFixture, synthetic: false,
  } }, matching()));
  assert.throws(() => checkSyntheticControl({ ...labelled(), packages: [
    { sourceName: "openssl", sourceVersion: "3.0.14-1~deb12u2" },
  ] }, matching()));
  assert.throws(() => checkSyntheticControl(labelled(), { ...matching(), controlsOnly: true }));
  assert.throws(() => checkSyntheticControl(labelled(), { ...matching(), cases: [] }));
});
