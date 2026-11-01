import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertFindingConservation, assertPackageConservation, controlInventory, labelledCases, releaseMatchesControl } from "./verify_linux_packages.mjs";

const fixtures = JSON.parse(readFileSync(new URL("fixtures/linux-package-controls.json", import.meta.url), "utf8"));

test("Debian controls preserve independent source epochs and never fabricate RPM metadata", () => {
  const inventory = controlInventory(fixtures.controls.debian, "epoch", "1:3.0.14-1~deb12u1", { sourceVersion: "2:3.0.14-1~deb12u2" });
  const pkg = inventory.packages[0];
  assert.equal(pkg.name, "libssl3:amd64");
  assert.equal(pkg.version, "1:3.0.14-1~deb12u1");
  assert.equal(pkg.sourceVersion, "2:3.0.14-1~deb12u2");
  assert.equal(pkg.sourceEpochKnown, true);
  assert.equal(pkg.dpkgStatus, "ii ");
  assert.equal(pkg.origin, "");
  for (const field of ["sourceRpm", "vendor", "modularityLabel", "rpmModularityQueried", "rpmRepositoryEvidence", "apkOrigin"]) assert.equal(pkg[field], undefined);
  assert.equal(inventory.acceptanceFixture.synthetic, true);
  assert.equal(inventory.acceptanceFixture.installedPackage, false);
});

test("existing APK and RPM controls keep their ecosystem-specific metadata and case counts", () => {
  const apk = controlInventory(fixtures.controls.alpine, "vulnerable", fixtures.controls.alpine.vulnerableVersion);
  assert.equal(apk.packages[0].sourceVersion, "3.5.1-r0");
  assert.equal(apk.packages[0].apkOrigin, "openssl");
  assert.equal(apk.packageInventory.apkRepositories.branches[0], "v3.22");
  assert.equal(labelledCases(fixtures.controls.alpine).length, 2);
  for (const family of ["alma", "rocky"]) {
    const control = fixtures.controls[family];
    const rpm = controlInventory(control, "vulnerable", control.vulnerableVersion).packages[0];
    assert.equal(rpm.version, "1:3.0.1-46.el9_1");
    assert.equal(rpm.sourceVersion, "3.0.1-46.el9_1");
    assert.equal(rpm.sourceEpochKnown, false);
    assert.equal(rpm.sourceRpm, "openssl-3.0.1-46.el9_1.src.rpm");
    assert.equal(rpm.vendor, control.vendor);
    assert.equal(rpm.rpmModularityQueried, true);
    const cases = labelledCases(control);
    assert.equal(cases.length, 3);
    assert.equal(cases[2].input.packages[1].name, "gpg-pubkey");
  }
});

test("release applicability requires exact Debian and Ubuntu releases while retaining APK/RPM branch rules", () => {
  for (const [family, accepted, rejected] of [
    ["debian", ["12"], ["11", "13", "12.1", "bookworm"]],
    ["ubuntu", ["24.04"], ["24", "24.10", "22.04", "24.04.1", "noble"]],
    ["alpine", ["3.22", "3.22.6"], ["3.2", "3.23", "edge"]],
    ["alma", ["9", "9.7"], ["8", "10"]],
    ["rocky", ["9", "9.7"], ["8", "10"]],
  ]) {
    for (const versionId of accepted) assert.equal(releaseMatchesControl({ versionId }, fixtures.controls[family]), true, `${family}:${versionId}`);
    for (const versionId of rejected) assert.equal(releaseMatchesControl({ versionId }, fixtures.controls[family]), false, `${family}:${versionId}`);
  }
});

test("Debian-family metadata controls are separately labelled and retain exact multiarch/source observations", () => {
  for (const family of ["debian", "ubuntu"]) {
    const control = fixtures.controls[family];
    const cases = labelledCases(control);
    assert.equal(cases.length, 9);
    assert.ok(cases.every((item) => item.input.acceptanceFixture.synthetic && item.input.acceptanceFixture.installedPackage === false));
    const byName = Object.fromEntries(cases.map((item) => [item.name, item]));
    assert.equal(byName["control-vulnerable"].input.acceptanceFixture.kind, "vendor-advisory-boundary");
    const multiarch = byName["control-multiarch-vulnerable"].input;
    assert.deepEqual(multiarch.packages.map(({ name, version, arch }) => [name, version, arch]), [
      [`${control.packageName}:amd64`, control.vulnerableVersion, "amd64"],
      [`${control.packageName}:i386`, control.vulnerableVersion, "i386"],
    ]);
    assert.equal(multiarch.packageInventory.packageCount, 2);
    const divergence = byName["control-source-vulnerable-binary-fixed"].input.packages[0];
    assert.equal(divergence.version, control.fixedVersion);
    assert.equal(divergence.sourceVersion, control.vulnerableVersion);
    const epoch = byName["control-source-epoch"].input.packages[0];
    assert.equal(epoch.version, `1:${control.vulnerableVersion}`);
    assert.equal(epoch.sourceVersion, `1:${control.vulnerableVersion}`);
    for (const item of cases.slice(2)) assert.equal(item.input.acceptanceFixture.kind, "synthetic-metadata-interpretation");
    assert.equal(byName["control-unknown-supplier"].applicabilityUnverified, true);
    assert.equal(byName["control-third-party-supplier"].expectedProvenance, "third-party");
    assert.equal(byName["control-third-party-supplier"].input.packages[0].origin, "Independent acceptance repository");
  }
});

// Contract fixture follows the actual pinned native decoder shape: DEB binary
// Version contains its revision, while source properties have separate fields.
// Real engine acceptance is the CLI's responsibility, not this unit fixture.
function packageTrace() {
  const inventory = controlInventory(fixtures.controls.debian, "fixture", "1:3.0.14-1~deb12u1");
  const pkg = inventory.packages[0];
  const ref = "pkg:deb/debian/libssl3@3.0.14-1~deb12u1?arch=amd64&distro=debian-12&epoch=1";
  const properties = {
    "hcp:package-manager": "dpkg", "hcp:architecture": "amd64", "hcp:dpkg-status": "ii ", "hcp:maintainer": pkg.maintainer,
    "aquasecurity:trivy:PkgID": ref, "aquasecurity:trivy:SrcName": "openssl", "aquasecurity:trivy:SrcVersion": "3.0.14",
    "aquasecurity:trivy:SrcRelease": "1~deb12u1", "aquasecurity:trivy:SrcEpoch": "1",
  };
  const sbom = { metadata: { component: { name: "debian" } }, components: [{ name: "libssl3", version: pkg.version,
    "bom-ref": ref, purl: ref, supplier: { name: pkg.maintainer }, properties: Object.entries(properties).map(([name, value]) => ({ name, value })) }] };
  const native = { Results: [{ Class: "os-pkgs", Type: "debian", Packages: [{ ID: ref, Name: "libssl3", Epoch: 1,
    Version: "3.0.14-1~deb12u1", Arch: "amd64", SrcName: "openssl", SrcEpoch: 1, SrcVersion: "3.0.14", SrcRelease: "1~deb12u1",
    Identifier: { BOMRef: ref, PURL: ref } }] }] };
  return { inventory, sbom, native };
}

test("package conservation accepts the actual DEB decoder layout including source epoch", () => {
  const trace = packageTrace();
  assert.equal(assertPackageConservation(trace.inventory, trace.sbom, trace.native).nativePackages.length, 1);
});

for (const [label, mutate] of [
  ["missing native record", ({ native }) => native.Results[0].Packages.pop()],
  ["duplicate native record", ({ native }) => native.Results[0].Packages.push(structuredClone(native.Results[0].Packages[0]))],
  ["changed architecture", ({ native }) => { native.Results[0].Packages[0].Arch = "i386"; }],
  ["lost binary epoch", ({ native }) => { delete native.Results[0].Packages[0].Epoch; }],
  ["lost source epoch", ({ native }) => { delete native.Results[0].Packages[0].SrcEpoch; }],
  ["changed source revision", ({ native }) => { native.Results[0].Packages[0].SrcRelease = "1~deb12u2"; }],
  ["misattributed supplier", ({ sbom }) => { sbom.components[0].supplier.name = "unknown"; }],
  ["collapsed multiarch ID", ({ native }) => { native.Results[0].Packages[0].ID = "libssl3@3.0.14-1~deb12u1"; }],
]) test(`package conservation rejects ${label}`, () => {
  const trace = packageTrace();
  mutate(trace);
  assert.throws(() => assertPackageConservation(trace.inventory, trace.sbom, trace.native));
});

function findingTrace() {
  const native = ["amd64", "i386"].map((arch) => ({ VulnerabilityID: "CVE-2024-6119", PkgName: "libssl3",
    PkgID: `libssl3:${arch}@3.0.14-1~deb12u1`, PkgIdentifier: { PURL: `pkg:deb/debian/libssl3@3.0.14-1~deb12u1?arch=${arch}&distro=debian-12` },
    InstalledVersion: "3.0.14-1~deb12u1", FixedVersion: "3.0.14-1~deb12u2", Severity: "HIGH", Status: "fixed",
    DataSource: { ID: "debian", Name: "Debian Security Tracker" }, PrimaryURL: "https://security-tracker.debian.org/tracker/CVE-2024-6119" }));
  const findings = native.map((item, index) => ({ id: "trivy_CVE-2024-6119_" + String(index).repeat(24), source: "trivy",
    title: "CVE-2024-6119: libssl3", status: "failed", risk: "high", description: "Fixture observation", recommendation: "Review vendor advisory", remediationAvailable: false,
    evidence: `package=libssl3; installed=${item.InstalledVersion}; package_id=${item.PkgID}; purl=${item.PkgIdentifier.PURL}; fixed=${item.FixedVersion}; severity=HIGH; vendor_status=fixed; data_source=debian; data_source_name=Debian Security Tracker; source=${item.PrimaryURL}` }));
  const report = { findings, scanner: { partial: false }, extension: { preserved: true } };
  return { osResults: [{ Vulnerabilities: native }], report, normalized: { findings: structuredClone(findings), raw: structuredClone(report) } };
}

test("finding conservation retains every architecture-qualified tuple and raw normalization", () => {
  const trace = findingTrace();
  assert.deepEqual(assertFindingConservation(trace.osResults, trace.report, trace.normalized), {
    nativeVulnerabilityRecords: 2, uniqueNativeVulnerabilities: 2, hcpVulnerabilityFindings: 2,
  });
});

test("finding conservation rejects hidden drops and changed vendor evidence even when normalization agrees", () => {
  for (const mutate of [
    (report) => report.findings.pop(),
    (report) => { report.findings[1].evidence = report.findings[0].evidence; },
    (report) => { report.findings[0].evidence = report.findings[0].evidence.replace("fixed=3.0.14-1~deb12u2", "fixed=3.0.14-1~deb12u3"); },
    (report) => { report.findings[0].evidence = report.findings[0].evidence.replace("data_source=debian", "data_source=ubuntu"); },
  ]) {
    const trace = findingTrace();
    mutate(trace.report);
    trace.normalized = { findings: structuredClone(trace.report.findings), raw: structuredClone(trace.report) };
    assert.throws(() => assertFindingConservation(trace.osResults, trace.report, trace.normalized));
  }
});

test("normalization cannot conceal applicability/evidence changes or discard saved raw fields", () => {
  for (const mutate of [
    (normalized) => { normalized.findings[0].status = "passed"; },
    (normalized) => { normalized.findings[0].evidence = ""; },
    (normalized) => { delete normalized.raw.extension; },
  ]) {
    const trace = findingTrace();
    mutate(trace.normalized);
    assert.throws(() => assertFindingConservation(trace.osResults, trace.report, trace.normalized));
  }
});
