import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { rmSync } from "node:fs";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ubuntu-osv-crosscheck"]);
const { parseUbuntuOsvSnapshot, evaluateUbuntuOsv } = await import(compiled.url("ubuntu-osv-crosscheck"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

// Synthetic records model Canonical's documented OSV format, NOT downloaded
// production CVE advisories or an authenticated feed.
function osv({ cve = "CVE-2024-6119", ecosystem = "Ubuntu:24.04:LTS",
  source = "openssl", fixed = "3.0.13-0ubuntu3.4", versions = [] } = {}) {
  return {
    schema_version: "1.7.0", id: "UBUNTU-" + cve, upstream: [cve],
    affected: [{
      package: { ecosystem, name: source },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, ...(fixed ? [{ fixed }] : [])] }],
      versions,
    }],
  };
}

function parse(value) {
  const raw = JSON.stringify(value);
  return parseUbuntuOsvSnapshot(raw, createHash("sha256").update(raw).digest("hex"));
}

function check(snapshot, overrides = {}) {
  return evaluateUbuntuOsv(snapshot, {
    cveId: "CVE-2024-6119", release: "24.04",
    sourcePackage: "openssl", sourceVersion: "3.0.13-0ubuntu3", ...overrides,
  });
}

test("Ubuntu OSV v1 comparison uses native dpkg versions and backported fixed releases", () => {
  const snapshot = parse(osv());
  assert.equal(snapshot.integrity, "digest-matched-publisher-unverified");
  assert.equal(check(snapshot).verdict, "affected");
  assert.equal(check(snapshot).fixedVersion, "3.0.13-0ubuntu3.4");
  assert.equal(check(snapshot, { sourceVersion: "3.0.13-0ubuntu3.4" }).verdict, "fixed_or_not_affected");
  assert.equal(check(snapshot, { sourceVersion: "3.0.13-0ubuntu3.5" }).verdict, "fixed_or_not_affected");
  assert.equal(check(snapshot, { sourceVersion: "3.0.13-0ubuntu3.10" }).verdict, "fixed_or_not_affected");
  assert.equal(check(snapshot, { sourceVersion: "1:3.0.13-0ubuntu3" }).verdict, "fixed_or_not_affected", "Epoch comparison must follow dpkg");
  assert.equal(check(snapshot, { sourceVersion: "3.0.13~rc1-0ubuntu3" }).verdict, "affected", "Tilde sorts before final versions");
});

test("Ubuntu OSV v1 matches exact source package and Ubuntu release, not binary or Pro suite", () => {
  assert.equal(check(parse(osv()), { sourcePackage: "libssl3t64" }).verdict, "unknown");
  assert.equal(check(parse(osv()), { release: "22.04" }).reason, "source_release_not_listed");
  assert.equal(check(parse(osv({ ecosystem: "Ubuntu:Pro:24.04:LTS" }))).verdict, "unknown");
  assert.equal(check(parse(osv({ ecosystem: "Ubuntu:22.04:LTS" }))).verdict, "unknown");
  assert.equal(check(parse(osv({ source: "openssl-nonvendor" }))).verdict, "unknown");
  assert.equal(check(parse(osv()), { cveId: "CVE-2024-99999" }).reason, "snapshot_identity_mismatch");
});

test("Ubuntu OSV v1 no-fixed entries may include needs-triage and require review", () => {
  const snapshot = parse(osv({ fixed: null, versions: ["3.0.13-0ubuntu3", "3.0.13-0ubuntu3.1"] }));
  assert.equal(check(snapshot).verdict, "needs_review");
  assert.equal(check(snapshot).reason, "no_fixed_event_may_include_needs_triage");
  assert.equal(check(snapshot, { sourceVersion: "3.0.13-0ubuntu3.9" }).verdict, "unknown");
  assert.equal(check(parse(osv({ fixed: null, versions: [] }))).verdict, "unknown");
});

test("Ubuntu OSV v1 rejects ambiguous or unsupported ranges and versions", () => {
  const duplicate = osv();
  duplicate.affected.push(structuredClone(duplicate.affected[0]));
  assert.equal(check(parse(duplicate)).verdict, "needs_review");
  const malformed = osv();
  malformed.affected[0].ranges[0].events[0].introduced = "1.0";
  assert.equal(check(parse(malformed)).reason, "unsupported_version_events");
  const unsupported = osv();
  unsupported.affected[0].ranges[0].type = "SEMVER";
  assert.equal(check(parse(unsupported)).reason, "unsupported_version_range");
  const badFixed = osv();
  badFixed.affected[0].ranges[0].events[1].fixed = "x; /bin/sh";
  assert.equal(check(parse(badFixed)).reason, "unsupported_fixed_version");
  assert.equal(check(parse(osv()), { sourceVersion: "\u0000" }).reason, "invalid_target_identity");
});

test("Ubuntu OSV v1 parser checks independent content digest and exact CVE schema", () => {
  const raw = JSON.stringify(osv());
  assert.throws(() => parseUbuntuOsvSnapshot(raw, "0".repeat(64)), /differs/);
  assert.throws(() => parseUbuntuOsvSnapshot(raw, "not-a-sha"), /SHA-256/);
  assert.throws(() => parseUbuntuOsvSnapshot(" ", createHash("sha256").update(" ").digest("hex")), /Unexpected end|JSON/);
  assert.throws(() => parseUbuntuOsvSnapshot("x".repeat(8 * 1024 * 1024 + 1), "a".repeat(64)), /size/);
  const mismatch = osv();
  mismatch.upstream = ["CVE-2026-12345"];
  assert.throws(() => parse(mismatch), /unsupported CVE schema/);
  const malicious = osv();
  malicious.id = "UBUNTU-CVE-2024-6119.other";
  assert.throws(() => parse(malicious), /unsupported CVE schema/);
});


test("Ubuntu OSV v1 rejects withdrawn and internally malformed records before conclusions", () => {
  const withdrawn = osv();
  withdrawn.withdrawn = "2026-10-01T00:00:00Z";
  assert.equal(check(parse(withdrawn)).reason, "withdrawn_advisory_requires_review");
  const malformed = osv();
  malformed.affected.push(null);
  assert.equal(check(parse(malformed)).reason, "snapshot_schema_unsupported");
});
