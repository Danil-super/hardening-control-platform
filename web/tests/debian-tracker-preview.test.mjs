import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const built = compileServerModules(["debian-tracker-preview"]);
const { annotateDebianTrackerPreview } = await import(built.url("debian-tracker-preview"));
const { importDebianTrackerFullSnapshot } = await import(built.url("debian-tracker-snapshot"));
test.after(() => rmSync(built.directory, { recursive: true, force: true }));
const now = new Date().toISOString();
const sha = raw => createHash("sha256").update(raw).digest("hex");

function feed() {
  return { openssl: {
    "CVE-2024-6119": { releases: { bookworm: {
      status: "resolved", fixed_version: "3.0.14-1~deb12u2",
      repositories: { bookworm: "9.9.9-not-fixed-version" },
    } } },
    "CVE-2024-6120": { releases: { bookworm: { status: "undetermined", fixed_version: null } } },
  } };
}
function finding(id, cve = "CVE-2024-6119", sourceVersion = "3.0.14-1~deb12u1", changes = {}) {
  const cveApplicability = {
    schemaVersion: 1, verdict: "affected", confidence: "metadata-consistent",
    distribution: { id: "debian", versionId: "12" },
    package: {
      name: "libssl3", installedVersion: sourceVersion, manager: "dpkg",
      architecture: "amd64", sourceName: "openssl", sourceVersion,
      provenance: "distribution-maintainer", purl: "pkg:deb/debian/libssl3@x",
    },
    advisory: { id: cve, scannerStatus: "affected", dataSourceId: "debian",
      sourceMatch: "matched", dataSourceName: "Debian" },
    database: { sha256: "a".repeat(64), freshness: "fresh" },
  };
  return {
    id, source: "trivy", status: "failed", risk: "high", remediationAvailable: false,
    profileId: "cve_packages", title: cve, category: "CVE", description: "original",
    recommendation: "manual validation",
    cveApplicability: { ...cveApplicability, ...changes },
  };
}
function fixture(t) {
  const stateRoot = mkdtempSync(path.join(tmpdir(), "hcp-debian-report-preview-"));
  t.after(() => rmSync(stateRoot, { recursive: true, force: true }));
  const raw = JSON.stringify(feed());
  const digest = sha(raw);
  const imported = () => importDebianTrackerFullSnapshot({
    stateRoot, expectedSha256: digest, now,
    fetchImpl: async () => new Response(raw, { headers: { "content-type": "application/json" } }),
  });
  const check = (findings, overrides = {}) => annotateDebianTrackerPreview({
    findings, stateRoot, osId: "debian", versionId: "12",
    releaseCodename: "bookworm", inventoryComplete: true,
    snapshotSha256: digest, now, ...overrides,
  });
  return { stateRoot, digest, imported, check };
}
function unchanged(before, after) {
  assert.equal(after.findings.length, before.length);
  assert.deepEqual(after.findings.map(x => x.id), before.map(x => x.id));
  after.findings.forEach((item, i) => {
    const { debianTrackerPreview, ...rest } = item;
    assert.deepEqual(rest, before[i]);
    if (debianTrackerPreview) {
      assert.equal(debianTrackerPreview.trustedVerdict, "unknown");
      assert.equal(debianTrackerPreview.publisherAuthenticated, false);
      assert.equal(debianTrackerPreview.publisherFreshnessVerified, false);
      assert.equal(debianTrackerPreview.remediationAuthorized, false);
    }
  });
}

test("preserves exact Trivy findings; records separate Debian candidate evidence and disagreements", async t => {
  const f = fixture(t);
  await f.imported();
  const original = [
    finding("a"), finding("b", "CVE-2024-6119", "3.0.14-1~deb12u2"),
    finding("c", "CVE-2024-6120"), finding("d", "CVE-2024-99999"),
    finding("e", "CVE-2024-6119", "3.0.14-1~deb12u1"),
  ];
  const annotated = f.check(original);
  unchanged(original, annotated);
  assert.deepEqual([
    annotated.summary.state, annotated.summary.eligibleFindings,
    annotated.summary.annotatedFindings, annotated.summary.candidateAffected,
    annotated.summary.candidateFixed, annotated.summary.candidateNeedsReview,
    annotated.summary.candidateUnknown, annotated.summary.unavailable,
    annotated.summary.conflictingWithTrivy,
  ], ["enabled", 5, 5, 2, 1, 1, 1, 1, 1]);
  assert.equal(annotated.findings[1].debianTrackerPreview.fixedVersion, "3.0.14-1~deb12u2");
  assert.equal(annotated.findings[1].debianTrackerPreview.conflictingWithTrivy, true);
  assert.equal(annotated.findings[3].debianTrackerPreview.reason, "cve_not_listed_unknown_not_clean");
  assert.equal(annotated.findings[0].debianTrackerPreview.fullSnapshotSha256, f.digest);
  assert.match(annotated.findings[0].debianTrackerPreview.derivedExcerptSha256, /^[a-f0-9]{64}$/);
});

test("disabled and non-Debian contexts never read even an invalid snapshot", () => {
  const findings = [finding("unchanged")];
  const input = { findings, stateRoot: "/not-found", osId: "debian",
    versionId: "12", releaseCodename: "bookworm", inventoryComplete: true };
  const disabled = annotateDebianTrackerPreview(input);
  assert.equal(disabled.summary, null);
  assert.equal(disabled.findings, findings);
  const astra = annotateDebianTrackerPreview({ ...input, osId: "astra",
    snapshotSha256: "a".repeat(64) });
  assert.equal(astra.summary, null);
  assert.equal(astra.findings, findings);
});

test("only exact Debian suite, native dpkg source and vendor-matched datasource are candidates", async t => {
  const f = fixture(t);
  await f.imported();
  const base = finding("original");
  const cases = [
    finding("missing-source", undefined, undefined, {
      package: { ...base.cveApplicability.package, sourceName: "libssl3" },
    }),
    finding("third-party", undefined, undefined, {
      package: { ...base.cveApplicability.package, provenance: "third-party" },
    }),
    finding("wrong-feed", undefined, undefined, {
      advisory: { ...base.cveApplicability.advisory, sourceMatch: "mismatch" },
    }),
  ];
  const result = f.check(cases);
  unchanged(cases, result);
  assert.equal(result.summary.annotatedFindings, 1);
  assert.equal(result.findings[0].debianTrackerPreview.reason, "source_package_not_listed");
  assert.equal(result.findings[1].debianTrackerPreview, undefined);
  assert.equal(result.findings[2].debianTrackerPreview, undefined);
  for (const overrides of [
    { versionId: "13", releaseCodename: "bookworm" },
    { versionId: "12", releaseCodename: "trixie" },
    { versionId: "14", releaseCodename: "forky" },
  ]) {
    const invalid = f.check([base], overrides);
    assert.equal(invalid.summary.state, "unsupported_release");
    assert.equal(invalid.findings[0], base);
  }
});

test("invalid pin, missing or altered snapshot, stale age and incomplete inventory fail closed", async t => {
  const f = fixture(t);
  await f.imported();
  for (const [options, state] of [
    [{ snapshotSha256: "wrong" }, "invalid_pin"],
    [{ snapshotSha256: "b".repeat(64) }, "unavailable"],
    [{ inventoryComplete: false }, "incomplete_inventory"],
    [{ maxImportAgeHours: 0 }, "invalid_policy"],
    [{ now: new Date(Date.parse(now) + 8 * 24 * 3600_000).toISOString() }, "stale_snapshot"],
    [{ now: new Date(Date.parse(now) - 3600_000).toISOString() }, "stale_snapshot"],
  ]) {
    const original = [finding("raw")];
    const result = f.check(original, options);
    assert.equal(result.summary.state, state);
    assert.equal(result.findings, original);
    unchanged(original, result);
  }
  const filename = path.join(f.stateRoot, "debian-tracker-snapshots", "v1", f.digest + ".json");
  writeFileSync(filename, "tampered", { flag: "w" });
  const original = [finding("no-change")];
  assert.equal(f.check(original).summary.state, "unavailable");
  assert.equal(f.check(original).findings, original);
});

test("over-budget results are wholly unavailable, never truncated or partially annotated", async t => {
  const f = fixture(t);
  await f.imported();
  const original = Array.from({ length: 129 }, (_, i) =>
    finding("finding-" + i, "CVE-2024-6119", "3.0.14-1~deb12u" + i));
  const result = f.check(original);
  assert.equal(result.summary.state, "budget_exceeded");
  assert.equal(result.summary.eligibleFindings, 129);
  assert.equal(result.findings, original);
  unchanged(original, result);
});
