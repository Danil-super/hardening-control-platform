import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["debian-tracker-snapshot"]);
const {
  DEBIAN_TRACKER_URL, DEBIAN_TRACKER_MAX_BYTES,
  importDebianTrackerFullSnapshot, readPinnedDebianTrackerFullSnapshot,
  evaluatePinnedDebianTrackerFullSnapshot,
} = await import(compiled.url("debian-tracker-snapshot"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

// Small synthetic *full-export-shaped* input. Not official Debian bytes.
function feed() {
  return {
    openssl: {
      "CVE-2024-6119": {
        description: "Synthetic source-package fix",
        releases: {
          bookworm: {
            status: "resolved", fixed_version: "3.0.14-1~deb12u2",
            repositories: { bookworm: "9.9.9-not-the-fixed-version" }, urgency: "high",
          },
          trixie: { status: "open", fixed_version: null, repositories: {} },
        },
      },
      "TEMP-0000000-EXAMPLE": { description: "Opaque non-CVE entry" },
    },
    bash: {
      "CVE-2024-99999": {
        releases: { bookworm: { status: "undetermined", fixed_version: null } },
      },
    },
  };
}
const sha256 = value => createHash("sha256").update(value).digest("hex");
function fixture(t) {
  const stateRoot = mkdtempSync(path.join(tmpdir(), "hcp-debian-tracker-full-"));
  t.after(() => rmSync(stateRoot, { recursive: true, force: true }));
  const rawJson = JSON.stringify(feed());
  const digest = sha256(rawJson);
  const now = new Date().toISOString();
  const requestedUrls = [];
  const fetchImpl = async (url, init) => {
    requestedUrls.push(url);
    assert.equal(url, DEBIAN_TRACKER_URL);
    assert.equal(init.method, "GET");
    assert.equal(init.redirect, "error");
    assert.equal(init.cache, "no-store");
    assert.equal(init.credentials, "omit");
    assert.equal(init.headers.Accept, "application/json");
    assert.equal(init.signal.aborted, false);
    return new Response(rawJson, { status: 200, headers: { "content-type": "application/json" } });
  };
  const imported = (overrides = {}) => importDebianTrackerFullSnapshot({
    stateRoot, expectedSha256: digest, fetchImpl, now, ...overrides,
  });
  const evaluate = (snapshotSha256 = digest, overrides = {}) => evaluatePinnedDebianTrackerFullSnapshot({
    stateRoot, snapshotSha256, osId: "debian", inventoryComplete: true,
    sourcePackage: "openssl", sourceVersion: "3.0.14-1~deb12u1",
    cveId: "CVE-2024-6119", release: "bookworm", now,
    ...overrides,
  });
  return { stateRoot, rawJson, digest, now, requestedUrls, fetchImpl, imported, evaluate };
}
function assertNoTrust(result) {
  assert.equal(result.publisherAuthenticated, false);
  assert.equal(result.publisherFreshnessVerified, false);
  assert.equal(result.trustedVerdict, "unknown");
  assert.equal(result.remediationAuthorized, false);
}

test("full-feed HTTPS import stores verified immutable bytes and an exact source-derived CVE excerpt", async t => {
  const f = fixture(t);
  chmodSync(f.stateRoot, 0o755);
  const manifest = await f.imported();
  assert.deepEqual(f.requestedUrls, [DEBIAN_TRACKER_URL]);
  assert.equal(manifest.sourceUrl, DEBIAN_TRACKER_URL);
  assert.equal(manifest.sha256, f.digest);
  assert.equal(manifest.sourcePackageCount, 2);
  assert.equal(manifest.issueCount, 3);
  assert.equal(manifest.pinMode, "independently-specified-sha256");
  assert.equal(manifest.publisherAuthenticated, false);
  assert.equal(manifest.publisherFreshnessVerified, false);
  const stored = readPinnedDebianTrackerFullSnapshot(f.stateRoot, f.digest);
  assert.deepEqual(stored.data, feed());
  assert.deepEqual(stored.manifest, manifest);
  const folder = path.join(f.stateRoot, "debian-tracker-snapshots", "v1");
  assert.equal(readFileSync(path.join(folder, f.digest + ".json"), "utf8"), f.rawJson);
  const result = f.evaluate();
  assert.equal(result.status, "provisional");
  assert.equal(result.candidateVerdict, "affected");
  assert.equal(result.fixedVersion, "3.0.14-1~deb12u2");
  assert.equal(result.fullSnapshotSha256, f.digest);
  const extracted = JSON.stringify({
    openssl: { "CVE-2024-6119": feed().openssl["CVE-2024-6119"] },
  });
  assert.equal(result.derivedExcerptSha256, sha256(extracted));
  assertNoTrust(result);
  assert.equal(await f.imported(), manifest, "Second import reuses an exact manifest");
});

test("native dpkg evaluates source backports but only returns untrusted candidate evidence", async t => {
  const f = fixture(t);
  await f.imported();
  for (const [version, verdict] of [
    ["3.0.14-1~deb12u1", "affected"],
    ["3.0.14-1~deb12u2", "fixed_or_not_affected"],
    ["3.0.14-1~deb12u10", "fixed_or_not_affected"],
    ["1:3.0.14-1~deb12u1", "fixed_or_not_affected"],
  ]) {
    const result = f.evaluate(f.digest, { sourceVersion: version });
    assert.equal(result.candidateVerdict, verdict);
    assertNoTrust(result);
  }
  const open = f.evaluate(f.digest, { release: "trixie" });
  assert.equal(open.candidateVerdict, "needs_review");
  assertNoTrust(open);
});

test("invalid identities, absent CVE and unsupported Debian release fail closed", async t => {
  const f = fixture(t);
  await f.imported();
  for (const [input, reason] of [
    [{ osId: "ubuntu" }, "unsupported_exact_os_identity"],
    [{ osId: "astra" }, "unsupported_exact_os_identity"],
    [{ inventoryComplete: false }, "incomplete_source_inventory"],
    [{ sourcePackage: "libssl3" }, "source_package_not_listed"],
    [{ sourcePackage: "bash" }, "cve_not_listed_unknown_not_clean"],
    [{ cveId: "CVE-2024-99998" }, "cve_not_listed_unknown_not_clean"],
    [{ release: "bullseye" }, "source_release_not_listed"],
    [{ sourceVersion: "3.0.14;rm -rf" }, "invalid_target_identity"],
  ]) {
    const result = f.evaluate(f.digest, input);
    assert.equal(result.reason, reason);
    assert.equal(result.status, "unavailable");
    assert.equal(result.candidateVerdict, "unknown");
    assertNoTrust(result);
  }
});

test("stale, future and invalid import policies cannot silently mark a CVE fixed", async t => {
  const f = fixture(t);
  await f.imported();
  const later = new Date(Date.parse(f.now) + 8 * 24 * 3600_000).toISOString();
  assert.equal(f.evaluate(f.digest, { now: later }).reason, "local_import_window_expired");
  assert.equal(f.evaluate(f.digest, { now: later, maxImportAgeHours: 200 }).candidateVerdict, "affected");
  const earlier = new Date(Date.parse(f.now) - 3600_000).toISOString();
  assert.equal(f.evaluate(f.digest, { now: earlier }).reason, "future_dated_local_snapshot");
  assert.equal(f.evaluate(f.digest, { maxImportAgeHours: 0 }).reason, "invalid_local_import_age_policy");
  assert.equal(f.evaluate(f.digest, { now: "not-a-date" }).reason, "invalid_assessment_timestamp");
});

test("operator pin mismatch, malformed JSON and duplicate or escaped JSON keys are rejected pre-write", async t => {
  const f = fixture(t);
  await assert.rejects(f.imported({ expectedSha256: "0".repeat(64) }), /operator pin/);
  assert.equal(existsSync(path.join(f.stateRoot, "debian-tracker-snapshots")), false);
  const bad = [
    "{bad",
    '{"openssl":{},"openssl":{}}',
    '{"openssl":{},"open\\u0073sl":{}}',
    JSON.stringify({ openssl: { "CVE-2024-6119": { releases: [] } } }),
    JSON.stringify({ openssl: { "CVE-2024-6119": { releases: { bookworm: null } } } }),
  ];
  for (const raw of bad) {
    await assert.rejects(f.imported({
      expectedSha256: sha256(raw),
      fetchImpl: async () => new Response(raw, { headers: { "content-type": "application/json" } }),
    }));
  }
  assert.equal(existsSync(path.join(f.stateRoot, "debian-tracker-snapshots")), false);
});

test("fixed HTTPS origin, strict status/MIME, no redirect and declared body limit", async t => {
  const f = fixture(t);
  for (const response of [
    new Response("redirect", { status: 302, headers: { location: "http://127.0.0.1/admin", "content-type": "application/json" } }),
    new Response("error", { status: 500, headers: { "content-type": "application/json" } }),
    new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } }),
    new Response(f.rawJson, { headers: { "content-type": "application/json", "content-length": String(DEBIAN_TRACKER_MAX_BYTES + 1) } }),
    new Response(f.rawJson, { headers: { "content-type": "application/json", "content-range": "bytes 0-100/100000" } }),
  ]) {
    await assert.rejects(f.imported({ fetchImpl: async (url, init) => {
      assert.equal(url, DEBIAN_TRACKER_URL);
      assert.equal(init.redirect, "error");
      return response;
    } }));
  }
  assert.equal(existsSync(path.join(f.stateRoot, "debian-tracker-snapshots")), false);
});

test("actual streaming byte cap rejects oversized HTTP body without publication", async t => {
  const f = fixture(t);
  let chunks = 0;
  const stream = new ReadableStream({
    pull(controller) {
      controller.enqueue(new Uint8Array(4 * 1024 * 1024));
      chunks++;
    },
  });
  await assert.rejects(f.imported({
    expectedSha256: undefined,
    fetchImpl: async () => new Response(stream, { headers: { "content-type": "application/json" } }),
  }), /streamed size/);
  assert.ok(chunks >= 17);
  assert.equal(existsSync(path.join(f.stateRoot, "debian-tracker-snapshots")), false);
});

test("snapshot tampering, writable public file and symlink replacement fail closed", async t => {
  const f = fixture(t);
  await f.imported();
  const filename = path.join(f.stateRoot, "debian-tracker-snapshots", "v1", f.digest + ".json");
  writeFileSync(filename, f.rawJson + " ", { flag: "w" });
  assert.equal(f.evaluate().reason, "pinned_full_snapshot_or_derived_excerpt_invalid");
  await assert.rejects(f.imported(), /integrity mismatch/);
  writeFileSync(filename, f.rawJson);
  chmodSync(filename, 0o644);
  assert.equal(f.evaluate().status, "unavailable");
  chmodSync(filename, 0o600);
  rmSync(filename);
  symlinkSync("/etc/hosts", filename);
  assert.equal(f.evaluate().status, "unavailable");
});

test("interrupted manifest publication is not readable and can be retried identically", async t => {
  const f = fixture(t);
  await f.imported();
  const manifestFile = path.join(f.stateRoot, "debian-tracker-snapshots", "v1", f.digest + ".manifest.json");
  rmSync(manifestFile);
  assert.equal(f.evaluate().status, "unavailable");
  assert.equal((await f.imported()).sha256, f.digest);
  assert.equal(f.evaluate().candidateVerdict, "affected");
});

test("same raw bytes cannot silently gain new capture-time freshness on re-import", async t => {
  const f = fixture(t);
  const manifest = await f.imported();
  const later = new Date(Date.parse(f.now) + 60_000).toISOString();
  await assert.rejects(f.imported({ now: later }), /immutable Debian tracker manifest differs/);
  assert.deepEqual(readPinnedDebianTrackerFullSnapshot(f.stateRoot, f.digest).manifest, manifest);
});

test("observed digest without an operator pin is explicitly marked as not independently pinned", async t => {
  const f = fixture(t);
  const manifest = await f.imported({ expectedSha256: undefined });
  assert.equal(manifest.pinMode, "observed-at-capture");
  assert.equal(manifest.publisherAuthenticated, false);
  assert.equal(f.evaluate().trustedVerdict, "unknown");
});
