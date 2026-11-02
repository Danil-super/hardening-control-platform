import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["canonical-osv-upstream-check"]);
const { inspectCanonicalOsvUpstream } = await import(compiled.url("canonical-osv-upstream-check"));
const { importPinnedUbuntuOsvSnapshot, canonicalUbuntuOsvReference, readPinnedAdvisorySnapshot } =
  await import(compiled.url("vendor-advisory-snapshot"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const firstSha = "a".repeat(40);
const currentSha = "b".repeat(40);
const recordId = "UBUNTU-CVE-2024-6119";
const headEndpoint = "https://api.github.com/repos/canonical/ubuntu-security-notices/branches/main";
const baseRecord = {
  schema_version: "1.7.0", id: recordId, upstream: ["CVE-2024-6119"],
  modified: "2026-10-01T00:00:00Z",
  affected: [{ package: { name: "openssl", ecosystem: "Ubuntu:24.04:LTS" },
    ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.0.13-0ubuntu3.4" }] }],
    versions: ["3.0.13-0ubuntu3"] }],
};
const raw = JSON.stringify(baseRecord);
const digest = value => createHash("sha256").update(value).digest("hex");

function fixture(t, options = {}) {
  const stateRoot = mkdtempSync(path.join(tmpdir(), "hcp-osv-current-revision-"));
  t.after(() => rmSync(stateRoot, { recursive: true, force: true }));
  const snapshotSha256 = digest(raw);
  const manifest = importPinnedUbuntuOsvSnapshot({
    root: stateRoot, recordId, rawJson: raw, expectedSha256: snapshotSha256,
    ...(!options.localOnly ? { sourceReference: canonicalUbuntuOsvReference(recordId, firstSha) } : {}),
  });
  const queries = [];
  const rawUrl = canonicalUbuntuOsvReference(recordId, currentSha).url;
  const transport = async (url, init) => {
    queries.push(url);
    assert.equal(init.redirect, "error");
    assert.equal(init.cache, "no-store");
    assert.equal(init.credentials, "omit");
    assert.equal(init.method, "GET");
    if (url === headEndpoint) {
      return new Response(JSON.stringify({ name: "main", commit: { sha: currentSha } }),
        { status: 200, headers: { "content-type": "application/json" } });
    }
    assert.equal(url, rawUrl, "No untrusted CVE URL is requested");
    return new Response(raw, { status: 200, headers: { "content-type": "text/plain" } });
  };
  return {
    stateRoot, snapshotSha256, manifest, queries, transport, rawUrl,
    check: async (fetchImpl = transport) => inspectCanonicalOsvUpstream({
      stateRoot, snapshotSha256, fetchImpl, now: "2026-11-02T16:55:00Z",
    }),
  };
}

test("same exact CVE bytes across Git revisions is only a GitHub head observation", async t => {
  const f = fixture(t);
  const result = await f.check();
  assert.equal(result.status, "same_content_at_observed_head");
  assert.equal(result.pinnedRevision, firstSha);
  assert.equal(result.observedHeadRevision, currentSha);
  assert.equal(result.observedSha256, f.snapshotSha256);
  assert.deepEqual(f.queries, [headEndpoint, f.rawUrl]);
  assert.equal(result.publisherAuthenticated, false);
  assert.equal(result.publisherFreshnessVerified, false);
  assert.equal(result.trustedVerdict, "unknown");
  assert.equal(result.remediationAuthorized, false);
  assert.equal(readPinnedAdvisorySnapshot(f.stateRoot, f.snapshotSha256).manifest.sourceReference.revision, firstSha,
    "Read-only remote check cannot mutate the immutable snapshot manifest");
});

test("changed CVE fixed versions produce explicit drift while original pinned evidence stays intact", async t => {
  const f = fixture(t);
  const revised = JSON.stringify({ ...baseRecord, affected: [{
    ...baseRecord.affected[0], ranges: [{ type: "ECOSYSTEM", events: [
      { introduced: "0" }, { fixed: "3.0.13-0ubuntu3.5" },
    ] }],
  }] });
  const transport = async (url) => url === headEndpoint
    ? new Response(JSON.stringify({ name: "main", commit: { sha: currentSha } }), { headers: { "content-type": "application/json" } })
    : new Response(revised, { headers: { "content-type": "text/plain" } });
  const result = await f.check(transport);
  assert.equal(result.status, "changed_content_at_observed_head");
  assert.equal(result.observedSha256, digest(revised));
  assert.notEqual(result.observedSha256, result.localSha256);
  assert.equal(readPinnedAdvisorySnapshot(f.stateRoot, f.snapshotSha256).rawJson, raw);
  assert.equal(result.trustedVerdict, "unknown");
});

test("CVE deleted at current branch head is not represented as an unaffected result", async t => {
  const f = fixture(t);
  const result = await f.check(async (url) => url === headEndpoint
    ? new Response(JSON.stringify({ name: "main", commit: { sha: currentSha } }), { headers: { "content-type": "application/json" } })
    : new Response("not found", { status: 404, headers: { "content-type": "text/plain" } }));
  assert.equal(result.status, "missing_at_observed_head");
  assert.equal(result.trustedVerdict, "unknown");
  assert.equal(result.observedHeadRevision, currentSha);
  assert.equal(result.observedSha256, null);
});

test("missing or locally imported advisory is rejected before network access", async t => {
  const f = fixture(t, { localOnly: true });
  const result = await f.check();
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "local_snapshot_has_no_pinned_canonical_origin");
  assert.deepEqual(f.queries, []);
  const bad = await inspectCanonicalOsvUpstream({
    stateRoot: f.stateRoot, snapshotSha256: "0".repeat(64),
    fetchImpl: () => { throw Error("network should not be called"); },
  });
  assert.equal(bad.status, "unavailable");
  assert.equal(bad.reason, "local_snapshot_missing_or_invalid");
});

test("rejected branch metadata, redirects and upstream HTTP failures remain unknown", async t => {
  const f = fixture(t);
  const invalidHead = [
    new Response(JSON.stringify({ name: "main", commit: { sha: "main" } }), { headers: { "content-type": "application/json" } }),
    new Response(JSON.stringify({ name: "other", commit: { sha: currentSha } }), { headers: { "content-type": "application/json" } }),
    new Response("<html/>", { headers: { "content-type": "text/html" } }),
    new Response("", { status: 302, headers: { location: "http://127.0.0.1/private", "content-type": "application/json" } }),
    new Response("wrong", { status: 500, headers: { "content-type": "application/json" } }),
    new Response(JSON.stringify({ name: "main", commit: { sha: currentSha } }),
      { headers: { "content-type": "application/json", "content-length": "999999" } }),
  ];
  for (const response of invalidHead) {
    const result = await f.check(async url => {
      assert.equal(url, headEndpoint);
      return response;
    });
    assert.equal(result.status, "unavailable");
    assert.equal(result.trustedVerdict, "unknown");
  }
});

test("oversized streaming CVE, malformed OSV and redirected raw content fail closed", async t => {
  const f = fixture(t);
  const head = () => new Response(JSON.stringify({ name: "main", commit: { sha: currentSha } }),
    { headers: { "content-type": "application/json" } });
  const variants = [
    () => new Response(new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(8 * 1024 * 1024 + 1)); controller.close(); },
    }), { headers: { "content-type": "text/plain" } }),
    () => new Response("not json", { headers: { "content-type": "text/plain" } }),
    () => new Response("<p>html</p>", { headers: { "content-type": "text/html" } }),
    () => new Response("", { status: 301, headers: { "location": "http://127.0.0.1/a", "content-type": "text/plain" } }),
    () => new Response(JSON.stringify({ ...baseRecord, id: "UBUNTU-CVE-2024-6120" }), { headers: { "content-type": "text/plain" } }),
  ];
  for (const rawResponse of variants) {
    const result = await f.check(async url => url === headEndpoint ? head() : rawResponse());
    assert.equal(result.status, "unavailable");
    assert.equal(result.trustedVerdict, "unknown");
    assert.equal(result.observedSha256, null);
  }
});

test("network timeout/error or head fetch failure never removes the local pinned source", async t => {
  const f = fixture(t);
  const result = await f.check(async () => { throw new Error("timeout"); });
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "github_observation_failed_or_invalid");
  assert.equal(readPinnedAdvisorySnapshot(f.stateRoot, f.snapshotSha256).rawJson, raw);
});
