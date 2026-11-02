import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["canonical-ubuntu-osv-fetch", "ubuntu-pinned-crosscheck"]);
const { fetchPinnedCanonicalUbuntuOsv } = await import(compiled.url("canonical-ubuntu-osv-fetch"));
const { readPinnedAdvisorySnapshot, importPinnedUbuntuOsvSnapshot, canonicalUbuntuOsvReference } = await import(compiled.url("vendor-advisory-snapshot"));
const { evaluatePinnedUbuntuCrossCheck } = await import(compiled.url("ubuntu-pinned-crosscheck"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const revision = "a".repeat(40);
const recordId = "UBUNTU-CVE-2024-6119";
const record = {
  schema_version: "1.7.0", id: recordId, upstream: ["CVE-2024-6119"],
  affected: [{
    package: { name: "openssl", ecosystem: "Ubuntu:24.04:LTS" },
    ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.0.13-0ubuntu3.4" }] }],
    versions: ["3.0.13-0ubuntu3", "3.0.13-0ubuntu3.1"],
  }],
};
const rawJson = JSON.stringify(record);
const digest = createHash("sha256").update(rawJson).digest("hex");

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), "hcp-canonical-fetch-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const url = "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/"
    + revision + "/osv/cve/2024/" + recordId + ".json";
  const fetchImpl = async (requested, init) => {
    assert.equal(requested, url);
    assert.equal(init.redirect, "error");
    assert.equal(init.credentials, "omit");
    assert.equal(init.method, "GET");
    assert.equal(init.cache, "no-store");
    return new Response(rawJson, { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
  };
  const args = { stateRoot: root, recordId, revision, expectedSha256: digest, fetchImpl };
  return { root, url, args };
}

test("Canonical origin accepts only exact commit, CVE and fixed HTTPS host", () => {
  assert.equal(canonicalUbuntuOsvReference(recordId, revision).url,
    "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/"
    + revision + "/osv/cve/2024/" + recordId + ".json");
  for (const id of ["../../etc/passwd", "UBUNTU-CVE-2024-6119/../../bad", "CVE-2024-6119"]) {
    assert.throws(() => canonicalUbuntuOsvReference(id, revision), /Invalid/);
  }
  for (const bad of ["main", "a".repeat(39), "B".repeat(40), "a".repeat(41)]) {
    assert.throws(() => canonicalUbuntuOsvReference(recordId, bad), /Invalid/);
  }
});

test("pinned Canonical response passes vault and remains a provisional dpkg finding", async t => {
  const f = fixture(t);
  const receipt = await fetchPinnedCanonicalUbuntuOsv(f.args);
  assert.equal(receipt.fileSha256, digest);
  assert.equal(receipt.publisherAuthenticated, false);
  assert.equal(receipt.snapshot.sourceReference.url, f.url);
  assert.equal(receipt.transport, "fixed-https-origin-revision-pinned");
  const saved = readPinnedAdvisorySnapshot(f.root, digest);
  assert.equal(saved.rawJson, rawJson);
  assert.equal(saved.manifest.sourceReference.revision, revision);
  const result = evaluatePinnedUbuntuCrossCheck({
    stateRoot: f.root, snapshotSha256: digest, osId: "ubuntu", release: "24.04",
    cveId: "CVE-2024-6119", sourcePackage: "openssl",
    sourceVersion: "3.0.13-0ubuntu3.4", inventoryComplete: true,
  });
  assert.equal(result.candidateVerdict, "fixed_or_not_affected");
  assert.equal(result.trustedVerdict, "unknown");
  assert.equal(result.remediationAuthorized, false);
  assert.equal((await fetchPinnedCanonicalUbuntuOsv(f.args)).snapshot.sourceReference.revision, revision);
});

test("wrong digest or wrong CVE content is never stored", async t => {
  const f = fixture(t);
  await assert.rejects(fetchPinnedCanonicalUbuntuOsv({ ...f.args, expectedSha256: "0".repeat(64) }), /SHA-256/);
  await assert.rejects(fetchPinnedCanonicalUbuntuOsv({ ...f.args, expectedSha256: "invalid" }), /SHA-256/);
  const forged = JSON.stringify({ ...record, id: "UBUNTU-CVE-2024-6120" });
  const otherDigest = createHash("sha256").update(forged).digest("hex");
  await assert.rejects(fetchPinnedCanonicalUbuntuOsv({
    ...f.args, expectedSha256: otherDigest,
    fetchImpl: async () => new Response(forged, { headers: { "content-type": "application/json" } }),
  }), /identity/);
  assert.throws(() => readPinnedAdvisorySnapshot(f.root, digest), /ENOENT/);
  assert.throws(() => readPinnedAdvisorySnapshot(f.root, otherDigest), /ENOENT/);
});

test("redirects, HTTP errors, HTML and oversized Content-Length are rejected", async t => {
  const f = fixture(t);
  const responses = [
    new Response("", { status: 302, headers: { location: "http://127.0.0.1/private", "content-type": "text/plain" } }),
    new Response("error", { status: 404, headers: { "content-type": "text/plain" } }),
    new Response("<html></html>", { headers: { "content-type": "text/html" } }),
    new Response(rawJson, { headers: { "content-type": "text/plain", "content-length": "9000000" } }),
  ];
  for (const response of responses) {
    await assert.rejects(fetchPinnedCanonicalUbuntuOsv({ ...f.args, fetchImpl: async () => response }));
  }
  assert.throws(() => readPinnedAdvisorySnapshot(f.root, digest), /ENOENT/);
});

test("oversized streamed body is bounded independently of response headers", async t => {
  const f = fixture(t);
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(8 * 1024 * 1024 + 1));
      controller.close();
    },
  });
  await assert.rejects(fetchPinnedCanonicalUbuntuOsv({
    ...f.args, fetchImpl: async () => new Response(stream, { headers: { "content-type": "text/plain" } }),
  }), /bounded body limit/);
  assert.throws(() => readPinnedAdvisorySnapshot(f.root, digest), /ENOENT/);
});

test("an existing local-only import cannot silently acquire a Canonical label", async t => {
  const f = fixture(t);
  importPinnedUbuntuOsvSnapshot({ root: f.root, recordId, rawJson, expectedSha256: digest });
  await assert.rejects(fetchPinnedCanonicalUbuntuOsv(f.args), /origin differs/);
  assert.equal(readPinnedAdvisorySnapshot(f.root, digest).manifest.sourceReference, undefined);
});
