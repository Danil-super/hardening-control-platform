import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["astra-oval-official-catalog"]);
const { readOfficialAstraOvalCatalog } = await import(compiled.url("astra-oval-official-catalog"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const metadata = () => JSON.stringify({ size: "47960775", checksums: { sha256: "c".repeat(64) },
  uri: "https://attacker.invalid/evil.xml", sourceReviewedAt: "2026-11-03",
  publisherAuthenticated: true });
const response = (text, status = 200) => new Response(text, { status,
  headers: { "content-type": "application/json" } });

test("fixed Astra 1.7/1.8 vendor catalogs cannot be selected via arbitrary URL", async () => {
  const requested = [];
  const fetcher = async (url, init) => {
    requested.push({ url, init });
    return response(metadata());
  };
  for (const release of ["1.7", "1.8"]) {
    const value = await readOfficialAstraOvalCatalog(release, fetcher);
    assert.equal(value.release, release);
    assert.equal(value.sha256, "c".repeat(64));
    assert.ok(value.url.startsWith("https://dl.astralinux.ru/artifactory/al-oval/"));
    assert.ok(value.url.includes("/" + release + "_x86-64/"));
    assert.ok(value.metadataUrl.includes("dl.astralinux.ru/artifactory/api/storage/al-oval/"));
    assert.equal(value.publisherAuthenticated, false);
    assert.equal(value.publisherFreshnessVerified, false);
    assert.equal(value.remediationAuthorized, false);
    assert.equal(value.sourceReviewedAt, null);
    assert.match(value.warning, /не независимая подпись/);
  }
  assert.equal(requested.length, 2);
  for (const item of requested) {
    assert.equal(item.init.redirect, "error");
    assert.equal(item.init.credentials, "omit");
    assert.equal(item.init.method, "GET");
  }
  for (const release of ["../etc/passwd", "1.9", "1.7/other", "https://127.0.0.1"]) {
    await assert.rejects(readOfficialAstraOvalCatalog(release, fetcher));
  }
  assert.equal(requested.length, 2, "invalid release must not reach network");
});

test("fake publisher fields, stale labels and malicious metadata URL never grant trust", async () => {
  const input = await readOfficialAstraOvalCatalog("1.7", async () => response(metadata()));
  assert.equal(input.publisherAuthenticated, false);
  assert.equal(input.sourceReviewedAt, null);
  assert.equal(input.sourceReference, input.metadataUrl);
  assert.ok(!input.url.includes("attacker.invalid"));
});

test("missing sha, invalid length, error response and oversized metadata fail closed", async () => {
  const cases = [
    response(JSON.stringify({ size: "100", checksums: { sha256: "a".repeat(64) } })),
    response(JSON.stringify({ size: "47960775", checksums: { sha256: "../../secret" } })),
    response(JSON.stringify({ size: "999999999999", checksums: { sha256: "a".repeat(64) } })),
    response(JSON.stringify({ size: "47960775" })),
    response("{}", 503),
    response("x".repeat(65540)),
  ];
  for (const item of cases) {
    await assert.rejects(readOfficialAstraOvalCatalog("1.8", async () => item));
  }
});
