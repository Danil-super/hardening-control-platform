import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["vendor-advisory-snapshot"]);
const { importPinnedUbuntuOsvSnapshot, readPinnedAdvisorySnapshot } = await import(compiled.url("vendor-advisory-snapshot"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));
function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), "hcp-snapshot-contract-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const recordId = "UBUNTU-CVE-2024-6119";
  const rawJson = JSON.stringify({ schema_version: "1.7.0", id: recordId, upstream: ["CVE-2024-6119"], affected: [] });
  const sha256 = createHash("sha256").update(rawJson).digest("hex");
  const importSnapshot = () => importPinnedUbuntuOsvSnapshot({ root, recordId, rawJson, expectedSha256: sha256 });
  return { root, rawJson, recordId, sha256, importSnapshot };
}

test("pinned Ubuntu snapshots persist immutably, read only with matching bytes, and are idempotent", t => {
  const f = fixture(t);
  const first = f.importSnapshot();
  assert.equal(first.recordId, f.recordId);
  assert.equal(first.sha256, f.sha256);
  assert.equal(first.bytes, Buffer.byteLength(f.rawJson));
  assert.equal(first.publisherAuthenticated, false);
  assert.equal(first.importMethod, "operator-pinned-local-sha256");
  assert.equal(readPinnedAdvisorySnapshot(f.root, f.sha256).rawJson, f.rawJson);
  assert.deepEqual(f.importSnapshot(), first);
  const directory = path.join(f.root, "vendor-advisory-snapshots", "v1");
  assert.equal(lstatSync(directory).mode & 0o077, 0);
  assert.equal(lstatSync(path.join(directory, f.sha256 + ".json")).mode & 0o077, 0);
  assert.equal(lstatSync(path.join(directory, f.sha256 + ".manifest.json")).mode & 0o077, 0);
  assert.equal(readFileSync(path.join(directory, f.sha256 + ".json"), "utf8"), f.rawJson);
});

test("pinned snapshots reject a wrong digest, different CVE identity, and unsafe filenames", t => {
  const f = fixture(t);
  assert.throws(() => importPinnedUbuntuOsvSnapshot({ root: f.root, recordId: f.recordId, rawJson: f.rawJson,
    expectedSha256: "0".repeat(64) }), /differ/);
  assert.throws(() => importPinnedUbuntuOsvSnapshot({ root: f.root, recordId: "UBUNTU-CVE-2025-12345",
    rawJson: f.rawJson, expectedSha256: f.sha256 }), /identifier/);
  assert.throws(() => importPinnedUbuntuOsvSnapshot({ root: f.root, recordId: "../../etc/passwd",
    rawJson: f.rawJson, expectedSha256: f.sha256 }), /Invalid/);
  assert.throws(() => readPinnedAdvisorySnapshot(f.root, "../../etc/passwd"), /SHA-256/);
});

test("saved advisory corruption, public permissions and replacement by symlink fail closed", t => {
  const f = fixture(t);
  f.importSnapshot();
  const directory = path.join(f.root, "vendor-advisory-snapshots", "v1");
  const dataPath = path.join(directory, f.sha256 + ".json");
  writeFileSync(dataPath, f.rawJson + " ", { flag: "w" });
  assert.throws(() => readPinnedAdvisorySnapshot(f.root, f.sha256), /checksum|size/);
  // A retry must not overwrite a corrupted immutable file.
  assert.throws(() => f.importSnapshot(), /checksum|size/);
  writeFileSync(dataPath, f.rawJson);
  chmodSync(dataPath, 0o644);
  assert.throws(() => readPinnedAdvisorySnapshot(f.root, f.sha256), /permissions/);
  chmodSync(dataPath, 0o600);
  rmSync(dataPath);
  symlinkSync("/etc/hosts", dataPath);
  assert.throws(() => readPinnedAdvisorySnapshot(f.root, f.sha256), /ELOOP|symbolic|ordinary|file|ENOENT/);
});

test("an interrupted import without a manifest is incomplete but safely recoverable", t => {
  const f = fixture(t);
  const dir = path.join(f.root, "vendor-advisory-snapshots", "v1");
  const manifest = f.importSnapshot();
  const manifestPath = path.join(dir, f.sha256 + ".manifest.json");
  rmSync(manifestPath);
  assert.equal(existsSync(manifestPath), false);
  assert.throws(() => readPinnedAdvisorySnapshot(f.root, f.sha256), /ENOENT/);
  assert.equal(f.importSnapshot().sha256, manifest.sha256);
  assert.equal(readPinnedAdvisorySnapshot(f.root, f.sha256).rawJson, f.rawJson);
});

test("existing digest cannot be assigned to a different identity", t => {
  const f = fixture(t);
  f.importSnapshot();
  const malicious = JSON.stringify({ id: "UBUNTU-CVE-2026-99999", affected: [] });
  assert.throws(() => importPinnedUbuntuOsvSnapshot({ root: f.root, recordId: f.recordId,
    rawJson: malicious, expectedSha256: f.sha256 }), /differ/);
});
