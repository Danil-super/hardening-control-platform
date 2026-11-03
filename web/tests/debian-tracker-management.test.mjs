import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["debian-tracker-management"]);
const controller = await import(compiled.url("debian-tracker-management"));
const state = await import(compiled.url("state-store"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const raw = JSON.stringify({
  openssl: { "CVE-2024-6119": { releases: {
    bookworm: { status: "resolved", fixed_version: "3.0.14-1~deb12u2" },
  } } },
});
const digest = createHash("sha256").update(raw).digest("hex");
function setup(t) {
  const folder = mkdtempSync(path.join(tmpdir(), "hcp-managed-debian-"));
  const previous = {
    root: process.env.HCP_STATE_DIR, mode: process.env.HCP_TRIVY_MODE,
    pin: process.env.HCP_DEBIAN_TRACKER_PREVIEW_SHA256,
  };
  process.env.HCP_STATE_DIR = folder;
  process.env.HCP_TRIVY_MODE = "online";
  delete process.env.HCP_DEBIAN_TRACKER_PREVIEW_SHA256;
  t.after(() => {
    if (previous.root === undefined) delete process.env.HCP_STATE_DIR;
    else process.env.HCP_STATE_DIR = previous.root;
    if (previous.mode === undefined) delete process.env.HCP_TRIVY_MODE;
    else process.env.HCP_TRIVY_MODE = previous.mode;
    if (previous.pin === undefined) delete process.env.HCP_DEBIAN_TRACKER_PREVIEW_SHA256;
    else process.env.HCP_DEBIAN_TRACKER_PREVIEW_SHA256 = previous.pin;
    rmSync(folder, { recursive: true, force: true });
  });
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return new Response(raw, { status: 200, headers: { "content-type": "application/json" } });
  };
  return { folder, calls, fetchImpl, import: (changes = {}) =>
    controller.fetchDebianTrackerCandidate({ fetchImpl, ...changes }) };
}

test("import from fixed upstream is separate from explicit activation and survives a settings reload", async t => {
  const f = setup(t);
  const initial = controller.getDebianTrackerManagementStatus();
  assert.equal(initial.selectedSha256, null);
  assert.equal(initial.lastImportedSha256, null);
  const result = await f.import();
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, "https://security-tracker.debian.org/tracker/data/json");
  assert.equal(f.calls[0].options.redirect, "error");
  assert.equal(f.calls[0].options.credentials, "omit");
  assert.equal(result.importInProgress, false);
  assert.equal(result.selectedSha256, null, "Import never changes the currently audited source");
  assert.equal(result.lastImportedSha256, digest);
  assert.equal(result.lastImportedManifest.sourcePackageCount, 1);
  assert.equal(result.lastImportedManifest.publisherAuthenticated, false);
  assert.equal(result.localSelectionAvailable, false);
  const approved = controller.approveDebianTrackerSelection({
    selectedSha256: digest, expectedSha256: null,
  });
  assert.equal(approved.selectedSha256, digest);
  assert.equal(approved.selectionSource, "interface");
  assert.equal(approved.localSelectionAvailable, true);
  assert.equal(state.getDebianTrackerSelection().sha256, digest);
  assert.equal(controller.getDebianTrackerManagementStatus().selectedSha256, digest);
  assert.throws(() => controller.approveDebianTrackerSelection({
    selectedSha256: null, expectedSha256: null,
  }), /другом сеансе/);
  const cleared = controller.approveDebianTrackerSelection({
    selectedSha256: null, expectedSha256: digest,
  });
  assert.equal(cleared.selectedSha256, null);
  assert.equal(state.getDebianTrackerLastImportedSha256(), digest, "Disabling preserves immutable bytes");
});

test("re-importing unchanged Debian bytes cannot refresh immutable local capture timestamp", async t => {
  const f = setup(t);
  const now = new Date().toISOString();
  const first = await f.import({ now });
  const later = new Date(Date.parse(now) + 2000).toISOString();
  const again = await f.import({ now: later });
  assert.equal(again.imported.sha256, first.imported.sha256);
  assert.equal(again.imported.capturedAt, first.imported.capturedAt);
  assert.equal(again.lastImportedSha256, digest);
  assert.equal(again.selectedSha256, null);
});

test("stale, wrong SHA, corrupt bytes and absent snapshots fail approval without changing source", async t => {
  const f = setup(t);
  await assert.rejects(f.import({ expectedSha256: "f".repeat(64) }), /operator pin/);
  assert.equal(controller.getDebianTrackerManagementStatus().lastImportedSha256, null);
  const old = new Date(Date.now() - 8 * 86400_000).toISOString();
  await f.import({ now: old });
  assert.throws(() => controller.approveDebianTrackerSelection({
    selectedSha256: digest, expectedSha256: null,
  }), /устарел/);
  assert.equal(controller.getDebianTrackerManagementStatus().selectedSha256, null);
  const location = path.join(f.folder, "debian-tracker-snapshots", "v1", digest + ".json");
  writeFileSync(location, "tampered", { flag: "w" });
  assert.throws(() => controller.approveDebianTrackerSelection({
    selectedSha256: digest, expectedSha256: null, maxImportAgeHours: 200,
  }), /целостность/);
  assert.equal(controller.getDebianTrackerManagementStatus().selectedSha256, null);
  assert.throws(() => controller.approveDebianTrackerSelection({
    selectedSha256: "f".repeat(64), expectedSha256: null,
  }), /последний/);
});

test("a second simultaneous import is rejected rather than racing to overwrite a snapshot", async t => {
  const f = setup(t);
  let resume;
  let signal;
  const called = new Promise(resolve => { signal = resolve; });
  const delayed = new Promise(resolve => { resume = resolve; });
  const first = controller.fetchDebianTrackerCandidate({
    fetchImpl: async (url) => {
      assert.equal(url, "https://security-tracker.debian.org/tracker/data/json");
      signal();
      await delayed;
      return new Response(raw, { headers: { "content-type": "application/json" } });
    },
  });
  await called;
  await assert.rejects(f.import(), /Уже выполняется/);
  resume();
  await first;
  assert.equal(controller.getDebianTrackerManagementStatus().lastImportedSha256, digest);
});

test("offline CVE mode blocks network fetching but does not revoke the previously selected source", async t => {
  const f = setup(t);
  await f.import();
  controller.approveDebianTrackerSelection({ selectedSha256: digest, expectedSha256: null });
  state.setVulnerabilityDatabaseMode("offline");
  await assert.rejects(f.import(), /локальный режим/);
  assert.equal(state.getDebianTrackerSelection().sha256, digest);
});

test("persisted disable overrides a legacy environment pin without deleting its raw snapshot", t => {
  setup(t);
  process.env.HCP_DEBIAN_TRACKER_PREVIEW_SHA256 = digest;
  assert.equal(state.getDebianTrackerSelection().sha256, digest);
  controller.approveDebianTrackerSelection({ selectedSha256: null, expectedSha256: digest });
  assert.equal(state.getDebianTrackerSelection().sha256, null);
  assert.equal(state.getDebianTrackerSelection().source, "interface");
});
