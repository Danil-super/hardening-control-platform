import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ubuntu-osv-lifecycle"]);
const { evaluateUbuntuOsvLifecycle } = await import(compiled.url("ubuntu-osv-lifecycle"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const now = "2026-11-02T17:00:00Z";
const revision = "a".repeat(40);
const baseline = {
  importedAt: "2026-11-02T12:00:00Z",
  revision,
  now,
  record: { modified: "2026-10-28T00:00:00Z", published: "2024-09-03T00:00:00Z" },
};
const lifecycle = (changes = {}) => evaluateUbuntuOsvLifecycle({ ...baseline, ...changes });

test("recent local import permits a provisional candidate but never verifies upstream freshness", () => {
  const state = lifecycle();
  assert.equal(state.state, "import_window_ok");
  assert.equal(state.candidateAllowed, true);
  assert.equal(state.importAgeHours, 5);
  assert.equal(state.recordModifiedAt, undefined);
  assert.equal(state.modifiedAt, "2026-10-28T00:00:00Z");
  assert.equal(state.publisherFreshnessVerified, false);
  assert.equal(state.publisherAuthenticated, false);
});

test("old local import is held back independently of old vendor modified dates", () => {
  const oldImport = lifecycle({ importedAt: "2026-10-01T00:00:00Z" });
  assert.equal(oldImport.state, "stale_import");
  assert.equal(oldImport.candidateAllowed, false);
  assert.equal(oldImport.publisherFreshnessVerified, false);
  const oldModified = lifecycle({ record: { modified: "2024-01-01T00:00:00Z" } });
  assert.equal(oldModified.candidateAllowed, true);
  assert.equal(oldModified.publisherFreshnessVerified, false, "Old modified alone cannot establish a stale or current vendor feed");
});

test("withdrawn, future and malformed OSV lifecycle timestamps never enable a candidate", () => {
  const withdrawn = lifecycle({ record: { modified: "2026-10-28T00:00:00Z", withdrawn: "2026-10-30T00:00:00Z" } });
  assert.equal(withdrawn.state, "withdrawn_record");
  assert.equal(withdrawn.candidateAllowed, false);
  assert.equal(lifecycle({ record: { modified: "2026-11-10T00:00:00Z" } }).state, "future_timestamps");
  assert.equal(lifecycle({ importedAt: "2030-01-01T00:00:00Z" }).state, "future_timestamps");
  assert.equal(lifecycle({ record: { published: "2026-10-29T00:00:00Z", modified: "2026-10-28T00:00:00Z" } }).state, "invalid_timestamps");
  for (const modified of ["", "2026-02-30T00:00:00Z", "2026-11-02T09:00:00+03:00", null]) {
    assert.equal(lifecycle({ record: { modified } }).state, "invalid_timestamps", String(modified));
  }
  assert.equal(lifecycle({ record: { modified: "2026-10-28T00:00:00Z", withdrawn: "invalid" } }).state, "invalid_timestamps");
});

test("missing or malformed immutable Git revision is not a pinned source", () => {
  for (const invalid of [null, undefined, "main", "b".repeat(39)]) {
    assert.equal(lifecycle({ revision: invalid }).state, "unpinned_origin");
    assert.equal(lifecycle({ revision: invalid }).candidateAllowed, false);
  }
});

test("reject invalid import-age policy rather than assuming default freshness", () => {
  for (const maxImportAgeHours of [0, -1, 1.5, 8761, NaN]) {
    assert.throws(() => lifecycle({ maxImportAgeHours }), /Invalid Ubuntu OSV import-age policy/);
  }
  assert.equal(lifecycle({ importedAt: "2026-11-01T17:00:00Z", maxImportAgeHours: 24 }).candidateAllowed, true);
  assert.equal(lifecycle({ importedAt: "2026-11-01T16:59:59Z", maxImportAgeHours: 24 }).state, "stale_import");
});
