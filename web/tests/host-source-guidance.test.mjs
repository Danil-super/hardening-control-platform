import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["host-source-guidance"]);
const { parseSourceGuidance, describeSourceAssignment } = await import(compiled.url("host-source-guidance"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const sample = () => ({
  ok: true, alias: "astra-lab", assessment: "saved-settings-only",
  astraOval: { state: "configured", group: "astra-1.7", message: "Назначение сохранено." },
  openScap: { state: "missing", group: null, message: "Не назначено." },
});

test("only an exact host- and saved-settings-bound response may be displayed", () => {
  assert.equal(parseSourceGuidance(sample(), "other-host"), null);
  assert.equal(parseSourceGuidance({ ...sample(), assessment: "full-cve-coverage" }, "astra-lab"), null);
  assert.equal(parseSourceGuidance({ ...sample(), ok: false }, "astra-lab"), null);
  assert.equal(parseSourceGuidance({ ...sample(), astraOval: null }, "astra-lab"), null);
  const result = parseSourceGuidance(sample(), "astra-lab");
  assert.equal(result.alias, "astra-lab");
  assert.equal(result.astraOval.state, "configured");
  assert.equal(result.openScap.state, "missing");
});

test("malformed or unrecognised source assignments fail closed", () => {
  for (const invalid of [
    { state: "scan_completed" }, { state: "configured", group: undefined },
    { state: "configured", group: null, message: "" },
    { state: "configured", group: null, message: "x", profileKind: "super-secure" },
    { state: "configured", group: null, message: "x", declaredRelease: "a".repeat(129) },
  ]) {
    assert.equal(parseSourceGuidance({ ...sample(), astraOval: invalid }, "astra-lab"), null, JSON.stringify(invalid));
  }
});

test("assigned policy is only a neutral configuration state, not success", () => {
  assert.deepEqual(describeSourceAssignment(sample().astraOval),
    { label: "Назначено (не проверено)", tone: "neutral" });
  for (const state of ["conflict", "incomplete"]) {
    assert.equal(describeSourceAssignment({ state, group: null, message: "x" }).tone, "warning");
  }
  assert.equal(describeSourceAssignment(sample().openScap).tone, "neutral");
});
