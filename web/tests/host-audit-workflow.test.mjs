import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["host-audit-workflow", "dashboard-evidence-status"]);
const { selectHostAuditNextStep: select } = await import(compiled.url("host-audit-workflow"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const risk = overrides => ({
  critical: 0, high: 0, medium: 0, low: 0, unknown: 0,
  auditCount: 2, freshCount: 2, partialCount: 0, staleCount: 0,
  identityExcludedCount: 0, maxAgeHours: 168, ...overrides,
});
const host = overrides => ({ alias: "astra-lab", controlReady: true,
  riskSummary: risk({}), ...overrides });

test("no selected host or unready control node never offers a scan as completed", () => {
  assert.equal(select({ alias: null, controlReady: false }).id, "connect");
  assert.equal(select(host({ controlReady: false })).id, "controller");
});
test("recovery takes priority over controller, running scan and old findings", () => {
  const state = host({ recoveryRequired: true, activeJob: true, controlReady: false,
    riskSummary: risk({ critical: 3 }) });
  const next = select(state);
  assert.equal(next.id, "recovery");
  assert.equal(next.href, "#recent-remediations");
});
test("active job does not let previous report masquerade as current result", () => {
  assert.equal(select(host({ activeJob: true })).id, "running");
});
test("absent or corrupt summary never asserts a host has never been audited", () => {
  const unknown = select(host({ riskSummary: undefined }));
  assert.equal(unknown.id, "unknown");
  assert.match(unknown.detail, /не означает, что проверок не было/);
  assert.equal(select(host({ riskSummary: risk({ auditCount: 0, freshCount: 1 }) })).id, "unknown");
  assert.equal(select(host({ riskSummary: risk({ auditCount: -1 }) })).id, "unknown");
  assert.equal(select(host({ riskSummary: risk({ critical: NaN }) })).id, "unknown");
  assert.equal(select(host({ riskSummary: risk({ auditCount: 0, freshCount: 0 }) })).id, "first_audit");
});
test("old reports excluded after identity change require checking the host again", () => {
  const state = select(host({ riskSummary: risk({
    auditCount: 0, freshCount: 0, identityExcludedCount: 1,
  }) }));
  assert.equal(state.id, "identity");
});
test("stale results, missing freshness, partial and counter conflicts cannot authorize triage", () => {
  for (const fields of [
    { freshCount: 0, staleCount: 2 },
    { freshCount: 1, partialCount: 1 },
    { freshCount: 1, staleCount: 1 },
    { freshCount: 2, identityExcludedCount: 1 },
    { freshCount: 3 },
    { freshCount: 1, staleCount: 0, partialCount: 0 },
  ]) {
    const state = select(host({ riskSummary: risk({ critical: 7, ...fields }) }));
    assert.ok(["repeat", "coverage"].includes(state.id), JSON.stringify(fields));
  }
});
test("even unknown or low risk is a finding requiring assessment", () => {
  for (const band of ["critical", "high", "medium", "low", "unknown"]) {
    assert.equal(select(host({ riskSummary: risk({ [band]: 1 }) })).id, "triage");
  }
});
test("fresh zero-findings state is not described as secure", () => {
  const state = select(host({ riskSummary: risk({}) }));
  assert.equal(state.id, "report");
  assert.match(state.detail, /не означает отсутствие всех уязвимостей/);
});
test("workflow builds a host-bounded correlation URL", () => {
  assert.equal(select(host({ alias: "audit.vm-1", riskSummary: risk({ high: 1 }) })).href,
    "/reports/correlation/audit.vm-1");
});
