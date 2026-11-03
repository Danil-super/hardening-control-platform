import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["dashboard-evidence-status"]);
const { describeHostAuditEvidence, summarizeDashboardEvidence } = await import(compiled.url("dashboard-evidence-status"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

const risk = overrides => ({
  critical: 1, high: 2, medium: 1, low: 0, unknown: 4,
  auditCount: 2, freshCount: 2, partialCount: 0, staleCount: 0,
  identityExcludedCount: 0, maxAgeHours: 168, ...overrides,
});

test("facts-only reports never count as a completed security audit", () => {
  const host = { alias: "astra-lab", reportCount: 4, lastReport: null,
    riskSummary: risk({ auditCount: 0, freshCount: 0, critical: 0, high: 0, unknown: 0 }) };
  assert.equal(describeHostAuditEvidence(host).state, "no_audit");
  assert.equal(summarizeDashboardEvidence([host]).hostsWithAudits, 0);
});

test("fresh sources with gaps or changed asset identity are not shown as fully assessed", () => {
  for (const fields of [
    { partialCount: 1 }, { staleCount: 1 }, { identityExcludedCount: 1 },
  ]) {
    assert.equal(describeHostAuditEvidence({ alias: "node", riskSummary: risk(fields) }).state, "needs_review");
  }
  assert.equal(describeHostAuditEvidence({
    alias: "node", riskSummary: risk({ freshCount: 0, staleCount: 2 }),
  }).state, "stale");
});

test("separate risk and unknown severity without inventing a security score", () => {
  const hosts = [
    { alias: "a", riskSummary: risk({}) },
    { alias: "b", riskSummary: risk({ partialCount: 1, critical: 0, high: 3, unknown: 1 }) },
    { alias: "c", riskSummary: risk({ auditCount: 0, freshCount: 0, critical: 0, high: 0, unknown: 0 }) },
  ];
  const result = summarizeDashboardEvidence(hosts);
  assert.deepEqual([result.totalHosts, result.freshEvidenceHosts, result.needsReviewHosts,
    result.noFreshEvidenceHosts, result.hostsWithAudits], [3, 1, 1, 1, 2]);
  assert.equal(result.criticalHighFindings, 6);
  assert.equal(result.unknownSeverityFindings, 5);
  assert.equal("securityScore" in result, false);
});

test("malformed counters do not yield a false completeness or negative findings", () => {
  const result = summarizeDashboardEvidence([
    { alias: "unknown", riskSummary: risk({ auditCount: NaN, freshCount: -1,
      high: -5, critical: Infinity, unknown: -1 }) },
  ]);
  assert.equal(result.freshEvidenceHosts, 0);
  assert.equal(result.criticalHighFindings, 0);
  assert.equal(result.unknownSeverityFindings, 0);
});


test("inconsistent counts must never promote a host to fresh evidence", () => {
  const inconsistent = [
    { auditCount: 2, freshCount: 3 },
    { auditCount: 2, staleCount: 3, freshCount: 1 },
    { auditCount: 2, partialCount: 3, freshCount: 1 },
    { auditCount: 2, freshCount: 1, partialCount: 0, staleCount: 0 },
    { auditCount: 2, freshCount: 2, staleCount: 1 },
  ];
  for (const fields of inconsistent) {
    assert.equal(
      describeHostAuditEvidence({ alias: "inconsistent", riskSummary: risk(fields) }).state,
      "needs_review",
      JSON.stringify(fields),
    );
  }
});

test("missing fresh evidence takes priority over remediation when a different host was audited", () => {
  const result = summarizeDashboardEvidence([
    { alias: "fresh", riskSummary: risk({}) },
    { alias: "stale", riskSummary: risk({ freshCount: 0, staleCount: 2 }) },
  ]);
  assert.equal(result.freshEvidenceHosts, 1);
  assert.equal(result.noFreshEvidenceHosts, 1);
  assert.equal(result.hostsWithAudits, 2);
});
