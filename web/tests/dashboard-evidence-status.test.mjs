import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["dashboard-evidence-status"]);
const { describeHostAuditEvidence, summarizeDashboardEvidence, filterDashboardAssessments } = await import(compiled.url("dashboard-evidence-status"));
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

test("dashboard never labels the last diagnostic report as last security audit", () => {
  const recentFacts = { alias: "node", lastReport: { createdAt: "2026-11-03T18:45:00Z" },
    riskSummary: risk({ lastSecurityAuditAt: "2026-11-02T11:30:00Z" }) };
  assert.equal(describeHostAuditEvidence(recentFacts).lastAuditAt, "2026-11-02T11:30:00Z");
  const noAudit = { ...recentFacts, riskSummary: risk({ auditCount: 0, freshCount: 0,
    lastSecurityAuditAt: null }) };
  assert.equal(describeHostAuditEvidence(noAudit).lastAuditAt, null);
  const olderFactsWithoutEvidence = { ...recentFacts, riskSummary: risk({
    lastSecurityAuditAt: undefined,
  }) };
  assert.equal(describeHostAuditEvidence(olderFactsWithoutEvidence).lastAuditAt, null);
});


test("missing riskSummary is unknown, not proof that no audit ever happened", () => {
  const assessed = describeHostAuditEvidence({ alias: "older-host", lastReport: null });
  assert.equal(assessed.state, "unknown_evidence");
  const summary = summarizeDashboardEvidence([{ alias: "older-host" }]);
  assert.equal(summary.needsReviewHosts, 1);
  assert.equal(summary.noFreshEvidenceHosts, 0);
  assert.equal(summary.freshEvidenceHosts, 0);
});

test("severity distribution includes only consistent current evidence", () => {
  const hosts = [
    { alias: "fresh", riskSummary: risk({ critical: 2, high: 1, medium: 4, low: 3, unknown: 2 }) },
    { alias: "partly", riskSummary: risk({ freshCount: 1, staleCount: 1, critical: 0, high: 2, medium: 0, low: 0, unknown: 1 }) },
    { alias: "old", riskSummary: risk({ freshCount: 0, staleCount: 2, critical: 8, high: 9, unknown: 5 }) },
    { alias: "no-audit", riskSummary: risk({ auditCount: 0, freshCount: 0, critical: 5, high: 6 }) },
    { alias: "bad", riskSummary: risk({ auditCount: 1, freshCount: 2, critical: 9, high: 9 }) },
  ];
  const result = summarizeDashboardEvidence(hosts);
  assert.deepEqual(result.severity, { critical: 2, high: 3, medium: 4, low: 3, unknown: 3 });
  assert.equal(result.criticalHighFindings, 5);
  assert.equal(result.unknownSeverityFindings, 3);
  assert.equal(result.needsReviewHosts, 2);
  assert.equal(result.noFreshEvidenceHosts, 2);
  assert.equal(result.freshEvidenceHosts, 1);
});

test("host-state filters partition the inventory without double counting", () => {
  const hosts = [
    { alias: "fresh", riskSummary: risk({}) },
    { alias: "review", riskSummary: risk({ partialCount: 1 }) },
    { alias: "stale", riskSummary: risk({ freshCount: 0, staleCount: 2 }) },
    { alias: "absent", riskSummary: risk({ auditCount: 0, freshCount: 0 }) },
    { alias: "unknown" },
  ];
  const assessed = summarizeDashboardEvidence(hosts).assessed;
  assert.equal(filterDashboardAssessments(assessed, "all").length, 5);
  assert.deepEqual(filterDashboardAssessments(assessed, "fresh").map(x => x.alias), ["fresh"]);
  assert.deepEqual(filterDashboardAssessments(assessed, "review").map(x => x.alias), ["review", "unknown"]);
  assert.deepEqual(filterDashboardAssessments(assessed, "no_fresh").map(x => x.alias), ["stale", "absent"]);
});

test("malformed severity fields cannot inflate a critical count", () => {
  const assessed = describeHostAuditEvidence({ alias: "bad", riskSummary: risk({ critical: Infinity }) });
  assert.equal(assessed.state, "unknown_evidence");
  assert.equal(assessed.criticalHigh, 0);
  assert.deepEqual(assessed.severity, { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
});


test("asset identity-excluded history is review work, not a never-audited host", () => {
  const state = describeHostAuditEvidence({
    alias: "replaced-host",
    riskSummary: risk({ auditCount: 0, freshCount: 0, identityExcludedCount: 1 }),
  });
  assert.equal(state.state, "needs_review");
  assert.match(state.detail, /идентичности/);
  const overview = summarizeDashboardEvidence([{
    alias: "replaced-host",
    riskSummary: risk({ auditCount: 0, freshCount: 0, identityExcludedCount: 1 }),
  }]);
  assert.equal(overview.needsReviewHosts, 1);
  assert.equal(overview.noFreshEvidenceHosts, 0);
});
