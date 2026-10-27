import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, beforeEach, afterEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["host-risk-summary", "ansible-reports", "audit-correlation"]);
const { buildHostRiskSummary, riskBandOf } = await import(compiled.url("host-risk-summary"));
const { listAnsibleReports } = await import(compiled.url("ansible-reports"));
let directory;
beforeEach(() => { directory = mkdtempSync(path.join(tmpdir(), "hcp-host-risks-")); process.env.HCP_REPORTS_DIR = directory; });
afterEach(() => rmSync(directory, { recursive: true, force: true }));
after(() => { delete process.env.HCP_REPORTS_DIR; rmSync(compiled.directory, { recursive: true, force: true }); });
const item = (id, overrides = {}) => ({ id, profileId: "basic_linux", title: id, category: "test", risk: "high", status: "failed", source: "agentless", description: "test", recommendation: "test", ...overrides });
function save(name, mode, findings, ageHours = 1, overrides = {}) {
  writeFileSync(path.join(directory, name + ".json"), JSON.stringify({ inventoryHost: "host-one", mode, profileId: mode === "agentless" ? "basic_linux" : mode, createdAt: new Date(Date.now() - ageHours * 3600_000).toISOString(), findings, ...overrides }));
}
const summary = () => buildHostRiskSummary("host-one", listAnsibleReports());

test("host risks combine latest tool results, never the entire history or diagnostic findings", () => {
  save("old", "agentless", [item("old-risk"), item("old-risk-two")], 2);
  save("latest", "agentless", [item("ssh-root")]);
  save("lynis", "lynis", [item("suggestion", { source: "lynis", risk: "low", status: "manual" })]);
  save("facts", "facts", [item("not-an-audit")], 0.1);
  save("events", "events", [item("not-a-vulnerability")], 0.1);
  const risks = summary();
  assert.equal(risks.high, 1);
  assert.equal(risks.low, 1);
  assert.equal(risks.total, 2);
  assert.equal(risks.auditCount, 2);
});

test("critical and unknown are distinct from high and information; cache detects new evidence", () => {
  save("oval", "astra-oval", [item("oval:1", { source: "openscap", profileId: "astra-oval", title: "CVE-2024-10487: chromium", description: "(Chromium security severity: Critical)", evidence: '{"vendorSeverity":null}', severityUnknown: true, risk: "info" }), item("unknown", { source: "openscap", profileId: "astra-oval", risk: "info", severityUnknown: true })]);
  const first = summary();
  assert.equal(first.critical, 1); assert.equal(first.high, 0); assert.equal(first.unknown, 1); assert.equal(first.info, 0);
  assert.equal(riskBandOf({ risk: "high", severityUnknown: true, severityAssessment: { level: "critical" } }), "unknown");
  save("oval", "astra-oval", []);
  assert.equal(summary().total, 0);
  assert.equal(listAnsibleReports()[0].findingsCount, 0);
});

test("a new diagnostic report cannot clear risks, while a new passing audit can", () => {
  save("audit", "agentless", [item("risk")]);
  assert.equal(summary().high, 1);
  save("new-facts", "facts", [], 0);
  assert.equal(summary().high, 1);
  save("new-audit", "agentless", [item("risk", { status: "passed" })], 0);
  assert.equal(summary().high, 0);
});

test("stale and partial coverage stays visible, including expiry of cached summaries", () => {
  save("old", "agentless", [item("old-risk")], 200);
  save("partial", "lynis", [item("suggestion", { source: "lynis", risk: "low", status: "manual" })], 1, { scanner: { available: true, partial: true } });
  assert.equal(summary().staleCount, 1); assert.equal(summary().partialCount, 1);
  assert.equal(summary().low, 1);
  const now = Date.now;
  try { Date.now = () => now() + 170 * 3600_000; assert.equal(summary().low, 0); assert.equal(summary().freshCount, 0); }
  finally { Date.now = now; }
});

test("overlapping checks from two HCP profiles are grouped instead of counted twice", () => {
  save("basic", "agentless", [item("ssh-root")]);
  save("ssh", "agentless", [item("ssh-root", { profileId: "ssh_security" })], 1, { profileId: "ssh_security" });
  assert.equal(summary().auditCount, 2);
  assert.equal(summary().high, 1);
});
test("explicit Critical from Trivy and XCCDF survives the legacy high-priority mapping", () => {
  save("trivy", "vulnerabilities", [item("cve", { source: "trivy", evidence: "package=test; severity=CRITICAL; status=affected" }), item("high", { source: "trivy", evidence: "severity=HIGH" })]);
  save("xccdf", "openscap", [item("rule", { source: "openscap", profileId: "openscap", evidence: "rule=test; severity=critical; result=fail" })]);
  save("prose", "agentless", [item("not-metadata", { description: "Critical impact", evidence: "severity=critical" })]);
  const risks = summary();
  assert.equal(risks.critical, 2);
  assert.equal(risks.high, 2);
});
test("unrated Trivy CVEs are unknown, not informational observations", () => {
  save("trivy", "vulnerabilities", [item("CVE-2025-10000", { source: "trivy", risk: "info", evidence: "severity=UNKNOWN; package=test" }), item("CVE-2025-10001", { source: "trivy", risk: "info", evidence: "package=test" })]);
  const risks = summary();
  assert.equal(risks.unknown, 2); assert.equal(risks.info, 0);
});
