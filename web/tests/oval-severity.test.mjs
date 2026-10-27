import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ansible-reports"]);
const { normalizeOvalFinding, readAnsibleReport } = await import(compiled.url("ansible-reports"));
const reports = mkdtempSync(path.join(tmpdir(), "hcp-severity-"));
after(() => { rmSync(compiled.directory, { recursive: true, force: true }); rmSync(reports, { recursive: true, force: true }); delete process.env.HCP_REPORTS_DIR; });
const base = { id: "oval:fixture:def:1", profileId: "astra-oval", title: "CVE-2026-10001: Astra — chromium", category: "CVE", status: "failed", source: "openscap", risk: "info", severityUnknown: true, description: "(Chromium security severity: Critical)", recommendation: "Update", evidence: '{"vendorSeverity":null}' };

test("explicit Chromium label has attribution; arbitrary prose cannot assign severity", () => {
  const result = normalizeOvalFinding(base);
  assert.equal(result.risk, "high");
  assert.equal(result.severityUnknown, false);
  assert.deepEqual(result.severityAssessment, { level: "critical", source: "chromium_description" });
  for (const changes of [{ description: "critical vulnerability, high impact" }, { title: "openssl" }, { description: "(Chromium security severity: High) (Chromium security severity: Low)" }, { evidence: '{"vendorSeverity":"unknown-vendor-level"}' }]) {
    assert.equal(normalizeOvalFinding({ ...base, ...changes }).severityUnknown, true);
  }
  const unrelated = { ...base, profileId: "other" };
  assert.equal(normalizeOvalFinding(unrelated), unrelated);
});

test("metadata wins, including Critical and Important, without inferring CVSS", () => {
  for (const [severity, level] of [["Critical", "critical"], ["Important", "high"], ["Moderate", "medium"], ["Low", "low"]]) {
    const result = normalizeOvalFinding({ ...base, evidence: JSON.stringify({ vendorSeverity: severity }) });
    assert.deepEqual(result.severityAssessment, { level, source: "oval_metadata" });
  }
  assert.deepEqual(normalizeOvalFinding({ ...base, evidence: '{"vendorSeverity":"High", "criteria":' }, { vendorSeverity: "High" }).severityAssessment, { level: "high", source: "oval_metadata" });
  assert.equal(normalizeOvalFinding({ ...base, evidence: '{"vendorSeverity":"custom", "criteria":' }, { vendorSeverity: "custom" }).severityUnknown, true);
});

test("historical view is classified consistently without rewriting the source JSON", () => {
  process.env.HCP_REPORTS_DIR = reports;
  const id = "astra-1-astra-oval-run-fixture";
  const pathname = path.join(reports, id + ".json");
  const original = JSON.stringify({ mode: "astra-oval", profileId: "astra-oval", inventoryHost: "astra-1", createdAt: new Date().toISOString(), findings: [base] });
  writeFileSync(pathname, original);
  const report = readAnsibleReport(id);
  assert.equal(report.high, 1);
  assert.equal(report.findings[0].severityAssessment.level, "critical");
  assert.equal(report.raw.findings[0].severityUnknown, true);
  assert.equal(readFileSync(pathname, "utf8"), original);
});
