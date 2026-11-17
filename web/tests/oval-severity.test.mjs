import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ansible-reports"]);
const { normalizeOvalFinding, readAnsibleReport } = await import(compiled.url("ansible-reports"));
const { parseOvalCvss3 } = await import(compiled.url("oval-cvss"));
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

test("CVSS 3 uses explicit bounded scores and complete vectors, never prose or arbitrary numbers", () => {
  const vector = "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H";
  for (const [score, level] of [[0.1, "low"], [3.9, "low"], [4, "medium"], [6.9, "medium"], [7, "high"], [8.9, "high"], [9, "critical"], [10, "critical"]]) {
    const cvss3 = { version: "3.0", score, vector };
    const result = normalizeOvalFinding({ ...base, title: "poppler", description: "evidence", evidence: JSON.stringify({ vendorSeverity: null, cvss3 }) });
    assert.equal(result.severityUnknown, false); assert.equal(result.severityAssessment.level, level);
    assert.equal(result.severityAssessment.score, score); assert.equal(result.severityAssessment.source, "oval_cvss3");
  }
  for (const score of [0, -1, 11, NaN, Infinity, "9.8", 6.555]) assert.equal(parseOvalCvss3({ version: "3.0", score, vector }), null);
  for (const vector of ["", "AV:N", "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:XYZ", "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/I:H"]) assert.equal(parseOvalCvss3({ version: "3.0", score: 9, vector }), null);
});

test("historical CVSS comes from the digest-bound original; changed XML invalidates cached interpretation", () => {
  process.env.HCP_REPORTS_DIR = reports;
  const id = "astra-1-astra-oval-run-cvss", sourcePath = path.join(reports, ".raw-evidence", id, "source.xml");
  mkdirSync(path.dirname(sourcePath), { recursive: true, mode: 0o700 });
  const xml = `<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><definitions><definition id="${base.id}" class="vulnerability"><metadata><bdu><CVSS3.0>NistCVSS3(cvss='AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H', score=6.5)</CVSS3.0></bdu></metadata></definition></definitions></oval_definitions>`;
  const sha256 = createHash("sha256").update(xml).digest("hex");
  writeFileSync(sourcePath, xml);
  const raw = { mode: "astra-oval", profileId: "astra-oval", inventoryHost: "astra-1", createdAt: new Date().toISOString(), scanner: { database: { sha256 } }, rawEvidence: { version: 1, artifacts: [{ kind: "source", path: `.raw-evidence/${id}/source.xml`, bytes: Buffer.byteLength(xml), sha256 }] }, findings: [{ ...base, title: "poppler", description: "evidence" }] };
  const original = JSON.stringify(raw), reportPath = path.join(reports, id + ".json"); writeFileSync(reportPath, original);
  let result = readAnsibleReport(id);
  assert.equal(result.findings[0].severityAssessment.source, "oval_cvss3");
  assert.equal(result.findings[0].severityAssessment.score, 6.5);
  assert.equal(result.medium, 1); assert.equal(result.unknown, 0);
  assert.equal(result.raw.findings[0].severityUnknown, true);
  assert.equal(readFileSync(reportPath, "utf8"), original);
  assert.equal(readFileSync(sourcePath, "utf8"), xml);
  writeFileSync(sourcePath, xml.replace("score=6.5", "score=9.5"));
  result = readAnsibleReport(id);
  assert.equal(result.findings[0].severityUnknown, true);
  assert.equal(result.unknown, 1);
  assert.equal(result.critical, 0);
});
