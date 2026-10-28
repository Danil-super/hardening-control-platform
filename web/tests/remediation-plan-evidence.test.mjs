import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { execFileSync } from "node:child_process";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["remediation-plan", "project-report"]);
const state = mkdtempSync(path.join(tmpdir(), "hcp-plan-proof-state-"));
const reports = mkdtempSync(path.join(tmpdir(), "hcp-plan-proof-reports-"));
process.env.HCP_STATE_DIR = state;
process.env.HCP_REPORTS_DIR = reports;
process.env.HCP_AUDIT_HMAC_KEY = "plan-proof-fixture-key";
const plans = await import(compiled.url("remediation-plan"));
const store = await import(compiled.url("state-store"));
const correlation = await import(compiled.url("audit-correlation"));
const pdf = await import(compiled.url("project-report"));
after(() => {
  delete process.env.HCP_STATE_DIR;
  delete process.env.HCP_REPORTS_DIR;
  delete process.env.HCP_AUDIT_HMAC_KEY;
  for (const directory of [compiled.directory, state, reports]) rmSync(directory, { recursive: true, force: true });
});

const finding = (extra = {}) => ({ id: "password_auth", profileId: "ssh_security", title: "Password authentication", category: "SSH",
  risk: "high", status: "failed", source: "agentless", description: "Password authentication is enabled.",
  recommendation: "Apply approved configuration.", evidence: "PasswordAuthentication yes", remediationAvailable: false, ...extra });
const delay = () => new Promise((resolve) => setTimeout(resolve, 8));
function writeReport(host, name, findings, extra = {}) {
  const id = `${host}-${name}`;
  writeFileSync(path.join(reports, `${id}.json`), JSON.stringify({ inventoryHost: host, hostname: host,
    createdAt: new Date().toISOString(), mode: "agentless", profileId: "ssh_security", scanner: { available: true, partial: false }, findings, ...extra }));
  return id;
}
async function completed(host, original = finding(), extra = {}) {
  const originalReportId = writeReport(host, "before", Array.isArray(original) ? original : [original], extra);
  const item = plans.addCorrelatedFindingToPlan(host, correlation.buildHostCorrelation(host).findings[0].id);
  plans.advanceRemediationPlanItem({ id: item.id, status: "proposed", note: "Apply reviewed fixture change." });
  plans.advanceRemediationPlanItem({ id: item.id, status: "agreed", note: "Approved through fixture ticket.",
    owner: "Fixture owner", dueAt: new Date(Date.now() + 86400000).toISOString(), approvalReference: "FIXTURE-1" });
  plans.advanceRemediationPlanItem({ id: item.id, status: "completed", note: "Approved fixture work was performed." });
  await delay();
  return { id: item.id, originalReportId };
}
const confirm = (item, verificationReportId) => plans.advanceRemediationPlanItem({ id: item.id, status: "confirmed", verificationReportId,
  note: "The corresponding control was checked again." });

test("confirmation rejects failed/manual evidence, missing coverage, unrelated facts and another profile", async () => {
  for (const [name, findings, extra, error] of [
    ["failed", [finding()], {}, /всё ещё/],
    ["manual", [finding({ status: "manual" })], {}, /всё ещё/],
    ["missing", [], {}, /не содержит доказанного/],
    ["facts", [], { mode: "facts", profileId: "facts" }, /не проверяет/],
    ["other-profile", [finding({ status: "passed" })], { profileId: "basic_linux" }, /совпадение/],
    ["partial", [finding({ status: "passed" })], { partial: true }, /полный свежий/],
    ["missing-time", [finding({ status: "passed" })], { createdAt: null }, /полный свежий/],
    ["future-time", [finding({ status: "passed" })], { createdAt: new Date(Date.now() + 3600000).toISOString() }, /полный свежий/],
    ["other-host", [finding({ status: "passed" })], { inventoryHost: "somebody-else" }, /этому хосту/],
  ]) {
    const host = `proof-${name}`;
    const item = await completed(host);
    const reportId = writeReport(host, "after", findings, extra);
    assert.throws(() => confirm(item, reportId), error, name);
    assert.equal(store.getRemediationPlanItem(item.id).status, "completed");
  }
});

test("new PDF snapshots and rendered text retain loss of earlier OpenSCAP coverage", async () => {
  const host = "pdf-scope-loss";
  const original = finding({ id: "scope_rule_A", profileId: "openscap", source: "openscap", evidence: "rule=scope_rule_A" });
  writeReport(host, "before", [original], { mode: "openscap", profileId: "openscap",
    scanner: { available: true, partial: false, profile: "profile_A", datastreamChecksum: "sha256:" + "a".repeat(64) } });
  await delay();
  writeReport(host, "after", [{ ...original, id: "scope_rule_B", status: "passed", evidence: "rule=scope_rule_B" }], { mode: "openscap", profileId: "openscap",
    scanner: { available: true, partial: false, profile: "profile_B", datastreamChecksum: "sha256:" + "a".repeat(64) } });
  const result = await pdf.createProjectReport({ hostAlias: host, subject: { clientName: "Fixture client", projectName: "Coverage change", period: "Fixture period", specialist: "Fixture reviewer" } });
  const snapshot = JSON.parse(readFileSync(path.join(state, "project-reports", result.fileName.replace(/\.pdf$/, ".json")), "utf8"));
  assert.equal(snapshot.lostCoverage.length, 1);
  assert.equal(snapshot.lostCoverage[0].profileId, "profile_A");
  assert.ok(snapshot.coverage.some((entry) => entry.current === false && entry.fresh === false));
  const visible = execFileSync("/usr/bin/python3", ["-c", `
import base64,re,sys,zlib
streams=[]
for raw in re.findall(rb'stream\\r?\\n(.*?)endstream',sys.stdin.buffer.read(),re.S):
    try:
        raw=raw.strip()
        if raw.endswith(b'~>'): raw=base64.a85decode(raw,adobe=True)
        streams.append(zlib.decompress(raw))
    except (ValueError,zlib.error): pass
print('visible' if b'profile_A' in b'\\n'.join(streams) else 'missing')
`], { input: pdf.readProjectReportPdf(result.id).pdf, encoding: "utf8" });
  assert.equal(visible.trim(), "visible");
});

test("the explicit successful same control confirms, while changed source bytes and superseded observations do not", async () => {
  const item = await completed("proof-good");
  assert.equal(confirm(item, writeReport("proof-good", "after", [finding({ status: "passed", evidence: "PasswordAuthentication no" })])).status, "confirmed");
  const changed = await completed("proof-changed");
  const changedPath = path.join(reports, `${changed.originalReportId}.json`);
  writeFileSync(changedPath, readFileSync(changedPath, "utf8") + "\n");
  assert.throws(() => confirm(changed, writeReport("proof-changed", "after", [finding({ status: "passed" })])), /неизменённое исходное/);
  const superseded = await completed("proof-newer");
  const clean = writeReport("proof-newer", "clean", [finding({ status: "passed" })]);
  await delay();
  writeReport("proof-newer", "failed-again", [finding()]);
  assert.throws(() => confirm(superseded, clean), /более новый/);
  assert.equal(store.verifyAuditChain().valid, true);
});

test("OpenSCAP verification requires the same real profile and content", async () => {
  const original = finding({ id: "xccdf_rule_sshd", source: "openscap", profileId: "openscap", evidence: "rule=xccdf_rule_sshd" });
  const source = { mode: "openscap", profileId: "openscap", scanner: { available: true, partial: false, profile: "profile_A", datastreamChecksum: "sha256:" + "a".repeat(64) } };
  for (const [name, scanner, succeeds] of [
    ["same", source.scanner, true],
    ["profile", { ...source.scanner, profile: "profile_B" }, false],
    ["content", { ...source.scanner, datastreamChecksum: "sha256:" + "b".repeat(64) }, false],
    ["unknown", { available: true, partial: false, profile: "profile_A" }, false],
  ]) {
    const host = `proof-scap-${name}`;
    const item = await completed(host, original, source);
    const reportId = writeReport(host, "after", [{ ...original, status: "passed" }], { ...source, scanner });
    if (succeeds) assert.equal(confirm(item, reportId).status, "confirmed");
    else assert.throws(() => confirm(item, reportId), /совпадение|полный свежий/);
  }
});

test("every failed OpenSCAP instance must remain covered and pass before a grouped plan item is confirmed", async () => {
  const rule = "xccdf_org.example_rule_permissions";
  const originals = [
    finding({ id: `openscap_${rule}_5016c3c3db51`, source: "openscap", profileId: "openscap", evidence: `rule=${rule}; instance=/etc/a` }),
    finding({ id: `openscap_${rule}_79d24e96ede1`, source: "openscap", profileId: "openscap", evidence: `rule=${rule}; instance=/etc/b` }),
  ];
  const source = { mode: "openscap", profileId: "openscap", scanner: { available: true, partial: false, profile: "profile_A", datastreamChecksum: "sha256:" + "a".repeat(64) } };
  for (const missing of [0, 1, null]) {
    const host = `proof-scap-instances-${missing ?? "complete"}`;
    const item = await completed(host, originals, source);
    assert.equal(store.getRemediationPlanItem(item.id).evidence.length, 2);
    const after = originals.filter((_, index) => index !== missing).map((value) => ({ ...value, status: "passed" }));
    const reportId = writeReport(host, "after", after, source);
    const result = correlation.buildHostCorrelation(host);
    assert.equal(result.findings.length, 0);
    if (missing === null) {
      assert.equal(result.lostCoverage.length, 0);
      assert.equal(result.coverage.find((value) => value.current).partial, false);
      assert.equal(confirm(item, reportId).status, "confirmed");
    } else {
      assert.deepEqual(result.lostCoverage[0].ruleIds, [rule]);
      assert.deepEqual(result.lostCoverage[0].findingIds, [originals[missing].id]);
      assert.equal(result.coverage.find((value) => value.current).partial, true);
      assert.throws(() => confirm(item, reportId), /для каждого исходного объекта/);
      assert.equal(store.getRemediationPlanItem(item.id).status, "completed");
    }
  }
});

const ovalSource = (id, result = "true", digest = "c".repeat(64)) => ({ mode: "astra-oval", profileId: "astra-oval", scanner: {
  available: true, partial: false, evaluationPerformed: true, database: { sha256: digest },
  definitionResults: [{ id, class: "vulnerability", result, vendorSeverity: "critical", platformApplicability: { status: "astra_named" } }],
} });
test("Astra OVAL false proves resolution only for the evaluated original definition and pinned source", async () => {
  const id = "oval:fixture:def:1";
  const original = finding({ id, profileId: "astra-oval", source: "openscap", title: "CVE-2026-10101: fixture", evidence: JSON.stringify({ definitionId: id, vendorSeverity: "critical" }) });
  for (const [name, extra, succeeds] of [
    ["false", ovalSource(id, "false"), true],
    ["missing", ovalSource("oval:fixture:def:2", "false"), false],
    ["unknown", ovalSource(id, "unknown"), false],
    ["other-db", ovalSource(id, "false", "d".repeat(64)), false],
    ["not-run", { ...ovalSource(id, "false"), scanner: { ...ovalSource(id, "false").scanner, evaluationPerformed: false } }, false],
  ]) {
    const host = `proof-oval-${name}`;
    const item = await completed(host, original, ovalSource(id));
    const reportId = writeReport(host, "after", [], extra);
    if (succeeds) assert.equal(confirm(item, reportId).status, "confirmed");
    else assert.throws(() => confirm(item, reportId), /совпадение|не содержит доказанного/);
  }
});

test("Trivy requires a fresh post-work full inventory and rejects the same CVE/package under a new finding id", async () => {
  const original = finding({ id: "trivy_old_version", source: "trivy", profileId: "cve_packages", title: "CVE-2026-12345: fixture", evidence: "package=fixture; installed=1.0" });
  for (const name of ["good", "stale-inventory", "partial-coverage", "still-failed", "manual"]) {
    const host = `proof-trivy-${name}`;
    const item = await completed(host, original, { mode: "vulnerabilities", profileId: "cve_packages" });
    const inventoryId = writeReport(host, "packages", [], { mode: "packages", profileId: "packages",
      ...(name === "stale-inventory" ? { createdAt: new Date(Date.now() - 60000).toISOString() } : {}),
      packages: [{ name: "fixture", version: "2.0" }], packageInventory: { packageCount: 1 } });
    await delay();
    const findings = ["still-failed", "manual"].includes(name) ? [{ ...original, id: "trivy_new_version", status: name === "manual" ? "manual" : "failed", evidence: "package=fixture; installed=2.0" }] : [];
    const reportId = writeReport(host, "after", findings, { mode: "vulnerabilities", profileId: "cve_packages", vulnerabilityScan: {
      provider: "Trivy", partial: false, checkedPackages: 1, sourcePackageReportId: inventoryId,
      databaseFreshness: { status: "fresh" }, coverage: { complete: name !== "partial-coverage", inventoryPackages: 1, scannedPackages: 1 },
    } });
    if (name === "good") assert.equal(confirm(item, reportId).status, "confirmed");
    else assert.throws(() => confirm(item, reportId), /всё ещё|не содержит доказанного/);
  }
});

test("the plan and newly rendered PDFs preserve Critical/Unknown after a clean report", async () => {
  const host = "severity-history";
  const original = [
    finding({ id: "unknown", profileId: "astra-oval", source: "openscap", risk: "info", severityUnknown: true, title: "CVE-2026-10111: unrated", evidence: JSON.stringify({ vendorSeverity: null }) }),
    finding({ id: "critical", profileId: "astra-oval", source: "openscap", title: "CVE-2026-10112: critical", evidence: JSON.stringify({ vendorSeverity: "critical" }) }),
  ];
  const reportId = writeReport(host, "before", original, { mode: "astra-oval", profileId: "astra-oval" });
  for (const value of correlation.buildHostCorrelation(host).findings) plans.addCorrelatedFindingToPlan(host, value.id);
  const snapshot = async () => {
    const result = await pdf.createProjectReport({ hostAlias: host, subject: { clientName: "Fixture client", projectName: "Rating history", period: "Fixture period", specialist: "Fixture reviewer" } });
    assert.equal(pdf.readProjectReportPdf(result.id).pdf.subarray(0, 5).toString(), "%PDF-");
    return JSON.parse(readFileSync(path.join(state, "project-reports", result.fileName.replace(/\.pdf$/, ".json")), "utf8")).findings;
  };
  const before = await snapshot();
  await delay();
  writeReport(host, "after", [], { mode: "astra-oval", profileId: "astra-oval" });
  const after = await snapshot();
  const ratings = (items) => items.map(({ title, risk, severityUnknown, severityAssessment, severityOrigin }) => ({ title, risk, severityUnknown, severityAssessment, severityOrigin })).sort((a, b) => a.title.localeCompare(b.title));
  assert.deepEqual(ratings(after), ratings(before));
  assert.deepEqual(ratings(plans.remediationPlanForHost(host).items), ratings(before));
  assert.equal(after.find((value) => value.title.includes("10111")).severityUnknown, true);
  assert.equal(after.find((value) => value.title.includes("10112")).severityAssessment.level, "critical");

  // Simulate an old schema entry. Only the exact original bytes may recover it.
  const db = new DatabaseSync(path.join(state, "hcp.sqlite"));
  db.prepare("UPDATE remediation_plan_items SET severity_snapshot_json = NULL WHERE host_alias = ?").run(host);
  const recovered = plans.remediationPlanForHost(host).items;
  assert.ok(recovered.every((value) => value.severityOrigin === "source_evidence"));
  assert.equal(recovered.find((value) => value.title.includes("10112")).severityAssessment.level, "critical");
  const originalPath = path.join(reports, `${reportId}.json`);
  writeFileSync(originalPath, readFileSync(originalPath, "utf8") + "\n");
  const unavailable = plans.remediationPlanForHost(host).items;
  assert.ok(unavailable.every((value) => value.severityOrigin === "unknown_legacy" && value.severityUnknown && value.severityAssessment === null));
  assert.ok((await snapshot()).every((value) => value.severityUnknown === true));

  // Verify additive migration of a real previous SQLite schema in a new process.
  const legacy = mkdtempSync(path.join(tmpdir(), "hcp-plan-legacy-"));
  try {
    db.prepare("VACUUM INTO ?").run(path.join(legacy, "hcp.sqlite"));
    const legacyDb = new DatabaseSync(path.join(legacy, "hcp.sqlite"));
    legacyDb.exec("ALTER TABLE remediation_plan_items DROP COLUMN severity_snapshot_json");
    legacyDb.close();
    const output = execFileSync(process.execPath, ["--input-type=module", "-e", `const store=await import(${JSON.stringify(compiled.url("state-store"))}); console.log(JSON.stringify(store.listRemediationPlanItems("severity-history")));`],
      { encoding: "utf8", env: { ...process.env, HCP_STATE_DIR: legacy } });
    assert.ok(JSON.parse(output).every((value) => value.severityOrigin === "unknown_legacy"));
  } finally { rmSync(legacy, { recursive: true, force: true }); db.close(); }
});
