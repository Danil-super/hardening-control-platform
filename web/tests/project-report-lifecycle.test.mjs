import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import test, { after } from "node:test";
import ts from "typescript";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["remediation-plan", "project-report", "host-risk-summary"]);
const state = mkdtempSync(path.join(tmpdir(), "hcp-report-lifecycle-state-"));
const reports = mkdtempSync(path.join(tmpdir(), "hcp-report-lifecycle-reports-"));
process.env.HCP_STATE_DIR = state;
process.env.HCP_REPORTS_DIR = reports;
process.env.HCP_AUDIT_HMAC_KEY = "report-lifecycle-fixture-key";
const plans = await import(compiled.url("remediation-plan"));
const store = await import(compiled.url("state-store"));
const correlation = await import(compiled.url("audit-correlation"));
const reportApi = await import(compiled.url("ansible-reports"));
const project = await import(compiled.url("project-report"));
const risk = await import(compiled.url("host-risk-summary"));
const routeSource = ts.transpileModule(readFileSync(new URL("../app/api/ansible/reports/[reportId]/route.ts", import.meta.url), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
}).outputText.replace(/(["'])@\/lib\/([^"']+)\1/g, '"./$2.mjs"')
  .replace('"next/server"', JSON.stringify(new URL("../node_modules/next/server.js", import.meta.url).href));
writeFileSync(path.join(compiled.directory, "report-route.mjs"), routeSource);
const route = await import(pathToFileURL(path.join(compiled.directory, "report-route.mjs")).href);
after(() => {
  delete process.env.HCP_STATE_DIR;
  delete process.env.HCP_REPORTS_DIR;
  delete process.env.HCP_AUDIT_HMAC_KEY;
  for (const directory of [compiled.directory, state, reports]) rmSync(directory, { recursive: true, force: true });
});

const subject = { clientName: "Fixture client", projectName: "Lifecycle regression", period: "Fixture interval", specialist: "Fixture reviewer" };
const finding = (extra = {}) => ({ id: "password_auth", profileId: "ssh_security", title: "Password authentication", category: "SSH",
  risk: "high", status: "failed", source: "agentless", description: "Password authentication is enabled.",
  recommendation: "Apply the approved configuration.", evidence: "PasswordAuthentication yes", remediationAvailable: false, ...extra });
function save(host, suffix, findings = [], extra = {}) {
  const id = `${host}-${suffix}`;
  writeFileSync(path.join(reports, `${id}.json`), JSON.stringify({ inventoryHost: host, hostname: host, createdAt: new Date().toISOString(),
    mode: "agentless", profileId: "ssh_security", scanner: { available: true, partial: false }, findings, ...extra }));
  return id;
}
function add(host) { return plans.addCorrelatedFindingToPlan(host, correlation.buildHostCorrelation(host).findings[0].id); }
function propose(item) { return plans.advanceRemediationPlanItem({ id: item.id, status: "proposed", note: "Apply a reviewed fixture change." }); }
function complete(item) {
  propose(item);
  plans.advanceRemediationPlanItem({ id: item.id, status: "agreed", note: "Approved through the fixture ticket.", owner: "Fixture owner",
    dueAt: new Date(Date.now() + 86400000).toISOString(), approvalReference: "FIXTURE-APPROVAL" });
  plans.advanceRemediationPlanItem({ id: item.id, status: "completed", note: "The approved fixture change was performed." });
}
function confirm(item, reportId) { return plans.advanceRemediationPlanItem({ id: item.id, status: "confirmed", verificationReportId: reportId, note: "Every original object was checked again." }); }
async function exportReport(host) {
  const record = await project.createProjectReport({ hostAlias: host, subject });
  const snapshot = JSON.parse(readFileSync(path.join(state, "project-reports", record.fileName.replace(/\.pdf$/, ".json")), "utf8"));
  return { record, snapshot, pdf: project.readProjectReportPdf(record.id).pdf };
}
function visibleAscii(pdf) {
  return execFileSync("/usr/bin/python3", ["-c", `
import base64,re,sys,zlib
streams=[]
for raw in re.findall(rb'stream\\r?\\n(.*?)endstream',sys.stdin.buffer.read(),re.S):
    try:
        raw=raw.strip()
        if raw.endswith(b'~>'): raw=base64.a85decode(raw,adobe=True)
        streams.append(zlib.decompress(raw))
    except (ValueError,zlib.error): pass
sys.stdout.buffer.write(b'\\n'.join(streams))
`], { input: pdf, maxBuffer: 4 * 1024 * 1024 }).toString("latin1");
}
const removeReport = (reportId) => route.DELETE(new Request(`http://fixture.invalid/api/ansible/reports/${reportId}`, {
  method: "DELETE", body: JSON.stringify({ confirmReportId: reportId }),
}), { params: Promise.resolve({ reportId }) });

test("a recurrence is visible after confirmation without rewriting history or duplicating an unresolved plan", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const host = "lifecycle-recurrence";
  save(host, "before", [finding()]);
  const item = add(host); complete(item);
  t.mock.timers.tick(1000);
  confirm(item, save(host, "verified", [finding({ status: "passed", evidence: "PasswordAuthentication no" })]));
  const confirmed = store.getRemediationPlanItem(item.id);
  const history = store.listRemediationPlanHistory(item.id);
  const oldPdf = await exportReport(host);
  assert.equal(oldPdf.snapshot.unplannedFindings.length, 0);
  t.mock.timers.tick(1000);
  const recurrenceReport = save(host, "recurrence", [finding()]);
  const result = await exportReport(host);
  assert.equal(result.snapshot.unplannedFindings.length, 1, "a saved confirmation must not suppress a new failure");
  assert.equal(result.snapshot.unplannedFindings[0].recurring, true);
  assert.equal(result.snapshot.findings[0].status, "confirmed", "historical confirmation is immutable");
  assert.equal(result.snapshot.findings[0].currentObservation.sources[0].reportId, recurrenceReport);
  assert.equal(plans.remediationPlanForHost(host).items[0].currentObservation.recurring, true);
  assert.equal(risk.buildHostRiskSummary(host, reportApi.listAnsibleReports()).high, 1);
  assert.deepEqual(store.getRemediationPlanItem(item.id), confirmed);
  assert.deepEqual(store.listRemediationPlanHistory(item.id), history);
  assert.deepEqual(project.readProjectReportPdf(oldPdf.record.id).pdf, oldPdf.pdf);
  const active = add(host);
  assert.notEqual(active.id, item.id);
  assert.equal(add(host).id, active.id, "a repeated add reuses the active plan");
  const planned = await exportReport(host);
  assert.equal(planned.snapshot.unplannedFindings.length, 0, "the unresolved plan already contains the current observation");
  assert.equal(planned.snapshot.findings.find((value) => value.id === active.id).currentObservation.sources[0].reportId, recurrenceReport);
});

test("risk expiry is derived at viewing/export time, printed, and can be reopened without resubmitting an expired date", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const host = "lifecycle-expiry";
  save(host, "failed", [finding()]);
  const item = add(host); propose(item);
  const until = new Date(Date.now() + 1000).toISOString();
  plans.advanceRemediationPlanItem({ id: item.id, status: "accepted_risk", note: "Temporary fixture exception with an explicit deadline.",
    owner: "Fixture owner", approvalReference: "FIXTURE-EXCEPTION", riskAcceptedUntil: until });
  const history = store.listRemediationPlanHistory(item.id);
  const active = await exportReport(host);
  assert.equal(active.snapshot.findings[0].riskAcceptanceState, "active");
  assert.equal(active.snapshot.unplannedFindings.length, 0);
  assert.ok(active.snapshot.findings[0].currentObservation, "accepted risk does not erase the observed failure");
  t.mock.timers.tick(1001);
  const expired = await exportReport(host);
  assert.equal(expired.snapshot.findings[0].status, "accepted_risk");
  assert.equal(expired.snapshot.findings[0].riskAcceptanceState, "expired");
  assert.equal(expired.snapshot.unplannedFindings.length, 1);
  assert.ok(visibleAscii(expired.pdf).includes(until), "the real PDF must print the acceptance deadline");
  assert.equal(plans.planItemDetail(item.id).item.riskAcceptanceState, "expired");
  assert.deepEqual(store.listRemediationPlanHistory(item.id), history);
  assert.deepEqual(project.readProjectReportPdf(active.record.id).pdf, active.pdf);
  assert.equal(propose(item).status, "proposed");
  assert.equal(store.getRemediationPlanItem(item.id).approvalReference, "FIXTURE-EXCEPTION");
});

test("25 XCCDF instances survive plan creation, the actual PDF, and all-object verification", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const host = "lifecycle-instances";
  const rule = "xccdf_org.example_rule_permissions";
  const originals = Array.from({ length: 25 }, (_, index) => {
    const instance = `/etc/fixture-${index}`;
    return finding({ id: `openscap_${rule}_${createHash("sha256").update(instance).digest("hex").slice(0, 12)}`,
      profileId: "openscap", source: "openscap", evidence: `rule=${rule}; result=fail; instance=${instance}` });
  });
  const scope = { mode: "openscap", profileId: "openscap", scanner: { available: true, partial: false,
    profile: "fixture_profile", datastreamChecksum: "sha256:" + "a".repeat(64) } };
  save(host, "before", originals, scope);
  const item = add(host);
  assert.deepEqual(item.evidence.map((value) => value.findingId), originals.map((value) => value.id));
  complete(item);
  const exported = await exportReport(host);
  assert.equal(exported.snapshot.findings[0].evidence.length, 25);
  const visible = visibleAscii(exported.pdf);
  for (const original of originals) assert.ok(visible.includes(original.id), `PDF omitted ${original.id}`);
  t.mock.timers.tick(1000);
  const missing = save(host, "missing", originals.slice(0, -1).map((value) => ({ ...value, status: "passed" })), scope);
  assert.throws(() => confirm(item, missing), /для каждого исходного объекта/);
  t.mock.timers.tick(1000);
  const full = save(host, "full", originals.map((value) => ({ ...value, status: "passed" })), scope);
  assert.equal(confirm(item, full).status, "confirmed");
  const before = store.listRemediationPlanItems(host).length;
  assert.throws(() => store.createRemediationPlanItem({ ...item, findingKey: "oversized-fixture",
    evidence: Array.from({ length: 2500 }, () => ({ ...item.evidence[0], evidence: "x".repeat(4000) })) }), { code: "plan_evidence_too_large" });
  assert.equal(store.listRemediationPlanItems(host).length, before, "oversize rejection must not create a truncated plan");
});

test("Nmap scope reaches risk coverage and the real PDF, and broader scans restore coverage", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const host = "lifecycle-nmap";
  const scope = (scanScope) => ({ mode: "nmap", profileId: "nmap", scanner: { available: true, partial: false, scanScope,
    portCoverage: scanScope === "full_tcp" ? "all_tcp_1_65535" : `${scanScope}_tcp`, coverageComplete: scanScope === "full_tcp" } });
  const open = finding({ id: "nmap_tcp_65535", source: "nmap", profileId: "nmap", title: "Open TCP port 65535",
    risk: "info", status: "manual", evidence: "port=tcp/65535" });
  const wide = save(host, "wide", [open], scope("full_tcp"));
  t.mock.timers.tick(1000);
  const narrow = save(host, "narrow", [], scope("top_100"));
  const result = await exportReport(host);
  assert.equal(result.snapshot.unplannedFindings.length, 0, "historical observations must not be represented as freshly observed");
  assert.equal(result.snapshot.lostCoverage[0].reportId, wide);
  assert.equal(result.snapshot.lostCoverage[0].reason, "ports_not_checked");
  assert.deepEqual(result.snapshot.lostCoverage[0].findingIds, [open.id]);
  assert.equal(result.snapshot.coverage.find((value) => value.reportId === narrow).partial, true);
  assert.equal(risk.buildHostRiskSummary(host, reportApi.listAnsibleReports()).partialCount, 1);
  assert.equal(reportApi.readAnsibleReport(narrow).partial, false, "top-100 alone completed its chosen scope");
  assert.ok(visibleAscii(result.pdf).includes("top_100"));
  assert.ok(visibleAscii(result.pdf).includes("full_tcp"));
  assert.equal(result.snapshot.sourceManifest.find((value) => value.id === narrow).coverageComplete, false);
  t.mock.timers.tick(1000);
  save(host, "full-again", [], scope("full_tcp"));
  const restored = correlation.buildHostCorrelation(host);
  assert.equal(restored.lostCoverage.length, 0);
  assert.equal(restored.coverage.length, 1);
  assert.equal(restored.coverage[0].partial, false);
});

test("final history filters by host in SQLite and retains more than 500 transactions without cross-host contamination", async () => {
  const host = "lifecycle-history";
  save(host, "audit");
  function transaction(alias, id) {
    store.createRemediationTransaction({ id, hostAlias: alias, action: "closePort", profileId: "network",
      reason: "Isolated historical transaction fixture", parameters: {} });
    store.updateRemediationTransaction(id, { status: "applied", backupRef: `/fixture/backup/${id}` });
  }
  transaction(host, "txn-target-oldest");
  for (let index = 0; index < 501; index++) {
    transaction("lifecycle-other", `txn-other-${index}`);
    transaction(host, `txn-target-${index}`);
  }
  assert.equal(store.listRemediationTransactions(1, host).length, 1);
  assert.equal(store.listRemediationTransactions(1, host)[0].hostAlias, host);
  const exported = await exportReport(host);
  assert.equal(exported.snapshot.transactions.length, 502);
  assert.ok(exported.snapshot.transactions.some((item) => item.id === "txn-target-oldest"));
  assert.ok(exported.snapshot.transactions.every((item) => item.id.startsWith("txn-target-")));
  assert.equal(store.verifyAuditChain().valid, true);
});

test("deleting or changing a source during rendering aborts publication without orphan PDF files", async () => {
  for (const action of ["delete", "change"]) {
    const host = `lifecycle-render-${action}`;
    const id = save(host, "source");
    const before = readdirSync(path.join(state, "project-reports")).sort();
    const exporting = project.createProjectReport({ hostAlias: host, subject });
    const rejected = assert.rejects(exporting, /изменился или был удалён/);
    if (action === "delete") {
      const deleted = await removeReport(id);
      assert.equal(deleted.status, 200);
      assert.equal(existsSync(path.join(reports, `${id}.json`)), false);
    } else {
      const source = path.join(reports, `${id}.json`);
      writeFileSync(source, readFileSync(source, "utf8") + "\n");
    }
    await rejected;
    assert.equal(project.listProjectReports(host).length, 0);
    assert.deepEqual(readdirSync(path.join(state, "project-reports")).sort(), before);
  }
  const host = "lifecycle-render-normal";
  const id = save(host, "source");
  const result = await exportReport(host);
  assert.equal(result.pdf.subarray(0, 5).toString("ascii"), "%PDF-");
  assert.equal((await removeReport(id)).status, 409, "published source remains protected");
  assert.equal(store.verifyAuditChain().valid, true);
});
