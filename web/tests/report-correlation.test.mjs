import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, beforeEach, afterEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ansible-reports", "audit-correlation", "auth-edge"]);
const reports = await import(compiled.url("ansible-reports"));
const { buildHostCorrelation } = await import(compiled.url("audit-correlation"));
const { isProtectedPath } = await import(compiled.url("auth-edge"));
const oldDirectory = process.env.HCP_REPORTS_DIR;
let directory;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-report-correlation-"));
  process.env.HCP_REPORTS_DIR = directory;
});
afterEach(() => rmSync(directory, { recursive: true, force: true }));
after(() => {
  if (oldDirectory === undefined) delete process.env.HCP_REPORTS_DIR; else process.env.HCP_REPORTS_DIR = oldDirectory;
  rmSync(compiled.directory, { recursive: true, force: true });
});

function finding(id, source, evidence, overrides = {}) {
  return { id, source, title: id, category: "test", profileId: source, risk: "high", status: "failed", description: "test", recommendation: "Check the evidence", remediationAvailable: false, evidence, ...overrides };
}
function save(name, overrides = {}) {
  writeFileSync(path.join(directory, `${name}.json`), JSON.stringify({
    inventoryHost: "host-one", hostname: "different-display-hostname", mode: "nmap", profileId: "nmap",
    createdAt: new Date(Date.now() - 60000).toISOString(), scanner: { available: true, partial: false },
    findings: [], summary: { score: null, high: 0 }, ...overrides,
  }));
}

test("correlation routes require the same login as individual reports", () => {
  for (const route of ["/reports/correlation", "/reports/correlation/host-one", "/reports/agentless", "/api/settings/openscap-policies"]) assert.equal(isProtectedPath(route), true, route);
  assert.equal(isProtectedPath("/api/ansible/auth/login"), false);
});

test("inventoryHost is authoritative even when filenames suggest another host", () => {
  save("foo-nmap-run-test", { inventoryHost: "foo-bar", findings: [finding("port", "nmap", "port=tcp/8080")] });
  const report = reports.listAnsibleReports()[0];
  assert.equal(reports.targetAliasFromReport(report), "foo-bar");
  assert.equal(buildHostCorrelation("foo").findings.length, 0);
  assert.equal(buildHostCorrelation("foo-bar").findings.length, 1);
  assert.equal(reports.targetAliasFromReportFileName("foo-nmap-server-nmap-run-test.json", "nmap", "nmap"), "foo-nmap-server");
  assert.equal(reports.targetAliasFromReportFileName("foo-bar-basic_linux.json", "basic_linux", "agentless"), "foo-bar");
});

test("future-dated reports cannot replace the latest usable audit", () => {
  save("host-one-nmap-run-normal", { findings: [finding("real", "nmap", "port=tcp/8080")] });
  save("host-one-nmap-run-future", { createdAt: "2099-01-01T00:00:00Z", findings: [finding("future", "nmap", "port=tcp/22")] });
  const listed = reports.listAnsibleReports();
  assert.equal(listed[0].id, "host-one-nmap-run-normal");
  assert.equal(listed[1].reportTimeValid, false);
  assert.deepEqual(buildHostCorrelation("host-one").findings.map((item) => item.title), ["real"]);
});

test("matching ports do not collapse distinct issues or prove vulnerability", () => {
  save("host-one-nmap-run-test", { findings: [finding("port-open", "nmap", "port=tcp/22")] });
  save("host-one-ssh-audit-run-test", { mode: "ssh-audit", profileId: "ssh-audit", findings: [finding("weak-kex", "ssh_audit", "port=tcp/22; algorithm=diffie-hellman-group1-sha1")] });
  const result = buildHostCorrelation("host-one");
  assert.equal(result.findings.length, 2);
  assert.ok(result.findings.every((item) => item.confidence === "observed"));
  assert.ok(result.findings.every((item) => !item.description.includes("подтверждена")));
});

test("the same CVE in different packages remains separately actionable", () => {
  save("host-one-vulnerabilities-run-test", { mode: "vulnerabilities", profileId: "cve_packages", findings: [
    finding("CVE-2026-12345 first", "trivy", "package=first; installed=1.0"),
    finding("CVE-2026-12345 second", "trivy", "package=second; installed=2.0"),
  ] });
  const result = buildHostCorrelation("host-one");
  assert.equal(result.findings.length, 2);
  assert.ok(result.findings.some((item) => item.title.includes("first")));
  assert.ok(result.findings.some((item) => item.title.includes("second")));
});

test("partial scans hide aggregate scores and retain limitations in coverage", () => {
  save("host-one-vulnerabilities-run-test", { mode: "vulnerabilities", profileId: "cve_packages", vulnerabilityScan: { partial: true }, summary: { score: 100 }, findings: [finding("CVE-2026-12345", "trivy", "package=first")] });
  save("host-one-openscap-run-test", { mode: "openscap", profileId: "openscap", scanner: { available: false }, summary: { score: 100 } });
  save("host-one-dependency-track-run-test", { mode: "dependency-track", profileId: "dependency-track", findings: [finding("upload", "dependency_track", "accepted", { status: "passed" })] });
  const result = buildHostCorrelation("host-one");
  assert.ok(reports.listAnsibleReports().every((item) => item.score === null));
  assert.equal(result.findings[0].confidence, "manual");
  assert.equal(result.coverage.find((item) => item.mode === "openscap").available, false);
  assert.equal(result.coverage.find((item) => item.mode === "dependency-track").auditEvidence, false);
  assert.equal(result.freshReports.filter((item) => !item.partial).length, 0);
});

test("legacy vulnerability score and finding count never become protection percentage or event count", () => {
  save("host-one-vulnerabilities-run-legacy", { mode: "vulnerabilities", profileId: "cve_packages", summary: { score: 100, total: 12 }, findings: [] });
  const report = reports.listAnsibleReports()[0];
  assert.equal(report.score, null);
  assert.equal(report.eventsCount, 0);
});

test("malformed findings cannot crash correlation or produce a complete report", () => {
  save("host-one-nmap-run-malformed", { findings: [null, "invalid", { id: "missing-fields" }] });
  const report = reports.listAnsibleReports()[0];
  assert.equal(report.partial, true);
  assert.equal(buildHostCorrelation("host-one").findings.length, 0);
});

test("manual policy recommendations do not make completed probes unavailable", () => {
  save("host-one-basic_linux-run-manual", { mode: "agentless", profileId: "basic_linux", summary: { score: 80 }, scanner: { partial: false }, findings: [finding("root_account_present", "agentless", "root account exists", { status: "manual" })] });
  const report = reports.listAnsibleReports()[0];
  assert.equal(report.partial, false);
  assert.equal(report.needsReview, true);
  assert.equal(report.score, 80);
  assert.equal(buildHostCorrelation("host-one").findings[0].confidence, "manual");
});
