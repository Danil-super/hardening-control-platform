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
    createdAt: new Date(Date.now() - 60000).toISOString(), scanner: { available: true, partial: false,
      scanScope: "top_100", portCoverage: "top_100_tcp", coverageComplete: false },
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

const checksum = character => `sha256:${character.repeat(64)}`;
const ago = milliseconds => new Date(Date.now() - milliseconds).toISOString();
function saveScap(name, { profile = "profile-a", digest = checksum("a"), time = ago(60_000), findings = [], ...rest } = {}) {
  save(name, { mode: "openscap", profileId: "openscap", createdAt: time,
    scanner: { available: true, partial: false, profile, datastreamChecksum: digest }, findings, ...rest });
}

test("old Greenbone observations remain stale after a current import, including legacy JSON", () => {
  save("host-one-greenbone-run-imported", { mode: "greenbone", profileId: "greenbone", createdAt: ago(1000),
    scanner: { available: true, partial: false, scanStartedAt: "2020-01-01T00:00:00Z", scanEndedAt: "2020-01-01T01:00:00Z" },
    findings: [finding("old", "greenbone", "port=443/tcp")] });
  const report = reports.listAnsibleReports()[0];
  assert.equal(report.createdAt, "2020-01-01T01:00:00.000Z");
  assert.equal(report.observedAt, report.createdAt);
  assert.ok(Date.parse(report.importedAt) > Date.parse(report.observedAt));
  assert.equal(report.reportTimeValid, true);
  assert.equal(buildHostCorrelation("host-one").findings.length, 0);
  assert.equal(buildHostCorrelation("host-one").coverage[0].fresh, false);
});

test("Greenbone requires a valid native completion time instead of fresh createdAt or file mtime", () => {
  for (const end of [undefined, "invalid", "2025-02-30T00:00:00Z", "2025-01-01T00:00:00", "2099-01-01T00:00:00Z"]) {
    save("host-one-greenbone-run-bad-time", { mode: "greenbone", profileId: "greenbone", scanner: { available: true, partial: false, scanEndedAt: end } });
    const report = reports.readAnsibleReport("host-one-greenbone-run-bad-time");
    assert.equal(report.reportTimeValid, false, String(end));
    assert.equal(report.partial, true);
    assert.equal(report.createdAt, null);
    assert.equal(reports.reportTimestamp(report), 0);
    assert.equal(buildHostCorrelation("host-one").freshReports.length, 0);
  }
});

test("a reimport cannot replace a newer Greenbone observation and valid offset timestamps work", () => {
  const recent = ago(60_000);
  save("host-one-greenbone-run-recent", { mode: "greenbone", profileId: "greenbone", scanner: { available: true, scanEndedAt: recent },
    findings: [finding("recent", "greenbone", "port=443/tcp")] });
  save("host-one-greenbone-run-reimport", { mode: "greenbone", profileId: "greenbone", createdAt: ago(1000),
    scanner: { available: true, scanEndedAt: "2020-01-01T04:00:00+03:00" }, findings: [finding("old", "greenbone", "port=443/tcp")] });
  const result = buildHostCorrelation("host-one");
  assert.deepEqual(result.findings.map(item => item.title), ["recent"]);
  assert.equal(result.coverage[0].fresh, true);
  assert.equal(reports.readAnsibleReport("host-one-greenbone-run-reimport").createdAt, "2020-01-01T01:00:00.000Z");
});

test("OpenSCAP different real profiles preserve a coverage gap without merging old failures", () => {
  saveScap("host-one-openscap-run-a", { time: ago(120_000), findings: [finding("old-failure", "openscap", "rule=rule-a")] });
  saveScap("host-one-openscap-run-b", { profile: "profile-b", findings: [finding("pass-b", "openscap", "rule=rule-b", { status: "passed" })] });
  const result = buildHostCorrelation("host-one");
  assert.equal(result.findings.length, 0);
  assert.equal(result.lostCoverage.length, 1);
  assert.equal(result.lostCoverage[0].reason, "scope_changed");
  assert.equal(result.lostCoverage[0].profileId, "profile-a");
  const previous = result.coverage.find(item => item.profileId === "profile-a");
  assert.equal(previous.current, false);
  assert.equal(previous.fresh, false);
  assert.equal(previous.partial, true);
  assert.equal(previous.auditEvidence, false);
  assert.ok(result.coverage.find(item => item.current).coverageIssues.includes("previous_coverage_not_verified"));
  assert.equal(reports.reportScopesCompatible(reports.readAnsibleReport("host-one-openscap-run-a"), reports.readAnsibleReport("host-one-openscap-run-b")), false);
});

test("same OpenSCAP profile and content replaces previous results; content changes cannot clear them silently", () => {
  saveScap("host-one-openscap-run-old", { time: ago(120_000), findings: [finding("failed", "openscap", "rule=rule-a")] });
  saveScap("host-one-openscap-run-new", { findings: [finding("passed", "openscap", "rule=rule-a", { status: "passed" })] });
  assert.equal(buildHostCorrelation("host-one").findings.length, 0);
  assert.equal(buildHostCorrelation("host-one").lostCoverage.length, 0);
  assert.equal(reports.reportScopesCompatible(reports.readAnsibleReport("host-one-openscap-run-old"), reports.readAnsibleReport("host-one-openscap-run-new")), true);
  saveScap("host-one-openscap-run-new", { digest: checksum("b"), findings: [finding("passed", "openscap", "rule=rule-a", { status: "passed" })] });
  assert.equal(buildHostCorrelation("host-one").lostCoverage[0].reason, "scope_changed");
  assert.equal(reports.reportScopesCompatible(reports.readAnsibleReport("host-one-openscap-run-old"), reports.readAnsibleReport("host-one-openscap-run-new")), false);
});

test("a future-dated OpenSCAP policy never supplants a valid current scope", () => {
  saveScap("host-one-openscap-run-normal", { findings: [finding("real", "openscap", "rule=rule-a")] });
  saveScap("host-one-openscap-run-future", { profile: "profile-b", time: "2099-01-01T00:00:00Z", findings: [finding("future", "openscap", "rule=rule-b")] });
  const result = buildHostCorrelation("host-one");
  assert.deepEqual(result.findings.map(item => item.title), ["real"]);
  assert.equal(result.lostCoverage.length, 0);
  assert.equal(result.coverage.find(item => item.profileId === "profile-b").validTime, false);
  assert.equal(result.coverage.find(item => item.profileId === "profile-b").supersededBy, null);
});

test("OpenSCAP unknown legacy scope and missing previously evaluated rules remain explicit", () => {
  saveScap("host-one-openscap-run-legacy", { digest: undefined, scanner: { available: true, partial: false, profile: "profile-a" }, time: ago(120_000) });
  const legacy = reports.readAnsibleReport("host-one-openscap-run-legacy");
  assert.equal(legacy.profileId, "profile-a");
  assert.equal(legacy.scopeKnown, false);
  assert.equal(legacy.partial, true);
  assert.equal(reports.reportScopesCompatible(legacy, legacy), false);
  saveScap("host-one-openscap-run-before", { time: ago(90_000), findings: [finding("failed", "openscap", "rule=rule-a")] });
  saveScap("host-one-openscap-run-after", { findings: [finding("pass-b", "openscap", "rule=rule-b", { status: "passed" })] });
  const result = buildHostCorrelation("host-one");
  assert.ok(result.lostCoverage.some(item => item.reason === "scope_unknown"));
  assert.deepEqual(result.lostCoverage.find(item => item.reason === "rules_missing").ruleIds, ["rule-a"]);
  assert.equal(result.coverage.find(item => item.current).partial, true);
  assert.equal(result.findings.length, 0);
});

test("stable bundled source identity survives regenerated datastream bytes while retaining their exact hash", () => {
  const scanner = { available: true, partial: false, profile: "profile-a", contentIdentity: `bundle-sha256:${"c".repeat(64)}` };
  saveScap("host-one-openscap-run-old", { time: ago(120_000), scanner: { ...scanner, datastreamChecksum: checksum("a") }, findings: [finding("a", "openscap", "rule=rule-a")] });
  saveScap("host-one-openscap-run-new", { scanner: { ...scanner, datastreamChecksum: checksum("b") }, findings: [finding("a", "openscap", "rule=rule-a", { status: "passed" })] });
  const old = reports.readAnsibleReport("host-one-openscap-run-old"), current = reports.readAnsibleReport("host-one-openscap-run-new");
  assert.equal(reports.reportScopesCompatible(old, current), true);
  assert.equal(current.raw.scanner.datastreamChecksum, checksum("b"));
  assert.equal(buildHostCorrelation("host-one").lostCoverage.length, 0);
});

test("Astra OVAL verification requires the actual same database digest", () => {
  save("host-one-astra-oval-run-old", { mode: "astra-oval", profileId: "astra-oval", scanner: { database: { sha256: "a".repeat(64) } } });
  save("host-one-astra-oval-run-new", { mode: "astra-oval", profileId: "astra-oval", scanner: { database: { sha256: "b".repeat(64) } } });
  const old = reports.readAnsibleReport("host-one-astra-oval-run-old"), current = reports.readAnsibleReport("host-one-astra-oval-run-new");
  assert.equal(old.contentId, checksum("a"));
  assert.equal(reports.reportScopesCompatible(old, current), false);
  assert.equal(reports.reportScopesCompatible(old, old), true);
  assert.equal(reports.reportScopesCompatible({ ...old, contentId: null }, old), false);
});

test("known Nmap scopes distinguish a completed selected range from lost earlier coverage", () => {
  const scope = (scanScope, partial = false) => ({ available: true, partial, scanScope,
    portCoverage: scanScope === "full_tcp" ? "all_tcp_1_65535" : `${scanScope}_tcp`, coverageComplete: scanScope === "full_tcp" });
  for (const [before, after, lost] of [["top_100", "top_100", false], ["top_100", "top_1000", true],
    ["top_1000", "full_tcp", false], ["full_tcp", "top_1000", true], ["top_1000", "top_100", true]]) {
    const host = `${before}-${after}`;
    save(`${host}-before`, { inventoryHost: host, createdAt: ago(120000), scanner: scope(before) });
    save(`${host}-after`, { inventoryHost: host, scanner: scope(after) });
    const result = buildHostCorrelation(host);
    assert.equal(result.lostCoverage.length > 0, lost, `${before} -> ${after}`);
    if (before === "top_100" && after === "top_1000") assert.equal(result.lostCoverage[0].reason, "port_set_unknown");
    assert.equal(result.coverage.find((item) => item.current).partial, lost);
    assert.equal(reports.readAnsibleReport(`${host}-after`).partial, false);
    assert.equal(reports.reportScopesCompatible(reports.readAnsibleReport(`${host}-before`), reports.readAnsibleReport(`${host}-after`)), before === after);
  }
  save("incomplete-nmap-before", { inventoryHost: "incomplete-nmap", createdAt: ago(120000), scanner: scope("top_100") });
  save("incomplete-nmap-after", { inventoryHost: "incomplete-nmap", scanner: scope("full_tcp", true) });
  assert.equal(buildHostCorrelation("incomplete-nmap").lostCoverage[0].reason, "ports_unverified");
});

test("legacy or contradictory Nmap scope cannot imply full coverage, and package inventory partial metadata propagates", () => {
  for (const scanner of [{ available: true }, { scanScope: "custom" },
    { scanScope: "top_100", portCoverage: "all_tcp_1_65535", coverageComplete: true }]) {
    save("unknown-nmap", { scanner });
    const report = reports.readAnsibleReport("unknown-nmap");
    assert.equal(report.scopeKnown, false);
    assert.equal(report.partial, true);
    assert.equal(reports.reportScopesCompatible(report, report), false);
  }
  save("partial-inventory", { mode: "packages", profileId: "packages", partial: false,
    packageInventory: { partial: true, partialReasons: ["one package manager failed"] } });
  assert.equal(reports.readAnsibleReport("partial-inventory").partial, true);
});
