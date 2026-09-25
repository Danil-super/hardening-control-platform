import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, afterEach, beforeEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ansible-reports", "audit-repeat"]);
const { findRepeatAuditNotice } = await import(compiled.url("audit-repeat"));
const previousReportsDirectory = process.env.HCP_REPORTS_DIR;
let reportsDirectory;

beforeEach(() => {
  reportsDirectory = mkdtempSync(path.join(tmpdir(), "hcp-audit-repeat-"));
  process.env.HCP_REPORTS_DIR = reportsDirectory;
});

afterEach(() => rmSync(reportsDirectory, { recursive: true, force: true }));
after(() => {
  if (previousReportsDirectory === undefined) delete process.env.HCP_REPORTS_DIR; else process.env.HCP_REPORTS_DIR = previousReportsDirectory;
  rmSync(compiled.directory, { recursive: true, force: true });
});

function saveReport(name, overrides = {}) {
  writeFileSync(path.join(reportsDirectory, `${name}.json`), JSON.stringify({
    inventoryHost: "host-one",
    hostname: "host-one.example.test",
    createdAt: "2025-01-01T10:00:00.000Z",
    profileId: "basic_linux",
    mode: "agentless",
    scanner: { available: true, partial: false },
    findings: [],
    summary: { score: 80, high: 0, medium: 0, low: 0, info: 0 },
    ...overrides,
  }));
}

function query(overrides = {}) {
  return {
    action: "agentlessAudit",
    profileId: "basic_linux",
    hostAlias: "host-one",
    extraVars: {},
    remediationTransactions: [],
    ...overrides,
  };
}

test("completed matching audit is offered as the existing evidence", () => {
  saveReport("host-one-basic_linux-run-first");
  const notice = findRepeatAuditNotice(query());
  assert.equal(notice?.reportId, "host-one-basic_linux-run-first");
  assert.equal(notice?.mode, "agentless");
  assert.match(notice?.message ?? "", /не зафиксировала/);
});

test("another profile and incomplete reports never suppress a new audit", () => {
  saveReport("host-one-basic_linux-run-first");
  assert.equal(findRepeatAuditNotice(query({ profileId: "ssh_security" })), null);

  rmSync(path.join(reportsDirectory, "host-one-basic_linux-run-first.json"));
  saveReport("host-one-basic_linux-run-partial", { partial: true });
  assert.equal(findRepeatAuditNotice(query()), null);
});

test("a HCP remediation recorded after the report keeps the verification audit open", () => {
  saveReport("host-one-basic_linux-run-first");
  const notice = findRepeatAuditNotice(query({
    remediationTransactions: [{ hostAlias: "host-one", updatedAt: "2025-01-01T10:01:00.000Z" }],
  }));
  assert.equal(notice, null);
});

test("Nmap requires the same selected port coverage before it warns", () => {
  saveReport("host-one-nmap-run-top1000", {
    profileId: "nmap",
    mode: "nmap",
    scanner: { available: true, partial: false, scanScope: "top_1000" },
  });
  assert.equal(findRepeatAuditNotice(query({
    action: "networkPortScan",
    extraVars: { nmap_scan_scope: "top_100" },
  })), null);
  assert.equal(findRepeatAuditNotice(query({
    action: "networkPortScan",
    extraVars: { nmap_scan_scope: "top_1000" },
  }))?.reportId, "host-one-nmap-run-top1000");
});
