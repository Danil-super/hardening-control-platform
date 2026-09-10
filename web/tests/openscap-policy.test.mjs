import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
function load(file, stubs = {}) {
  const code = ts.transpileModule(readFileSync(path.join(webRoot, file), "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", code)((name) => Object.hasOwn(stubs, name) ? stubs[name] : require(name), module, module.exports);
  return module.exports;
}

const inventory = load("lib/inventory.ts");
const policies = load("lib/openscap-policy.ts", {
  "@/lib/inventory": inventory,
  "@/lib/ansible-reports": {},
  "@/lib/state-store": {},
});

test("inventory membership respects vars, children and unrelated groups", () => {
  const parsed = inventory.parseStaticInventory(`[web]\nserver-1 ansible_host=192.0.2.1\n[web:vars]\nphantom\n[linux_hosts:children]\nweb\n[network]\nswitch-1\n`);
  assert.deepEqual(parsed.hosts.map((host) => host.alias), ["server-1", "switch-1"]);
  assert.deepEqual(inventory.getInventoryHost("server-1", parsed).groups, ["all", "linux_hosts", "web"]);
  assert.deepEqual(inventory.getInventoryHost("switch-1", parsed).groups, ["all", "network"]);
  assert.deepEqual(inventory.getInventoryTargetHosts("linux_hosts", parsed).map((host) => host.alias), ["server-1"]);
  assert.equal(inventory.getInventoryHost("web", parsed), null);
  assert.throws(() => inventory.getInventoryTargetHosts("server-1:web", parsed), /один точный alias/);
  assert.throws(() => inventory.getInventoryTargetHosts("server-1,switch-1", parsed), /один точный alias/);
  assert.throws(() => inventory.parseStaticInventory("[a:children]\nb\n[b:children]\na\n"), /Циклическое/);
  assert.throws(() => inventory.parseStaticInventory("[linux_hosts]\nnode[1:9]\n"), /без диапазонов/);
});

test("host/group collision is rejected before a single host change", () => {
  const parsed = inventory.parseStaticInventory("[linux_hosts]\nweb\n[web]\nserver-2\n");
  assert.equal(inventory.getInventoryHost("web", parsed), null);
  assert.throws(() => inventory.getInventoryTargetHosts("web", parsed), /совпадает/);
});

const profile = (groupName) => ({ groupName, datastream: "/content/ssg.xml", profile: `profile_${groupName}`, createdAt: "", updatedAt: "" });
test("OpenSCAP profile precedence has no implicit Linux fallback and rejects ambiguity", () => {
  assert.equal(policies.selectOpenScapPolicy("switch", ["network"], [profile("linux_hosts")]).policy, null);
  assert.equal(policies.selectOpenScapPolicy("host", ["linux_hosts", "web"], [profile("linux_hosts"), profile("web")]).policy.groupName, "web");
  assert.throws(() => policies.selectOpenScapPolicy("host", ["linux_hosts", "web", "db"], [profile("web"), profile("db")]), /несколько/);
});

const baseFinding = {
  id: "openscap_rule_1", source: "openscap", status: "failed", risk: "high", title: "Control",
  description: "Original evidence", evidence: "rule=rule_1; result=fail", recommendation: "Fix control", remediationAvailable: false,
};
const exception = (id, groupName = "web", expiresAt = "2030-01-01T00:00:00Z") => ({ id, groupName, expiresAt, ruleId: "rule_1", reason: `Approved reason ${id}` });
test("exceptions retain failed severity, evidence and totals; expired/unrelated exceptions do not apply", () => {
  const input = { mode: "openscap", summary: { score: 20, high: 1, total: 2 }, findings: [baseFinding, { ...baseFinding, id: "openscap_rule_2", status: "passed" }] };
  const result = policies.annotateOpenScapExceptions(input, ["web", "linux_hosts"], [exception("specific"), exception("fallback", "linux_hosts"), exception("expired", "web", "2020-01-01T00:00:00Z"), exception("other", "db")], "2026-09-10T00:00:00Z");
  assert.deepEqual(result.summary, input.summary);
  assert.deepEqual(result.findings.map((finding) => [finding.status, finding.risk]), [["failed", "high"], ["passed", "high"]]);
  assert.equal(result.findings[0].evidence, baseFinding.evidence);
  assert.equal(result.findings[0].recommendation, baseFinding.recommendation);
  assert.deepEqual(result.scanner.exceptionsApplied.map((item) => item.id), ["specific", "fallback"]);
  assert.match(result.findings[0].description, /сохранены/);
  assert.equal(input.findings[0].description, "Original evidence");
});

test("scheduled key rejects Unicode byte-length mismatch without throwing", () => {
  const auth = load("lib/scheduled-auth.ts");
  const previous = process.env.HCP_SCHEDULE_API_KEY;
  process.env.HCP_SCHEDULE_API_KEY = "é";
  try {
    assert.equal(auth.isScheduledRequestAuthorized(new Request("http://localhost", { headers: { "x-hcp-schedule-key": "a" } })), false);
    assert.equal(auth.isScheduledRequestAuthorized(new Request("http://localhost", { headers: { "x-hcp-schedule-key": "é" } })), true);
  } finally {
    if (previous === undefined) delete process.env.HCP_SCHEDULE_API_KEY; else process.env.HCP_SCHEDULE_API_KEY = previous;
  }
});

test("audit outcome marks missing and unavailable output partial", () => {
  const helper = load("lib/audit-result.ts", {
    "@/lib/inventory": { getInventoryTargetHosts: () => [{ alias: "host-1", groups: ["linux_hosts"] }, { alias: "host-2", groups: ["linux_hosts"] }] },
    "@/lib/ansible-control": { reportIdForRun: ({ limit }) => limit },
    "@/lib/ansible-reports": { readAnsibleReport: (id) => id === "host-1" ? { raw: { scanner: { partial: true, available: false } } } : null },
  });
  const result = helper.inspectAuditReports({ action: "openScapAudit", profileId: "basic_linux", limit: "linux_hosts", reportRunId: "run-123" });
  assert.equal(result.partial, true);
  assert.deepEqual(result.reportIds, ["host-1"]);
  assert.equal(result.warnings.length, 2);
});

test("scheduled OpenSCAP resolves each host's policy and returns a partial result for incomplete scans", async () => {
  const calls = [];
  const annotations = [];
  const events = [];
  const endpoint = load("app/api/internal/scheduled/openscap/route.ts", {
    "next/server": { NextResponse: { json: (body, options) => Response.json(body, options) } },
    "@/lib/ansible-control": {
      runAnsiblePlaybook: async (args) => { calls.push(args); return { reportRunId: `run-${args.limit}` }; },
      reportIdForRun: ({ limit }) => `${limit}-openscap`,
      appendIncident: (event) => events.push(event),
    },
    "@/lib/audit-result": { inspectAuditReports: ({ limit }) => ({ partial: limit === "db-1", warnings: limit === "db-1" ? ["Unavailable content"] : [] }) },
    "@/lib/inventory": { getInventoryTargetHosts: () => [{ alias: "web-1", groups: ["linux_hosts", "web"] }, { alias: "db-1", groups: ["linux_hosts", "db"] }] },
    "@/lib/openscap-policy": {
      resolveOpenScapPolicyForHost: (alias) => ({ policy: profile(alias.startsWith("web") ? "web" : "db"), groups: ["linux_hosts"], source: "group" }),
      applyOpenScapExceptions: (args) => { annotations.push(args); return { applied: 1 }; },
    },
    "@/lib/scheduled-auth": { isScheduledRequestAuthorized: () => true, isScheduledRunId: () => true },
    "@/lib/state-store": { listOpenScapExceptions: () => [exception("approved")] },
  });
  const response = await endpoint.POST(new Request("http://localhost", { method: "POST", body: JSON.stringify({ limit: "linux_hosts", reportRunId: "schedule-12345678" }) }));
  const body = await response.json();
  assert.equal(response.status, 207);
  assert.equal(body.ok, false);
  assert.equal(body.partial, true);
  assert.deepEqual(calls.map((call) => [call.limit, call.extraVars.hcp_openscap_profile]), [["web-1", "profile_web"], ["db-1", "profile_db"]]);
  assert.equal(annotations.length, 2);
  assert.equal(annotations[0].exceptions[0].id, "approved");
  assert.equal(events[0].status, "failed");
});

test("manual audit exposes annotation failures instead of reporting full success", async () => {
  const endpoint = load("app/api/ansible/run/route.ts", {
    "next/server": { NextResponse: { json: (body, options) => Response.json(body, options) } },
    "@/lib/ansible-control": {
      isPlaybookAction: () => true, isSafeLimit: () => true, normalizeProfileId: () => "basic_linux",
      validateExtraVars: () => ({ ok: true, values: {} }),
      playbooks: { openScapAudit: { kind: "audit", requiresLimit: true, requiresConfirmation: true } },
      runAnsiblePlaybook: async () => ({ stdout: "completed", stderr: "", command: "ansible-playbook", reportRunId: "run-host" }),
      reportIdForRun: () => "host-openscap-run-host", appendIncident: () => {},
    },
    "@/lib/openscap-policy": {
      resolveOpenScapPolicyForHost: () => ({ groups: ["linux_hosts"], policy: profile("linux_hosts"), source: "group" }),
      applyOpenScapExceptions: () => { throw new Error("disk is read-only"); },
    },
    "@/lib/state-store": { listOpenScapExceptions: () => [] },
    "@/lib/audit-result": { inspectAuditReports: () => ({ partial: false, warnings: [], reportIds: ["host-openscap-run-host"] }) },
    "@/lib/ansible-reports": {}, "@/lib/remediation": {},
  });
  const response = await endpoint.POST(new Request("http://localhost", { method: "POST", body: JSON.stringify({ action: "openScapAudit", limit: "host", confirmAudit: true }) }));
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.partial, true);
  assert.match(body.message, /disk is read-only/);
  assert.equal(body.warnings.length, 1);
});
