import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
function load(file, stubs = {}) {
  const source = ts.transpileModule(readFileSync(new URL(`../${file}`, import.meta.url), "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", source)(name => stubs[name] ?? require(name), module, module.exports);
  return module.exports;
}

const runId = "schedule-20261030T120000Z";
function fixture({ hosts = ["host-one"], missing = [], partial = [], failed = [], mismatched = [], unavailable = [], invalidTime = [], nullId = [], configuredKey = "schedule-test-key", cookie } = {}) {
  const calls = [], reads = [], incidents = [];
  const controls = {
    profileIds: new Set(["basic_linux", "ssh_security", "web_server", "docker_host"]),
    runAnsiblePlaybook: async input => {
      calls.push(input);
      if (failed.includes(input.limit)) throw Object.assign(new Error("A one-time sudo password is required"), { code: "sudo_password_required" });
      return { reportRunId: `run-${input.limit}` };
    },
    reportIdForRun: ({ action, profileId, limit, reportRunId }) => nullId.includes(limit) ? null : `${limit}-${action === "packageInventory" ? "packages" : profileId}-${reportRunId}`,
    appendIncident: value => incidents.push(value),
  };
  const helper = load("lib/scheduled-audit.ts", {
    "@/lib/ansible-control": controls,
    "@/lib/inventory": { getInventoryTargetHosts: limit => hosts.map(alias => ({ alias, groups: limit === "network" ? ["network"] : ["linux_hosts"] })) },
    "@/lib/ansible-reports": {
      targetAliasFromReport: report => report.inventoryHost,
      readAnsibleReport: id => {
        reads.push(id);
        const alias = hosts.find(host => id.startsWith(`${host}-`));
        if (missing.includes(alias)) return null;
        return { id, inventoryHost: mismatched.includes(alias) ? "other-host" : alias, mode: id.includes("-packages-") ? "packages" : "agentless",
          partial: partial.includes(alias), available: !unavailable.includes(alias), reportTimeValid: !invalidTime.includes(alias), raw: {} };
      },
    },
    "@/lib/audit-result": { auditReportLimitations: () => [] },
  });
  const auth = load("lib/scheduled-auth.ts");
  const endpoint = load("app/api/internal/scheduled/agentless/route.ts", {
    "next/server": { NextResponse: { json: (body, init) => Response.json(body, init) } },
    "@/lib/ansible-control": controls,
    "@/lib/scheduled-audit": helper,
    "@/lib/scheduled-auth": auth,
  });
  return { helper, calls, reads, incidents, post: async (body = { reportRunId: runId, limit: "linux_hosts", profileId: "basic_linux" }, key = "schedule-test-key") => {
    const previous = process.env.HCP_SCHEDULE_API_KEY;
    if (configuredKey === null) delete process.env.HCP_SCHEDULE_API_KEY; else process.env.HCP_SCHEDULE_API_KEY = configuredKey;
    try {
      const response = await endpoint.POST(new Request("http://localhost/api/internal/scheduled/agentless", {
        method: "POST", headers: { "x-hcp-schedule-key": key, ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body),
      }));
      return { status: response.status, body: await response.json() };
    } finally {
      if (previous === undefined) delete process.env.HCP_SCHEDULE_API_KEY; else process.env.HCP_SCHEDULE_API_KEY = previous;
    }
  } };
}

test("scheduled agentless executes each captured alias through the common runner and inspects exactly its new report", async () => {
  const target = fixture({ hosts: ["host-one", "host-two", "host-one"] });
  const { status, body } = await target.post({ reportRunId: runId, limit: "linux_hosts", profileId: "ssh_security", becomePassword: "must-not-forward", extraVars: { injected: true } });
  assert.equal(status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.partial, false);
  assert.equal(body.reportRunId, runId);
  assert.deepEqual(target.calls, ["host-one", "host-two"].map(limit => ({ action: "agentlessAudit", profileId: "ssh_security", limit })));
  assert.deepEqual(target.reads, ["host-one", "host-two"].map(alias => `${alias}-ssh_security-run-${alias}`));
  assert.deepEqual(body.results.map(result => result.reportId), target.reads);
  assert.equal(target.incidents[0].status, "success");
});

test("agentless invalid auth, scope, profile and run ID are rejected before any work", async () => {
  for (const key of ["", "wrong", "schedule-test-key-extra", "schedule-test-kex"]) {
    const target = fixture();
    assert.equal((await target.post(undefined, key)).status, 401);
    assert.deepEqual([target.calls.length, target.reads.length, target.incidents.length], [0, 0, 0]);
  }
  for (const configuredKey of [null, "", "  "]) {
    const target = fixture({ configuredKey });
    assert.equal((await target.post()).status, 401);
    assert.deepEqual(target.calls, []);
  }
  const cookieOnly = fixture({ cookie: "hcp_admin_session=unrelated-session" });
  assert.equal((await cookieOnly.post(undefined, "")).status, 401);
  assert.deepEqual(cookieOnly.calls, []);
  for (const body of [null, {}, { reportRunId: "invalid", limit: "linux_hosts" },
    ...["", "--all", "*", "linux_hosts,all", {}, 3].map(limit => ({ reportRunId: runId, limit })),
    ...["unknown", {}, 3].map(profileId => ({ reportRunId: runId, limit: "linux_hosts", profileId }))]) {
    const target = fixture();
    assert.equal((await target.post(body)).status, 400);
    assert.deepEqual([target.calls.length, target.reads.length, target.incidents.length], [0, 0, 0]);
  }
});

test("an empty or non-Linux target set is not a successful scheduled audit", async () => {
  for (const options of [{ hosts: [] }, {}]) {
    const target = fixture(options);
    assert.equal((await target.post({ reportRunId: runId, limit: "network" })).status, 400);
    assert.deepEqual(target.calls, []);
  }
});

test("missing, unidentifiable, mismatched and incomplete reports each keep their expected host in the failed result", async () => {
  for (const option of ["missing", "nullId", "mismatched", "partial", "unavailable", "invalidTime", "failed"]) {
    const target = fixture({ hosts: ["host-one", "host-two"], [option]: ["host-one"] });
    const { status, body } = await target.post();
    assert.equal(status, 207, option);
    assert.equal(body.ok, false, option);
    assert.equal(body.partial, true, option);
    assert.deepEqual(body.results.map(result => [result.hostAlias, result.partial]), [["host-one", true], ["host-two", false]], option);
    if (option === "failed") assert.equal(body.results[0].errorCode, "sudo_password_required");
    assert.match(target.incidents[0].message, /1\/2/);
  }
});

test("package collection uses the same per-host execution and cannot hide a missing or partial inventory", async () => {
  for (const option of ["missing", "partial", "failed"]) {
    const target = fixture({ hosts: ["host-one", "host-two"], [option]: ["host-one"] });
    const result = await target.helper.runScheduledInventoryAudit({ action: "packageInventory", profileId: "basic_linux", limit: "linux_hosts" });
    assert.deepEqual(target.calls, ["host-one", "host-two"].map(limit => ({ action: "packageInventory", profileId: "basic_linux", limit })));
    assert.deepEqual(result.map(item => item.partial), [true, false]);
    assert.equal(result[1].reportId, "host-two-packages-run-host-two");
  }
});
