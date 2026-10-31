import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const source = ts.transpileModule(readFileSync(new URL("../app/api/internal/scheduled/package-vulnerabilities/route.ts", import.meta.url), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const runId = "schedule-20261028T120000Z";

function route({ delivery = async () => ({ configured: true, message: "SBOM accepted; analysis pending" }), scanPartial = false,
  sbomFile = "fixture.json", scanError, hosts = ["host-one"], authorized = true, inventories, collectionError } = {}) {
  const incidents = [], deliveries = [], collections = [], scans = [];
  const stubs = {
    "next/server": { NextResponse: { json: (body, init) => Response.json(body, init) } },
    "@/lib/ansible-control": { appendIncident: value => incidents.push(value) },
    "@/lib/scheduled-auth": { isScheduledRequestAuthorized: () => authorized, isScheduledRunId: value => value === runId },
    "@/lib/scheduled-audit": {
      isScheduledLimit: value => typeof value === "string" && /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(value),
      runScheduledInventoryAudit: async input => {
        collections.push(input);
        if (collectionError) throw new Error(collectionError);
        return inventories ?? hosts.map(hostAlias => ({ hostAlias, reportId: `${hostAlias}-packages-run-fresh`, partial: false, warnings: [] }));
      },
    },
    "@/lib/vulnerability-scan": { scanPackageInventory: async ({ hostAlias, reportId }) => {
      scans.push({ hostAlias, reportId });
      if (scanError) throw new Error(scanError);
      return { reportId: `${hostAlias}-vulnerabilities-run-test`, report: { vulnerabilityScan: { partial: scanPartial, ...(sbomFile ? { sbomFile } : {}) } } };
    } },
    "@/lib/dependency-track": { syncDependencyTrack: async input => { deliveries.push(input); return delivery(input); } },
  };
  const module = { exports: {} };
  new Function("require", "module", "exports", source)(name => stubs[name] ?? require(name), module, module.exports);
  return { incidents, deliveries, collections, scans, post: async (body = { reportRunId: runId, limit: "linux_hosts" }) => {
    const response = await module.exports.POST(new Request("http://localhost/api/internal/scheduled/package-vulnerabilities", { method: "POST", body: JSON.stringify(body) }));
    return { status: response.status, body: await response.json() };
  } };
}

test("a configured delivery error makes a complete Trivy schedule partial and unsuccessful", async () => {
  const target = route({ delivery: async () => { throw new Error("Dependency-Track HTTP 503"); } });
  const { status, body } = await target.post();
  assert.equal(status, 207);
  assert.equal(body.ok, false);
  assert.equal(body.partial, true);
  assert.equal(body.results[0].partial, true);
  assert.equal(body.results[0].dependencyTrackStatus, "failed");
  assert.match(body.results[0].dependencyTrack, /503/);
  assert.equal(body.results[0].vulnerabilityReportId, "host-one-vulnerabilities-run-test");
  assert.equal(target.incidents[0].status, "failed");
});

test("an unconfigured optional integration is explicitly skipped without failing a complete scan", async () => {
  const target = route({ delivery: async () => ({ configured: false, message: "Not configured" }) });
  const { status, body } = await target.post();
  assert.equal(status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.partial, false);
  assert.equal(body.results[0].dependencyTrackStatus, "skipped");
  assert.equal(target.incidents[0].status, "success");
});

test("accepted upload is delivery success, while an incomplete scan remains partial", async () => {
  for (const scanPartial of [false, true]) {
    const target = route({ scanPartial });
    const { status, body } = await target.post();
    assert.equal(status, scanPartial ? 207 : 200);
    assert.equal(body.ok, !scanPartial);
    assert.equal(body.results[0].dependencyTrackStatus, "accepted");
    assert.equal(body.results[0].partial, scanPartial);
    assert.match(body.results[0].dependencyTrack, /analysis pending/);
  }
});

test("missing SBOM cannot silently bypass a configured delivery", async () => {
  const target = route({ sbomFile: null, delivery: async () => { throw new Error("Saved SBOM not found"); } });
  const { body } = await target.post();
  assert.equal(target.deliveries.length, 1);
  assert.equal(body.ok, false);
  assert.equal(body.results[0].dependencyTrackStatus, "failed");
});

test("a failed delivery on one host preserves successful hosts and fails the overall schedule", async () => {
  const target = route({ hosts: ["host-one", "host-two"], delivery: async ({ hostAlias }) => {
    if (hostAlias === "host-one") throw new Error("upload rejected");
    return { configured: true, message: "accepted" };
  } });
  const { body } = await target.post();
  assert.equal(body.ok, false);
  assert.deepEqual(body.results.map(result => result.partial), [true, false]);
  assert.match(target.incidents[0].message, /1\/2/);
});

test("scanner failures and unauthorized schedules never attempt delivery", async () => {
  const failed = route({ scanError: "Trivy failed" });
  const result = await failed.post();
  assert.equal(result.body.ok, false);
  assert.equal(result.body.results[0].error, "Trivy failed");
  assert.equal(failed.deliveries.length, 0);
  const denied = route({ authorized: false });
  assert.equal((await denied.post()).status, 401);
  assert.equal(denied.deliveries.length, 0);
});

test("a scoped package schedule collects through the common runner and scans only its new report IDs", async () => {
  const target = route({ hosts: ["host-one", "host-two"] });
  const { status, body } = await target.post({ reportRunId: runId, limit: "linux_hosts", becomePassword: "must-not-forward", extraVars: { ansible_python_interpreter: "/wrong/python" } });
  assert.equal(status, 200);
  assert.equal(body.ok, true);
  assert.deepEqual(target.collections, [{ action: "packageInventory", profileId: "basic_linux", limit: "linux_hosts" }]);
  assert.deepEqual(target.scans, ["host-one", "host-two"].map(hostAlias => ({ hostAlias, reportId: `${hostAlias}-packages-run-fresh` })));
  assert.deepEqual(body.results.map(result => result.packageReportId), target.scans.map(scan => scan.reportId));
  assert.equal(body.reportRunId, runId);
  assert.equal(target.incidents[0].limit, "linux_hosts");
});

test("missing inventory for one target is retained and cannot fall back to an older package report", async () => {
  const target = route({ inventories: [
    { hostAlias: "host-one", partial: true, warnings: [], error: "sudo denied", errorCode: "sudo_password_required" },
    { hostAlias: "host-two", reportId: "host-two-packages-run-fresh", partial: false, warnings: [] },
  ] });
  const { status, body } = await target.post({ reportRunId: runId, limit: "linux_hosts" });
  assert.equal(status, 207);
  assert.equal(body.ok, false);
  assert.equal(body.partial, true);
  assert.equal(body.results.length, 2);
  assert.equal(body.results[0].errorCode, "sudo_password_required");
  assert.deepEqual(target.scans, [{ hostAlias: "host-two", reportId: "host-two-packages-run-fresh" }]);
  assert.match(target.incidents[0].message, /1\/2/);
});

test("a partial source inventory keeps the overall schedule partial even if the scanner claims completeness", async () => {
  const target = route({ inventories: [{ hostAlias: "host-one", reportId: "host-one-packages-run-fresh", partial: true, warnings: ["RPM query incomplete"] }] });
  const { status, body } = await target.post({ reportRunId: runId, limit: "host-one" });
  assert.equal(status, 207);
  assert.equal(body.results[0].partial, true);
  assert.deepEqual(body.results[0].warnings, ["RPM query incomplete"]);
  assert.equal(target.scans.length, 1);
});

test("package auth and input rejection perform no collection, scan or delivery", async () => {
  const denied = route({ authorized: false });
  assert.equal((await denied.post({ reportRunId: runId, limit: "linux_hosts" })).status, 401);
  assert.deepEqual([denied.collections.length, denied.scans.length, denied.deliveries.length], [0, 0, 0]);
  for (const body of [null, {}, { reportRunId: "invalid", limit: "host-one" }, ...[null, "", "--all", "all:!x", "host-one,host-two", {}, 3].map(limit => ({ reportRunId: runId, limit }))]) {
    const target = route();
    assert.equal((await target.post(body)).status, 400);
    assert.deepEqual([target.collections.length, target.scans.length, target.deliveries.length], [0, 0, 0]);
  }
  const noHosts = route({ collectionError: "No Linux targets" });
  assert.equal((await noHosts.post({ reportRunId: runId, limit: "missing" })).status, 400);
  assert.deepEqual([noHosts.scans.length, noHosts.deliveries.length], [0, 0]);
  const legacy = route();
  assert.equal((await legacy.post({ reportRunId: runId })).status, 400, "without a target scope, batch completeness cannot be proven");
  assert.deepEqual([legacy.collections.length, legacy.scans.length], [0, 0]);
});
