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
  sbomFile = "fixture.json", scanError, hosts = ["host-one"], authorized = true } = {}) {
  const incidents = [], deliveries = [];
  const stubs = {
    "next/server": { NextResponse: { json: (body, init) => Response.json(body, init) } },
    "@/lib/ansible-control": { appendIncident: value => incidents.push(value) },
    "@/lib/ansible-reports": { listAnsibleReports: () => hosts.map(host => ({ id: `${host}-packages-${runId}`, mode: "packages", reportTimeValid: true, inventoryHost: host })), targetAliasFromReport: report => report.inventoryHost },
    "@/lib/scheduled-auth": { isScheduledRequestAuthorized: () => authorized, isScheduledRunId: value => value === runId },
    "@/lib/vulnerability-scan": { scanPackageInventory: async ({ hostAlias }) => {
      if (scanError) throw new Error(scanError);
      return { reportId: `${hostAlias}-vulnerabilities-run-test`, report: { vulnerabilityScan: { partial: scanPartial, ...(sbomFile ? { sbomFile } : {}) } } };
    } },
    "@/lib/dependency-track": { syncDependencyTrack: async input => { deliveries.push(input); return delivery(input); } },
  };
  const module = { exports: {} };
  new Function("require", "module", "exports", source)(name => stubs[name] ?? require(name), module, module.exports);
  return { incidents, deliveries, post: async () => {
    const response = await module.exports.POST(new Request("http://localhost/api/internal/scheduled/package-vulnerabilities", { method: "POST", body: JSON.stringify({ reportRunId: runId }) }));
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
