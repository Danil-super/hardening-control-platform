import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ansible-reports"]);
const api = await import(compiled.url("ansible-reports"));
const root = mkdtempSync(path.join(tmpdir(), "hcp-report-reader-"));
process.env.HCP_REPORTS_DIR = path.join(root, "reports");
process.env.HCP_STATE_DIR = path.join(root, "state");
mkdirSync(process.env.HCP_REPORTS_DIR);
after(() => { rmSync(root, { recursive: true, force: true }); rmSync(compiled.directory, { recursive: true, force: true }); });
function save(id, extra = {}) {
  writeFileSync(path.join(process.env.HCP_REPORTS_DIR, `${id}.json`), JSON.stringify({
    inventoryHost: "host-one", mode: "facts", createdAt: "2026-01-01T00:00:00Z", findings: [], events: [], ...extra,
  }));
}

test("cold concurrent readers yield to the event loop and preserve summaries and source references", async () => {
  save("large", { unusedLegacyData: "x".repeat(65 * 1024 * 1024) });
  save("large-two", { unusedLegacyData: "y".repeat(65 * 1024 * 1024) });
  save("future", { mode: "unknown-adapter", createdAt: "2099-01-01T00:00:00Z", scanner: { sourceCveReport: "large" } });
  save("delivery", { scanner: { deliveryReportId: "large" } });
  save("package", { vulnerabilityScan: { sourcePackageReportId: "large" }, scanner: { sourceCveReport: "large" } });
  writeFileSync(path.join(process.env.HCP_REPORTS_DIR, "malformed.json"), "{");
  const expected = api.listAnsibleReports("all");
  // A fresh compiled module has no warm in-memory cache.
  const fresh = compileServerModules(["ansible-reports"]);
  try {
    const cold = await import(fresh.url("ansible-reports"));
    let yielded = false;
    const tick = new Promise(resolve => setImmediate(() => { yielded = true; resolve(); }));
    const pending = Promise.all([1, 2, 3].map(() => cold.listAnsibleReportsAsync("all"))).then(results => {
      assert.equal(yielded, true, "a cold read must let the pending event-loop task run before completing");
      return results;
    });
    assert.equal(yielded, false);
    await tick;
    const results = await pending;
    for (const result of results) assert.deepEqual(result, expected);
    assert.deepEqual(await cold.listAnsibleReportDependentsAsync("large"), api.listAnsibleReportDependents("large"));
    assert.equal((await cold.listAnsibleReportDependentsAsync("large")).length, 3);
    save("delivery", { scanner: { sourceCveReport: "different" } });
    assert.equal((await cold.listAnsibleReportDependentsAsync("large")).length, 2);
    rmSync(path.join(process.env.HCP_REPORTS_DIR, "large.json"));
    assert.ok(!(await cold.listAnsibleReportsAsync("all")).some(r => r.id === "large"));
  } finally { rmSync(fresh.directory, { recursive: true, force: true }); }
});

test("future timestamps are re-evaluated and no raw legacy tree escapes the reader", async () => {
  const timestamp = Date.now() + 3000;
  save("clock", { createdAt: new Date(timestamp).toISOString(), unusedLegacyData: "private" });
  const before = (await api.listAnsibleReportsAsync("all")).find(r => r.id === "clock");
  assert.equal(before.reportTimeValid, false);
  assert.equal(JSON.stringify(before).includes("private"), false);
  await new Promise(resolve => setTimeout(resolve, Math.max(0, timestamp - Date.now()) + 50));
  assert.equal((await api.listAnsibleReportsAsync("all")).find(r => r.id === "clock").reportTimeValid, true);
});

test("a changed cached source during another cold read fails closed and the next request recovers", async () => {
  save("changing");
  await api.listAnsibleReportsAsync("all");
  save("new-cold", { unusedLegacyData: "x".repeat(16 * 1024 * 1024) });
  const pending = api.listAnsibleReportsAsync("all");
  const rejected = assert.rejects(pending, /изменился/);
  await new Promise(resolve => setImmediate(resolve));
  save("changing", { hostname: "updated" });
  await rejected;
  assert.equal((await api.listAnsibleReportsAsync("all")).find(r => r.id === "changing").host, "updated");
});

test("an unavailable worker rejects the request instead of blocking or returning an empty clean result", () => {
  save("not-cached");
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import assert from "node:assert/strict";
    const api = await import(${JSON.stringify(compiled.url("ansible-reports"))});
    await assert.rejects(api.listAnsibleReportsAsync("all"));
  `], { cwd: root, encoding: "utf8", timeout: 10000 });
  assert.equal(child.status, 0, child.stderr);
});
