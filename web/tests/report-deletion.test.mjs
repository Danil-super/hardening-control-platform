import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, afterEach, beforeEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ansible-reports"]);
const reportsApi = await import(compiled.url("ansible-reports"));
const previousReports = process.env.HCP_REPORTS_DIR;
const previousState = process.env.HCP_STATE_DIR;
let root;
let reports;

beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), "hcp-report-delete-"));
  reports = path.join(root, "reports");
  mkdirSync(reports, { recursive: true });
  process.env.HCP_REPORTS_DIR = reports;
  process.env.HCP_STATE_DIR = path.join(root, "state");
});

afterEach(() => rmSync(root, { recursive: true, force: true }));
after(() => {
  if (previousReports === undefined) delete process.env.HCP_REPORTS_DIR; else process.env.HCP_REPORTS_DIR = previousReports;
  if (previousState === undefined) delete process.env.HCP_STATE_DIR; else process.env.HCP_STATE_DIR = previousState;
  rmSync(compiled.directory, { recursive: true, force: true });
});

function save(name, data) {
  writeFileSync(path.join(reports, `${name}.json`), JSON.stringify({
    inventoryHost: "host-1", hostname: "host-1", createdAt: new Date().toISOString(), findings: [], events: [], ...data,
  }));
}

test("standalone CVE report removes its unreferenced SBOM", () => {
  const sbomDir = path.join(process.env.HCP_STATE_DIR, "sbom");
  mkdirSync(sbomDir, { recursive: true });
  writeFileSync(path.join(sbomDir, "scan-1.cdx.json"), "{}");
  save("host-1-vulnerabilities-run-1", {
    mode: "vulnerabilities", profileId: "cve_packages", vulnerabilityScan: { sbomFile: "scan-1.cdx.json" },
  });

  const deleted = reportsApi.deleteAnsibleReport("host-1-vulnerabilities-run-1");
  assert.equal(deleted.id, "host-1-vulnerabilities-run-1");
  assert.equal(deleted.sbomRemoved, true);
  assert.equal(existsSync(path.join(reports, "host-1-vulnerabilities-run-1.json")), false);
  assert.equal(existsSync(path.join(sbomDir, "scan-1.cdx.json")), false);
});

test("package inventory remains protected while a CVE report depends on it", () => {
  save("host-1-packages-run-1", { mode: "packages", profileId: "packages" });
  save("host-1-vulnerabilities-run-1", {
    mode: "vulnerabilities", profileId: "cve_packages", vulnerabilityScan: { sourcePackageReportId: "host-1-packages-run-1", sbomFile: "scan-1.cdx.json" },
  });

  assert.deepEqual(reportsApi.listAnsibleReportDependents("host-1-packages-run-1"), [{
    id: "host-1-vulnerabilities-run-1", mode: "vulnerabilities", reason: "package_inventory",
  }]);
});
