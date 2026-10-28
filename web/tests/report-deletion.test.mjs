import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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
  writeFileSync(path.join(sbomDir, "scan-1.trivy-config.yaml"), "{}\n");
  const unrelated = path.join(root, "unrelated-config.yaml");
  writeFileSync(unrelated, "keep\n");
  save("host-1-vulnerabilities-run-1", {
    mode: "vulnerabilities", profileId: "cve_packages", vulnerabilityScan: { sbomFile: "scan-1.cdx.json", sourceEvidence: { config: { path: unrelated } } },
  });

  const deleted = reportsApi.deleteAnsibleReport("host-1-vulnerabilities-run-1");
  assert.equal(deleted.id, "host-1-vulnerabilities-run-1");
  assert.equal(deleted.sbomRemoved, true);
  assert.equal(existsSync(path.join(reports, "host-1-vulnerabilities-run-1.json")), false);
  assert.equal(existsSync(path.join(sbomDir, "scan-1.cdx.json")), false);
  assert.equal(existsSync(path.join(sbomDir, "scan-1.trivy-config.yaml")), false);
  assert.equal(existsSync(unrelated), true);
});

test("shared scanner inputs remain until the last referencing report is removed", () => {
  const sbomDir = path.join(process.env.HCP_STATE_DIR, "sbom");
  mkdirSync(sbomDir, { recursive: true });
  for (const name of ["shared.cdx.json", "shared.trivy-config.yaml"]) writeFileSync(path.join(sbomDir, name), "{}\n");
  for (const id of ["first", "second"]) save(id, { mode: "vulnerabilities", vulnerabilityScan: { sbomFile: "shared.cdx.json" } });
  assert.equal(reportsApi.deleteAnsibleReport("first").sbomRemoved, false);
  for (const name of ["shared.cdx.json", "shared.trivy-config.yaml"]) assert.equal(existsSync(path.join(sbomDir, name)), true);
  assert.equal(reportsApi.deleteAnsibleReport("second").sbomRemoved, true);
  for (const name of ["shared.cdx.json", "shared.trivy-config.yaml"]) assert.equal(existsSync(path.join(sbomDir, name)), false);
});

test("legacy SBOM filenames do not alias the derived scanner config path", () => {
  const sbomDir = path.join(process.env.HCP_STATE_DIR, "sbom");
  mkdirSync(sbomDir, { recursive: true });
  writeFileSync(path.join(sbomDir, "legacy.json"), "{}\n");
  save("legacy", { mode: "vulnerabilities", vulnerabilityScan: { sbomFile: "legacy.json" } });
  assert.equal(reportsApi.deleteAnsibleReport("legacy").sbomRemoved, true);
  assert.equal(existsSync(path.join(reports, "legacy.json")), false);
  assert.equal(existsSync(path.join(sbomDir, "legacy.json")), false);
});

test("an unexpected config symlink stops cleanup before deleting evidence", () => {
  const sbomDir = path.join(process.env.HCP_STATE_DIR, "sbom");
  mkdirSync(sbomDir, { recursive: true });
  const outside = path.join(root, "unrelated.yaml");
  writeFileSync(outside, "keep\n");
  writeFileSync(path.join(sbomDir, "scan.cdx.json"), "{}");
  symlinkSync(outside, path.join(sbomDir, "scan.trivy-config.yaml"));
  save("scan", { mode: "vulnerabilities", vulnerabilityScan: { sbomFile: "scan.cdx.json" } });
  assert.throws(() => reportsApi.deleteAnsibleReport("scan"), /недопустимый тип/);
  assert.equal(existsSync(path.join(reports, "scan.json")), true);
  assert.equal(existsSync(path.join(sbomDir, "scan.cdx.json")), true);
  assert.equal(existsSync(outside), true);
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
