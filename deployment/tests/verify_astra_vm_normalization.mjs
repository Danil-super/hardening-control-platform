#!/usr/bin/env node
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { compileServerModules } from "../../web/tests/_typescript-loader.mjs";

const [reportId, definitionId, cve, expected, output, nativeReportPath, observationPath] = process.argv.slice(2);
assert.ok(process.env.HCP_REPORTS_DIR && process.env.HCP_STATE_DIR);
const compiled = compileServerModules(["ansible-reports", "asset-report-publication", "asset-binding", "state-store"]);
const stage = mkdtempSync(path.join(tmpdir(), "hcp-astra-publication-"));
try {
  const { assetConnectionId, machineIdentityHash } = await import(compiled.url("asset-binding"));
  const { recordAssetObservation } = await import(compiled.url("state-store"));
  const { publishCapturedAssetReports } = await import(compiled.url("asset-report-publication"));
  const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
  const observed = JSON.parse(readFileSync(observationPath, "utf8"));
  const binding = recordAssetObservation({ alias: observed.alias, connectionId: assetConnectionId(observed.connection),
    observation: { machineIdSha256: machineIdentityHash(observed.machineId), sshHostKeyFingerprint: observed.sshHostKeyFingerprint, observedAt: observed.observedAt } });
  const native = JSON.parse(readFileSync(nativeReportPath, "utf8"));
  assert.ok(Date.parse(binding.verifiedAt) <= Date.parse(native.createdAt), "Identity was captured before scanning");
  copyFileSync(nativeReportPath, path.join(stage, reportId + ".json"));
  publishCapturedAssetReports(stage, new Map([[reportId + ".json", binding]]));
  const report = readAnsibleReport(reportId);
  assert.ok(report, "The production web normalizer must read the actual VM report");
  assert.deepEqual(report.assetBinding, binding);
  assert.deepEqual(report.raw, { ...native, assetBinding: binding }, "Publication must preserve every native definition and observation");
  assert.equal(report.mode, "astra-oval");
  assert.equal(report.score, null);
  assert.equal(report.partial, report.raw.scanner.partial);
  const control = report.findings.filter((finding) => finding.id === definitionId);
  assert.equal(control.length, expected === "true" ? 1 : 0);
  if (control.length) {
    assert.equal(control[0].status, "failed");
    assert.ok(control[0].vulnerability.cveIds.includes(cve));
  }
  writeFileSync(output, JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
} finally {
  rmSync(stage, { recursive: true, force: true });
  rmSync(compiled.directory, { recursive: true, force: true });
}
