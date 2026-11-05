#!/usr/bin/env node
// Genuine native Astra 1.7 vendor OVAL publication through HCP's production
// binding+normalization. No selected CVE is assumed to be present/absent.
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { compileServerModules } from "../../web/tests/_typescript-loader.mjs";

const [reportId, sourcePath, observationPath, output] = process.argv.slice(2);
assert.equal(reportId, "hcp-real-astra-astra-oval-vendor-oval");
assert.ok(process.env.HCP_REPORTS_DIR && process.env.HCP_STATE_DIR);
assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");

const original = readFileSync(sourcePath);
const native = JSON.parse(original.toString("utf8"));
assert.equal(native.mode, "astra-oval");
assert.equal(native.inventoryHost, "hcp-real-astra");
assert.equal(native.scanner?.hostIdentity?.astraVersion, "1.7.6.15");
assert.equal(native.scanner?.partial, false);
assert.equal(native.scanner?.evaluationPerformed, true);
assert.equal(native.assetBinding, undefined);

const compiled = compileServerModules([
  "ansible-reports", "asset-report-publication", "asset-binding", "state-store",
]);
const stage = mkdtempSync(path.join(tmpdir(), "hcp-astra17-oval-real-"));
try {
  const { assetConnectionId, machineIdentityHash } = await import(compiled.url("asset-binding"));
  const { recordAssetObservation } = await import(compiled.url("state-store"));
  const { publishCapturedAssetReports } = await import(compiled.url("asset-report-publication"));
  const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
  const observed = JSON.parse(readFileSync(observationPath, "utf8"));
  assert.equal(observed.alias, native.inventoryHost);
  const binding = recordAssetObservation({
    alias: observed.alias,
    connectionId: assetConnectionId(observed.connection),
    observation: {
      machineIdSha256: machineIdentityHash(observed.machineId),
      sshHostKeyFingerprint: observed.sshHostKeyFingerprint,
      observedAt: observed.observedAt,
    },
  });
  assert.equal(binding.status, "verified");
  assert.ok(Date.parse(binding.verifiedAt) <= Date.parse(native.createdAt),
    "SSH identity observation must predate native scan");
  copyFileSync(sourcePath, path.join(stage, reportId + ".json"));
  publishCapturedAssetReports(stage, new Map([[reportId + ".json", binding]]));
  const reported = readAnsibleReport(reportId);
  assert.ok(reported, "Real Astra 1.7 vendor OVAL report must be available");
  assert.equal(reported.mode, "astra-oval");
  assert.equal(reported.partial, false);
  assert.equal(reported.score, null, "No aggregate CVE security score");
  assert.deepEqual(reported.assetBinding, binding);
  assert.deepEqual(reported.raw, { ...native, assetBinding: binding },
    "All actual native definitions and original observations must survive publishing");
  const rawDefinitions = native.scanner.definitionResults.length;
  assert.equal(rawDefinitions, native.scanner.definitionCount);
  assert.equal(rawDefinitions, native.scanner.evaluatedDefinitionCount);
  assert.ok(rawDefinitions > 0);
  writeFileSync(output, JSON.stringify({
    schemaVersion: 1, status: "genuine-astra17-oval-published",
    originalReportSha256: createHash("sha256").update(original).digest("hex"),
    originalDefinitionCount: rawDefinitions,
    sourceSha256: native.scanner.database.sha256,
    sourceAuthenticatedIndependently: false,
    nativePartial: false,
    preservedExactOriginalReport: true,
    verifiedAssetBinding: true,
    totalCveRecallMeasured: false,
  }, null, 2) + "\n", { mode: 0o600 });
} finally {
  rmSync(stage, { recursive: true, force: true });
  rmSync(compiled.directory, { recursive: true, force: true });
}
