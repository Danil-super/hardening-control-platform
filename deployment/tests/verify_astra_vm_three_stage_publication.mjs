#!/usr/bin/env node
/**
 * Publish three ACTUAL native Astra OpenSCAP reports through the same
 * source-bound production publisher used by HCP, without synthesizing or
 * modifying a rule status. Only a disposable GitHub runner invokes this file.
 *
 * Inputs: asset-observation.json, output-directory, three original full
 * OpenSCAP JSON report paths in baseline/violation/restored order.
 */
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { compileServerModules } from "../../web/tests/_typescript-loader.mjs";

const [observationPath, outputDir, ...inputs] = process.argv.slice(2);
assert.equal(inputs.length, 3, "Expected genuine baseline, violation and restored reports");
assert.ok(process.env.HCP_REPORTS_DIR && process.env.HCP_STATE_DIR, "Private acceptance state required");
assert.equal(process.env.GITHUB_ACTIONS, "true", "Must run in authorized CI");
assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted", "Disposable runner required");

const compiled = compileServerModules([
  "asset-binding", "state-store", "asset-report-publication", "ansible-reports",
]);
const stage = mkdtempSync(path.join(tmpdir(), "hcp-astra-three-stage-"));
try {
  const { assetConnectionId, machineIdentityHash } = await import(compiled.url("asset-binding"));
  const { recordAssetObservation } = await import(compiled.url("state-store"));
  const { publishCapturedAssetReports } = await import(compiled.url("asset-report-publication"));
  const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
  const observed = JSON.parse(readFileSync(observationPath, "utf8"));
  assert.equal(observed.alias, "hcp-real-astra");
  const binding = recordAssetObservation({
    alias: observed.alias,
    connectionId: assetConnectionId(observed.connection),
    observation: {
      machineIdSha256: machineIdentityHash(observed.machineId),
      sshHostKeyFingerprint: observed.sshHostKeyFingerprint,
      observedAt: observed.observedAt,
    },
  });
  assert.equal(binding.status, "verified", "Only verified native asset evidence accepted");
  assert.equal(binding.alias, observed.alias);

  const names = ["baseline", "violation", "restored"];
  const publications = new Map();
  const originals = [];
  for (let i = 0; i < names.length; i++) {
    const native = JSON.parse(readFileSync(inputs[i], "utf8"));
    assert.equal(native.mode, "openscap", "Native mode must be OpenSCAP");
    assert.equal(native.inventoryHost, observed.alias, "Report host identity mismatch");
    assert.equal(native.scanner?.profile, "xccdf_org.hcp_profile_astra_baseline");
    assert.equal(native.scanner?.datastream, "/__hcp_builtin__/astra-baseline.xml");
    assert.equal(native.scanner?.partial, false, "Incomplete native evaluation is not a metric");
    assert.match(native.scanner?.contentIdentity ?? "", /^bundle-sha256:[a-f0-9]{64}$/);
    assert.ok(Array.isArray(native.findings) && native.findings.length === 18);
    assert.ok(Date.parse(binding.verifiedAt) <= Date.parse(native.createdAt),
      "Asset identity observation must precede the actual scanner result");
    assert.equal(native.assetBinding, undefined, "Do not overwrite existing identity data");
    const reportId = `hcp-real-astra-openscap-${names[i]}`;
    const file = reportId + ".json";
    copyFileSync(inputs[i], path.join(stage, file));
    publications.set(file, binding);
    originals.push(native);
  }

  // This is the actual production publisher, not a synthetic injection into
  // the three audit results. Raw source bytes remain separately preserved.
  await publishCapturedAssetReports(stage, publications);
  mkdirSync(outputDir, { recursive: true });
  for (let i = 0; i < names.length; i++) {
    const reportId = `hcp-real-astra-openscap-${names[i]}`;
    const published = readAnsibleReport(reportId);
    assert.ok(published, "Published source-bound report must be readable");
    assert.deepEqual(published.assetBinding, binding);
    assert.deepEqual(published.raw, { ...originals[i], assetBinding: binding },
      "No native observation may be lost or altered during publication");
    assert.equal(published.mode, "openscap");
    assert.equal(published.partial, false);
    copyFileSync(path.join(process.env.HCP_REPORTS_DIR, reportId + ".json"),
      path.join(outputDir, names[i] + ".json"));
  }
  console.log("PASS: three genuine native Astra reports published with one verified asset binding.");
} finally {
  rmSync(stage, { recursive: true, force: true });
  rmSync(compiled.directory, { recursive: true, force: true });
}
