import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

test("an 8284-definition OVAL report above 32 MiB survives identity publication and the real normalizer", () => {
  const compiled = compileServerModules(["asset-report-publication", "asset-binding", "ansible-reports"]);
  const directory = mkdtempSync(path.join(tmpdir(), "hcp-large-oval-publication-"));
  const saved = Object.fromEntries(["HCP_STATE_DIR", "HCP_REPORTS_DIR"].map((name) => [name, process.env[name]]));
  process.env.HCP_STATE_DIR = directory; process.env.HCP_REPORTS_DIR = path.join(directory, "reports");
  return (async () => {
    try {
      const identity = await import(compiled.url("asset-binding"));
      const { publishCapturedAssetReports } = await import(compiled.url("asset-report-publication"));
      const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
      const observation = { machineIdSha256: identity.machineIdentityHash("1".repeat(32)), sshHostKeyFingerprint: `SHA256:${"A".repeat(43)}`, observedAt: new Date().toISOString() };
      const binding = { version: 1, status: "verified", alias: "large-oval", generation: 1, assetId: identity.assetIdForObservation(observation),
        machineIdSha256: observation.machineIdSha256, sshHostKeyFingerprint: observation.sshHostKeyFingerprint, verifiedAt: observation.observedAt,
        connectionId: identity.assetConnectionId({ address: "192.0.2.20", port: 22, user: "audit" }) };
      const stage = path.join(directory, "stage"); mkdirSync(stage);
      const id = "large-oval-astra-oval-run-fixture";
      // The official 8284-definition source's metadata alone exceeds 43 MiB.
      // Preserve the same count and representative nested criteria/predicates;
      // genuine vendor XML/result trees are exercised in the native Astra job.
      const definitions = Array.from({ length: 8284 }, (_, index) => ({ id: `oval:fixture:def:${index}`, result: "false", class: "vulnerability",
        sourceDefinition: { title: `Definition ${index}`, description: "Vendor advisory and applicability metadata. ".repeat(120),
          criteria: { operator: "AND", criterion: [{ test_ref: `oval:fixture:tst:${index}`, comment: "Installed package version comparison" }] } } }));
      const source = { inventoryHost: binding.alias, mode: "astra-oval", profileId: "astra-oval", createdAt: observation.observedAt,
        scanner: { available: true, partial: false, definitionCount: definitions.length, definitionResults: definitions, database: { sha256: "a".repeat(64) } }, findings: [] };
      const serialized = JSON.stringify(source, null, 2);
      assert.ok(Buffer.byteLength(serialized) > 32 * 1024 * 1024);
      writeFileSync(path.join(stage, `${id}.json`), serialized);
      publishCapturedAssetReports(stage, new Map([[`${id}.json`, binding]]));
      const report = readAnsibleReport(id);
      assert.equal(report.mode, "astra-oval"); assert.equal(report.assetBinding.assetId, binding.assetId);
      assert.equal(report.raw.scanner.definitionResults.length, 8284);
      assert.deepEqual(report.raw.scanner.definitionResults[8283], definitions[8283]);
      assert.equal(JSON.stringify(report.raw.scanner), JSON.stringify(source.scanner));
      assert.ok(readFileSync(report.path).length > 32 * 1024 * 1024);
    } finally {
      for (const [name, value] of Object.entries(saved)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
      rmSync(directory, { recursive: true, force: true }); rmSync(compiled.directory, { recursive: true, force: true });
    }
  })();
});
