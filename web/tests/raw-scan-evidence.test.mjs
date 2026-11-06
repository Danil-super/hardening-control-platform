import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["asset-report-publication"]);
const directory = mkdtempSync(path.join(tmpdir(), "hcp-raw-evidence-"));
process.env.HCP_STATE_DIR = directory;
process.env.HCP_REPORTS_DIR = path.join(directory, "reports");
const { publishCapturedAssetReports } = await import(compiled.url("asset-report-publication"));
const identity = await import(compiled.url("asset-binding"));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const observation = { machineIdSha256: "1".repeat(64), sshHostKeyFingerprint: "SHA256:" + "A".repeat(43), observedAt: new Date().toISOString() };
const binding = { version: 1, status: "verified", alias: "raw-fixture", generation: 1,
  assetId: identity.assetIdForObservation(observation), machineIdSha256: observation.machineIdSha256,
  sshHostKeyFingerprint: observation.sshHostKeyFingerprint, verifiedAt: observation.observedAt, connectionId: "2".repeat(64) };
after(() => { delete process.env.HCP_STATE_DIR; delete process.env.HCP_REPORTS_DIR; rmSync(directory, { recursive: true, force: true }); rmSync(compiled.directory, { recursive: true, force: true }); });

function fixture(name, mode = "astra-oval") {
  const stage = path.join(directory, name); mkdirSync(stage);
  const id = `raw-fixture-${mode}-${name}`;
  const source = Buffer.from("<original-source>synthetic fixture</original-source>");
  const result = Buffer.from("<original-result>synthetic fixture</original-result>");
  const report = { inventoryHost: binding.alias, mode, scanner: { available: true, partial: false,
    evaluationPerformed: true, resultSha256: sha(result), database: { sha256: sha(source) }, datastreamChecksum: "sha256:" + sha(source) }, findings: [] };
  writeFileSync(path.join(stage, `${id}.json`), JSON.stringify(report));
  const resultName = mode === "astra-oval" ? `.${id}.oval-results.xml` : `.${id}.xml`;
  const sourceName = mode === "astra-oval" ? `.${id}.source.xml` : `.${id}.xml.datastream.xml`;
  return { stage, id, source, result, resultName, sourceName, report };
}
function publish(f) {
  publishCapturedAssetReports(f.stage, new Map([[`${f.id}.json`, binding]]), { preserveRaw: true });
  return JSON.parse(readFileSync(path.join(process.env.HCP_REPORTS_DIR, `${f.id}.json`), "utf8"));
}

test("original OVAL and ARF bytes survive launch staging cleanup and are bound by hashes in the published report", () => {
  for (const mode of ["astra-oval", "openscap"]) {
    const f = fixture(mode, mode);
    writeFileSync(path.join(f.stage, f.resultName), f.result);
    writeFileSync(path.join(f.stage, f.sourceName), f.source);
    const report = publish(f);
    rmSync(f.stage, { recursive: true });
    assert.equal(report.rawEvidence.complete, true);
    assert.equal(report.rawEvidence.artifacts.length, 2);
    assert.equal(report.assetBinding.assetId, binding.assetId);
    for (const artifact of report.rawEvidence.artifacts) {
      const file = path.join(process.env.HCP_REPORTS_DIR, artifact.path);
      assert.equal(sha(readFileSync(file)), artifact.sha256);
      assert.equal(statSync(file).mode & 0o077, 0);
      assert.equal(path.isAbsolute(artifact.path), false);
    }
  }
});

test("missing original evidence stays partial rather than claiming a complete auditable run", () => {
  const f = fixture("missing");
  const report = publish(f);
  assert.equal(report.partial, true);
  assert.equal(report.rawEvidence.complete, false);
  assert.deepEqual(report.rawEvidence.missing.sort(), ["oval-results", "source"]);
});

test("raw evidence refuses a symlink or a checksum different from the normalized source/result", () => {
  for (const scenario of ["symlink", "wrong-hash", "directory", "oversize"]) {
    const f = fixture(scenario);
    writeFileSync(path.join(f.stage, f.sourceName), f.source);
    if (scenario === "symlink") symlinkSync(path.join(f.stage, f.sourceName), path.join(f.stage, f.resultName));
    else if (scenario === "directory") mkdirSync(path.join(f.stage, f.resultName));
    else {
      writeFileSync(path.join(f.stage, f.resultName), "different native result");
      if (scenario === "oversize") truncateSync(path.join(f.stage, f.resultName), 384 * 1024 * 1024 + 1);
    }
    assert.throws(() => publish(f), /доказательств|контрольн|тип|ссылк/i);
    assert.equal(existsSync(path.join(process.env.HCP_REPORTS_DIR, `${f.id}.json`)), false);
  }
});
