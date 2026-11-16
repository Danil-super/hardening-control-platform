import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["astra-oval-evidence", "asset-report-publication", "asset-binding", "ansible-reports"]);
const { assessAstraOvalEvidence } = await import(compiled.url("astra-oval-evidence"));
const { publishCapturedAssetReports } = await import(compiled.url("asset-report-publication"));
const assetIdentity = await import(compiled.url("asset-binding"));
const { readAnsibleReport } = await import(compiled.url("ansible-reports"));

function fixture(count = 3, positives = 1) {
  const definitions = Array.from({ length: count }, (_, i) => ({
    id: `oval:astra:def:${i+1}`, class: "vulnerability",
    result: i < positives ? "true" : "false",
    cveIds: i < positives ? [`CVE-2026-${10000 + i}`] : [],
  }));
  const findings = definitions.slice(0, positives).map((entry) => ({
    id: entry.id, profileId: "astra-oval", title: entry.cveIds[0],
    description: "Synthetic scoped definition test only.", recommendation: "Check vendor bulletin.",
    category: "Уязвимости пакетов Astra", risk: "info", status: "failed",
    source: "openscap", evidence: JSON.stringify({ definitionId: entry.id }), severityUnknown: true,
  }));
  return {
    scanner: {
      available: true, evaluationPerformed: true, partial: false,
      partialReasons: [], exitCode: 2, database: { sha256: "a".repeat(64), checksumVerified: true },
      resultSha256: "b".repeat(64),
      definitionCount: count, evaluatedDefinitionCount: count, definitionResults: definitions,
      resultCounts: { ...(positives ? { true: positives } : {}), ...(count - positives ? { false: count - positives } : {}) },
    }, findings,
  };
}

test("the selected source is complete only when every native result and positive finding survives", async () => {
  const original = fixture();
  assert.deepEqual(assessAstraOvalEvidence(original.scanner, original.findings), {
    complete: true, reason: "exact_scoped_definition_states_present", definitionCount: 3,
  });
  const corruptions = [
    (x) => { x.scanner.definitionCount--; },
    (x) => { x.scanner.evaluatedDefinitionCount--; },
    (x) => { x.scanner.definitionResults.pop(); },
    (x) => { x.scanner.definitionResults[1].id = x.scanner.definitionResults[0].id; },
    (x) => { x.scanner.definitionResults[0].result = "unknown"; },
    (x) => { x.scanner.definitionResults[0].result = "not evaluated"; },
    (x) => { x.scanner.resultCounts.true = 0; },
    (x) => { x.scanner.resultSha256 = "missing"; },
    (x) => { x.scanner.database.checksumVerified = false; },
    (x) => { x.scanner.database.sha256 = "bad"; },
    (x) => { x.scanner.partial = true; },
    (x) => { x.scanner.exitCode = 1; },
    (x) => { x.scanner.partialReasons.push("timeout"); },
    (x) => { x.findings = []; },
    (x) => { x.findings[0].status = "passed"; },
    (x) => { x.scanner.definitionResults[0].class = null; },
  ];
  for (const damage of corruptions) {
    const item = structuredClone(original);
    damage(item);
    assert.equal(assessAstraOvalEvidence(item.scanner, item.findings).complete, false);
  }
  assert.equal(assessAstraOvalEvidence(undefined, []).complete, false);
  assert.equal(assessAstraOvalEvidence(fixture(0, 0).scanner, []).complete, false);
});

test("original selected-source 19527-ID sized synthetic JSON survives asset-binding publication; corrupt scope remains partial", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "hcp-astra-oval-integrity-"));
  const saved = Object.fromEntries(["HCP_STATE_DIR", "HCP_REPORTS_DIR"].map((key) => [key, process.env[key]]));
  process.env.HCP_STATE_DIR = directory;
  process.env.HCP_REPORTS_DIR = path.join(directory, "reports");
  try {
    const identity = {
      machineIdSha256: assetIdentity.machineIdentityHash("1".repeat(32)),
      sshHostKeyFingerprint: `SHA256:${"A".repeat(43)}`,
      observedAt: new Date().toISOString(),
    };
    const binding = {
      version: 1, status: "verified", alias: "astra-oval-synthetic", generation: 1,
      assetId: assetIdentity.assetIdForObservation(identity), machineIdSha256: identity.machineIdSha256,
      sshHostKeyFingerprint: identity.sshHostKeyFingerprint, verifiedAt: identity.observedAt,
      connectionId: assetIdentity.assetConnectionId({ address: "192.0.2.44", port: 22, user: "audit" }),
    };
    const original = fixture(19527, 337);
    const stage = path.join(directory, "stage");
    mkdirSync(stage);
    const good = "astra-oval-synthetic-astra-oval-run-good";
    const bad = "astra-oval-synthetic-astra-oval-run-tampered";
    const base = { inventoryHost: binding.alias, hostname: binding.alias,
      createdAt: identity.observedAt, mode: "astra-oval", profileId: "astra-oval",
      summary: { score: null }, ...original, events: [] };
    writeFileSync(path.join(stage, good + ".json"), JSON.stringify(base));
    const tampered = structuredClone(base);
    tampered.scanner.evaluatedDefinitionCount--;
    writeFileSync(path.join(stage, bad + ".json"), JSON.stringify(tampered));
    await publishCapturedAssetReports(stage, new Map([
      [good + ".json", binding], [bad + ".json", binding],
    ]));
    const accepted = readAnsibleReport(good);
    assert.equal(accepted.assetBinding.assetId, binding.assetId);
    assert.equal(accepted.scopeKnown, true);
    assert.equal(accepted.partial, false);
    assert.equal(accepted.ovalEvidence.definitionCount, 19527);
    assert.equal(accepted.raw.scanner.definitionResults.length, 19527);
    assert.equal(accepted.findings.length, 337);
    assert.deepEqual(accepted.raw.scanner.definitionResults[19526], base.scanner.definitionResults[19526]);
    assert.equal(readFileSync(accepted.path, "utf8").includes(`"assetId": "${binding.assetId}"`), true);
    const rejected = readAnsibleReport(bad);
    assert.equal(rejected.assetBinding.assetId, binding.assetId);
    assert.equal(rejected.partial, true);
    assert.equal(rejected.needsReview, true);
    assert.equal(rejected.ovalEvidence.reason, "definition_scope_incomplete");
    assert.equal(rejected.raw.scanner.definitionResults.length, 19527);
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test("truly missing vendor digest is an unknown scope and always partial in HCP", async () => {
  const missing = fixture();
  delete missing.scanner.database.sha256;
  const proof = assessAstraOvalEvidence(missing.scanner, missing.findings);
  assert.equal(proof.complete, false);
  assert.equal(proof.reason, "source_sha_not_verified");
});
