import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["asset-report-publication"]);
const directory = mkdtempSync(path.join(tmpdir(), "hcp-raw-evidence-"));
process.env.HCP_STATE_DIR = directory;
process.env.HCP_REPORTS_DIR = path.join(directory, "reports");
const { publishCapturedAssetReports } = await import(compiled.url("asset-report-publication"));
const { prepareRawScanEvidence } = await import(compiled.url("raw-scan-evidence"));
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

const nativeModes = [
  { mode: "nmap", kind: "nmap", sidecar: "nmap.xml", filename: "nmap.xml", bytes: Buffer.from('<?xml version="1.0"?>\r\n<!-- original -->\r\n<nmaprun/>\r\n') },
  { mode: "ssh-audit", kind: "ssh-audit", sidecar: "ssh-audit.json", filename: "ssh-audit.json", bytes: Buffer.from('{\r\n  "banner" : {"raw":"SSH-fixture"}, "unmodeled" : 42\r\n}\r\n') },
  { mode: "lynis", kind: "lynis-report", sidecar: "report.dat", filename: "lynis-report.dat", bytes: Buffer.from([0x23, 0xff, 0x0d, 0x0a, ...Buffer.from("lynis_version=3.1.2\r\nfinish=true\r\n")]) },
];
function nativeFixture(name, native, scanner = {}) {
  const f = fixture(`${name}-${native.mode}`, native.mode);
  f.report.scanner = { available: true, partial: false, ...scanner };
  writeFileSync(path.join(f.stage, `${f.id}.json`), JSON.stringify(f.report));
  f.originalName = `.${f.id}.${native.sidecar}`;
  return f;
}
function noStagingDirectories() {
  assert.deepEqual(readdirSync(path.join(process.env.HCP_REPORTS_DIR, ".raw-evidence")).filter((name) => name.startsWith(".staging-")), []);
}

test("raw preparation maps each CLI original to its native manifest artifact without reserialization", () => {
  for (const native of nativeModes) {
    const f = nativeFixture("native-prepare", native);
    writeFileSync(path.join(f.stage, f.originalName), native.bytes);
    const prepared = prepareRawScanEvidence(f.stage, `${f.id}.json`, f.report, process.env.HCP_REPORTS_DIR);
    try {
      assert.deepEqual(prepared.evidence, { version: 1, complete: true, missing: [], artifacts: [{
        kind: native.kind, path: `.raw-evidence/${f.id}/${native.filename}`, sha256: sha(native.bytes), bytes: native.bytes.length,
      }] });
      assert.deepEqual(readFileSync(path.join(prepared.temporaryDirectory, native.filename)), native.bytes);
    } finally { rmSync(prepared.temporaryDirectory, { recursive: true, force: true }); }
    noStagingDirectories();
  }
});

test("CLI native originals publish byte-for-byte on successful and partial scans, including hidden JSON sidecars", () => {
  for (const native of nativeModes) for (const partial of [false, true]) {
    const f = nativeFixture(`native-${partial}`, native, { partial, available: !partial });
    writeFileSync(path.join(f.stage, f.originalName), native.bytes);
    const report = publish(f);
    rmSync(f.stage, { recursive: true });
    assert.deepEqual(report.rawEvidence, { version: 1, complete: true, missing: [], artifacts: [{
      kind: native.kind, path: `.raw-evidence/${f.id}/${native.filename}`, sha256: sha(native.bytes), bytes: native.bytes.length,
    }] });
    assert.equal(report.scanner.partial, partial);
    const artifact = path.join(process.env.HCP_REPORTS_DIR, report.rawEvidence.artifacts[0].path);
    assert.deepEqual(readFileSync(artifact), native.bytes);
    assert.equal(statSync(artifact).mode & 0o777, 0o600);
    assert.equal(statSync(path.dirname(artifact)).mode & 0o777, 0o700);
    noStagingDirectories();
  }
});

test("missing and unavailable CLI originals are never reconstructed from normalized reports", () => {
  for (const native of nativeModes) for (const available of [true, false]) {
    const f = nativeFixture(`native-missing-${available}`, native, { available });
    const report = publish(f);
    assert.deepEqual(report.rawEvidence, { version: 1, complete: false, missing: [native.kind], artifacts: [] });
    assert.equal(report.partial, true);
    assert.equal(report.scanner.available, available);
    assert.deepEqual(readdirSync(path.join(process.env.HCP_REPORTS_DIR, ".raw-evidence", f.id)), []);
    noStagingDirectories();
  }
});

test("native originals preserve opt-in and immutable publication semantics", () => {
  for (const native of nativeModes) {
    const f = nativeFixture("native-immutable", native);
    writeFileSync(path.join(f.stage, f.originalName), native.bytes);
    const report = publish(f);
    writeFileSync(path.join(f.stage, f.originalName), "replacement");
    assert.throws(() => publish(f), /уже сохранены|уже существует/);
    const artifact = path.join(process.env.HCP_REPORTS_DIR, report.rawEvidence.artifacts[0].path);
    assert.deepEqual(readFileSync(artifact), native.bytes);
    noStagingDirectories();
    const legacy = nativeFixture("native-opt-out", native);
    publishCapturedAssetReports(legacy.stage, new Map([[`${legacy.id}.json`, binding]]));
    const normalized = JSON.parse(readFileSync(path.join(process.env.HCP_REPORTS_DIR, `${legacy.id}.json`)));
    assert.equal(normalized.rawEvidence, undefined);
    assert.equal(existsSync(path.join(process.env.HCP_REPORTS_DIR, ".raw-evidence", legacy.id)), false);
  }
});

test("invalid native files fail closed and remove prepared copies and staging directories", () => {
  for (const native of nativeModes) for (const scenario of ["symlink", "empty", "directory", "oversize"]) {
    const f = nativeFixture(`native-invalid-${scenario}`, native);
    const original = path.join(f.stage, f.originalName);
    if (scenario === "symlink") symlinkSync(path.join(f.stage, `${f.id}.json`), original);
    else if (scenario === "directory") mkdirSync(original);
    else {
      writeFileSync(original, "");
      if (scenario === "oversize") truncateSync(original, 384 * 1024 * 1024 + 1);
    }
    assert.throws(() => publish(f), /доказательств|контрольн|тип|ссылк/i);
    assert.equal(existsSync(path.join(process.env.HCP_REPORTS_DIR, `${f.id}.json`)), false);
    assert.equal(existsSync(path.join(process.env.HCP_REPORTS_DIR, ".raw-evidence", f.id)), false);
    noStagingDirectories();
  }
});

test("standalone XCCDF fallback keeps existing XML paths and checksum validation", () => {
  const f = fixture("standalone-xccdf", "openscap");
  f.report.scanner.rawResultSha256 = sha(f.result);
  writeFileSync(path.join(f.stage, `${f.id}.json`), JSON.stringify(f.report));
  writeFileSync(path.join(f.stage, f.resultName), f.result);
  writeFileSync(path.join(f.stage, `.${f.id}.xml.evaluated-xccdf.xml`), f.source);
  const report = publish(f);
  assert.deepEqual(report.rawEvidence.artifacts.map(({ kind, path: file }) => [kind, file]), [
    ["arf", `.raw-evidence/${f.id}/arf.xml`], ["source", `.raw-evidence/${f.id}/source.xml`],
  ]);
  assert.equal(report.rawEvidence.complete, true);
  noStagingDirectories();
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
