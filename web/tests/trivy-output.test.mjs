import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import test from "node:test";
import ts from "typescript";
import { compileServerModules } from "./_typescript-loader.mjs";

const require = createRequire(import.meta.url);
const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const compiled = compileServerModules(["trivy-output", "vulnerability-scan", "ansible-reports"]);
const { readTrivyOutputFile, TRIVY_STDOUT_LIMIT } = await import(compiled.url("trivy-output"));
test.after(() => fs.rmSync(compiled.directory, { recursive: true, force: true }));

function directory(t) {
  const root = fs.mkdtempSync(path.join(tmpdir(), "hcp-output-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function evidence(bytes) { return { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") }; }

test("private output preserves every native UTF-8 byte and rejects wrong digest/size", (t) => {
  const file = path.join(directory(t), "result.json");
  const bytes = Buffer.from(JSON.stringify({ text: "advisory \"quote\" \\ escape\nКириллица 🔎" }));
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  assert.equal(readTrivyOutputFile(file, evidence(bytes)), bytes.toString("utf8"));
  for (const metadata of [undefined, { ...evidence(bytes), bytes: bytes.length - 1 },
    { ...evidence(bytes), bytes: TRIVY_STDOUT_LIMIT + 1 }, { ...evidence(bytes), sha256: "0".repeat(64) }]) {
    assert.throws(() => readTrivyOutputFile(file, metadata));
  }
  fs.writeFileSync(file, bytes.subarray(0, bytes.length - 1));
  assert.throws(() => readTrivyOutputFile(file, evidence(bytes)), /expected private ordinary file/);
});

test("output rejects symlinks, hard links, public permissions, invalid UTF-8 and oversized files", (t) => {
  const root = directory(t);
  const file = path.join(root, "native.json");
  const bytes = Buffer.from("{}");
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  const link = path.join(root, "link.json");
  fs.symlinkSync(file, link);
  assert.throws(() => readTrivyOutputFile(link, evidence(bytes)));
  fs.rmSync(link); fs.linkSync(file, link);
  assert.throws(() => readTrivyOutputFile(file, evidence(bytes)), /expected private ordinary file/);
  fs.rmSync(link); fs.chmodSync(file, 0o644);
  assert.throws(() => readTrivyOutputFile(file, evidence(bytes)), /expected private ordinary file/);
  fs.chmodSync(file, 0o600); fs.truncateSync(file, TRIVY_STDOUT_LIMIT + 1);
  assert.throws(() => readTrivyOutputFile(file, evidence(bytes)), /expected private ordinary file/);
  const invalid = Buffer.from([0xff, 0xfe]);
  fs.writeFileSync(file, invalid);
  assert.throws(() => readTrivyOutputFile(file, evidence(invalid)), /encoded data/);
});

test("replacement and partial rewrite during a real file read cannot be accepted", (t) => {
  const root = directory(t);
  const source = ts.transpileModule(fs.readFileSync(path.join(webDir, "lib/trivy-output.ts"), "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  for (const replacement of [true, false]) {
    const file = path.join(root, `native-${replacement}.json`);
    const bytes = Buffer.from('{"native":"complete original"}');
    fs.writeFileSync(file, bytes, { mode: 0o600 });
    let changed = false;
    const guardedFs = { ...fs, readSync(...args) {
      const count = fs.readSync(...args);
      if (!changed && count) {
        changed = true;
        if (replacement) {
          const next = file + ".next";
          fs.writeFileSync(next, bytes, { mode: 0o600 });
          fs.renameSync(next, file);
        } else fs.writeFileSync(file, bytes.subarray(0, 5));
      }
      return count;
    } };
    const exports = {};
    vm.runInNewContext(source, { exports, require: (name) => name === "node:fs" ? guardedFs : require(name), Buffer, TextDecoder });
    assert.throws(() => exports.readTrivyOutputFile(file, evidence(bytes)), /changed, was replaced or did not finish/);
    assert.equal(changed, true);
  }
});

function scanFixture(t, mode) {
  const root = directory(t);
  const reports = path.join(root, "reports"), cache = path.join(root, "cache"), temporary = path.join(root, "temporary");
  fs.mkdirSync(reports); fs.mkdirSync(path.join(cache, "db"), { recursive: true }); fs.mkdirSync(temporary);
  fs.writeFileSync(path.join(cache, "db/trivy.db"), "contract fixture, not a CVE database");
  fs.writeFileSync(path.join(cache, "db/metadata.json"), JSON.stringify({ Version: 2, UpdatedAt: new Date().toISOString() }));
  const binary = path.join(root, "trivy-contract-fixture");
  const marker = path.join(root, "native-evidence.json");
  fs.writeFileSync(binary, `#!/usr/bin/env node
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const args = process.argv.slice(2);
if (args.includes('--version')) { console.log('Version: 0.74.0-contract-fixture'); process.exit(0); }
if (${JSON.stringify(mode)} === 'overflow') {
  const chunk = Buffer.alloc(65536, 'x');
  for (let i = 0; i < 1025; i++) fs.writeSync(1, chunk);
  process.exit(0);
}
const sbom = JSON.parse(fs.readFileSync(args.at(-1), 'utf8'));
const pkg = sbom.components[0];
const vulnerabilities = Array.from({ length: 2662 }, (_, index) => ({
  VulnerabilityID: 'CVE-2026-' + (10000 + index), PkgName: pkg.name, InstalledVersion: pkg.version,
  PkgID: pkg['bom-ref'], PkgIdentifier: { BOMRef: pkg['bom-ref'] }, Status: 'affected', Severity: 'HIGH',
  Description: 'Fixture advisory with quoted "text" and unicode Кириллица. '.repeat(110),
}));
const output = JSON.stringify({ SchemaVersion: 2, Metadata: { OS: { Family: sbom.metadata.component.name, Name: sbom.metadata.component.version } },
  Results: [{ Class: 'os-pkgs', Type: sbom.metadata.component.name, Packages: sbom.components.map(p => ({
    Name: p.name, Version: p.version, Identifier: { BOMRef: p['bom-ref'], PURL: p.purl },
  })), Vulnerabilities: vulnerabilities }] });
fs.writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ bytes: Buffer.byteLength(output), sha256: createHash('sha256').update(output).digest('hex') }));
fs.writeSync(1, output);
`, { mode: 0o700 });
  const overrides = { HCP_STATE_DIR: root, HCP_REPORTS_DIR: reports, HCP_TRIVY_BIN: binary, HCP_TRIVY_CACHE_DIR: cache,
    HCP_TRIVY_MODE: "offline", TMPDIR: temporary };
  const previous = Object.fromEntries(Object.keys(overrides).map(key => [key, process.env[key]]));
  Object.assign(process.env, overrides);
  t.after(() => { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  const reportId = "output-host-packages-fixture";
  fs.writeFileSync(path.join(reports, reportId + ".json"), JSON.stringify({ mode: "packages", inventoryHost: "output-host",
    createdAt: new Date().toISOString(), packageInventory: { packageCount: 1, manager: "dpkg", osRelease: { ID: "ubuntu", VERSION_ID: "22.04" } },
    packages: [{ name: "openssl", version: "3.0.0-1", arch: "amd64", manager: "dpkg", sourceName: "openssl", sourceVersion: "3.0.0-1",
      maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", origin: "Ubuntu" }] }));
  return { root, reportId, marker, temporary };
}

test("large native output reaches saved and normalized reports without losing any finding", async (t) => {
  const fixture = scanFixture(t, "large");
  const { scanPackageInventory } = await import(compiled.url("vulnerability-scan"));
  const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
  const result = await scanPackageInventory({ hostAlias: "output-host", reportId: fixture.reportId });
  assert.equal(result.report.scanner.available, true);
  assert.equal(result.partial, false);
  const native = JSON.parse(fs.readFileSync(fixture.marker, "utf8"));
  assert.ok(native.bytes > 16 * 1024 * 1024 && native.bytes < TRIVY_STDOUT_LIMIT);
  assert.deepEqual(result.report.vulnerabilityScan.sourceEvidence.nativeOutput, native);
  assert.equal(result.report.findings.length, 2662);
  const normalized = readAnsibleReport(result.reportId);
  assert.equal(normalized.findings.length, 2662);
  assert.equal(new Set(normalized.findings.map(f => f.id)).size, 2662);
  assert.deepEqual(normalized.findings.map(f => [f.id, f.status, f.risk]), result.report.findings.map(f => [f.id, f.status, f.risk]));
  assert.equal(normalized.score, null);
  assert.deepEqual(fs.readdirSync(fixture.temporary), [], "Successful transport must not leave private native output files");
});

test("native stdout above its finite budget creates a partial report and cleans temporary output", async (t) => {
  const fixture = scanFixture(t, "overflow");
  const { scanPackageInventory } = await import(compiled.url("vulnerability-scan"));
  const result = await scanPackageInventory({ hostAlias: "output-host", reportId: fixture.reportId });
  assert.equal(result.report.scanner.available, false);
  assert.equal(result.partial, true);
  assert.equal(result.report.summary.score, null);
  assert.equal(result.report.vulnerabilityScan.checkedPackages, 0);
  assert.ok(result.report.findings.every(f => f.status === "manual"));
  assert.match(result.report.findings[0].evidence, /source_failure=output_limit/);
  assert.match(result.message, /бюджет обработки/);
  assert.deepEqual(fs.readdirSync(fixture.temporary), [], "Failure must remove partial native output and its directory");
});
