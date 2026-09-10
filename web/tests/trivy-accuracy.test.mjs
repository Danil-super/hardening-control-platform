import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import test from "node:test";
import { execFileSync } from "node:child_process";
import ts from "typescript";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const source = readFileSync(path.join(webDir, "lib/vulnerability-scan.ts"), "utf8");
const compiled = ts.transpileModule(source + "\nexport const testing = { trivyFinding, packagePurl, writePackageSbom, scanCoverage };", { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText;

function harness(t, response = "normal") {
  const dir = mkdtempSync(path.join(tmpdir(), "hcp-trivy-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const reports = path.join(dir, "reports");
  const cache = path.join(dir, "cache");
  mkdirSync(reports);
  mkdirSync(path.join(cache, "db"), { recursive: true });
  writeFileSync(path.join(cache, "db/trivy.db"), "fixture, not a real Trivy database");
  writeFileSync(path.join(cache, "db/metadata.json"), JSON.stringify({ UpdatedAt: new Date().toISOString() }));
  // This executable is a contract fixture. These tests do not claim a live Trivy scan.
  const binary = path.join(dir, "trivy-fixture");
  writeFileSync(binary, `#!/usr/bin/env node\nconst fs = require('node:fs');\nconst args = process.argv.slice(2);\nfs.writeFileSync(${JSON.stringify(path.join(dir, "args.json"))}, JSON.stringify({args, env: process.env}));\nconst sbom = JSON.parse(fs.readFileSync(args.at(-1), 'utf8'));\nconst response = ${JSON.stringify(response)};\nlet output = {SchemaVersion: 2, Metadata: {OS: {Family: sbom.metadata.component.name, Name: sbom.metadata.component.version}}, Results: [{Class: 'os-pkgs', Type: sbom.metadata.component.name, Packages: sbom.components.map(p => ({Name: p.name, Version: p.version, Identifier: {BOMRef: p['bom-ref'], PURL: p.purl}})), Vulnerabilities: []}]};\nif(response === 'empty') output = {};\nif(response === 'missing-package') output.Results[0].Packages = [];\nif(response === 'wrong-os') output.Metadata.OS.Family = 'alpine';\nif(response === 'eosl') output.Metadata.OS.EOSL = true;\nif(response === 'many') output.Results[0].Vulnerabilities = Array.from({length: 1005}, (_,i) => ({VulnerabilityID:'CVE-2026-' + i, PkgName:'libssl3', InstalledVersion:'3.0.2-0ubuntu1', FixedVersion:'3.0.2-0ubuntu2', Status:'fixed', Severity:'HIGH'}));\nconsole.log(JSON.stringify(output));\n`);
  chmodSync(binary, 0o700);
  const env = { ...process.env, HCP_TRIVY_BIN: binary, HCP_TRIVY_CACHE_DIR: cache, HCP_TRIVY_MAX_DB_AGE_HOURS: "168", TRIVY_SERVER: "https://must-not-be-used.invalid", TRIVY_SEVERITY: "LOW", TRIVY_IGNORE_UNFIXED: "true" };
  const exports = {};
  const mocks = {
    "@/lib/ansible-control": { getStateDir: () => dir },
    "@/lib/ansible-reports": { getReportsDir: () => reports, listAnsibleReports: () => [], targetAliasFromReport: (r) => r.inventoryHost ?? r.fileName.replace(/-packages(?:-.*)?\.json$/, "") },
    "@/lib/state-store": { getVulnerabilityDatabaseSettings: () => ({ mode: "offline", source: "environment" }) },
  };
  vm.runInNewContext(compiled, { exports, require: (name) => mocks[name] ?? require(name), process: { env }, URLSearchParams, console });
  const report = { mode: "packages", profileId: "packages", inventoryHost: "lab-host", hostname: "different-hostname", createdAt: new Date().toISOString(), packageInventory: { packageCount: 1, manager: "dpkg", osRelease: { ID: "ubuntu", VERSION_ID: "22.04" }, error: "" }, packages: [{ name: "libssl3:amd64", version: "3.0.2-0ubuntu1", arch: "amd64", manager: "dpkg", sourceName: "openssl", sourceVersion: "3.0.2-0ubuntu1" }] };
  const save = () => writeFileSync(path.join(reports, "lab-host-packages-run1.json"), JSON.stringify(report));
  save();
  return { ...exports, dir, reports, cache, report, save, scan: () => exports.scanPackageInventory({ hostAlias: "lab-host", reportId: "lab-host-packages-run1" }) };
}

test("Trivy fixed means a vulnerable installation with a patch available", (t) => {
  const { testing } = harness(t);
  const finding = testing.trivyFinding({ VulnerabilityID: "CVE-2026-1234", PkgName: "openssl", InstalledVersion: "1.0", FixedVersion: "1.1", Status: "fixed", Severity: "HIGH" });
  assert.equal(finding.status, "failed");
  assert.equal(finding.risk, "high");
  assert.match(finding.recommendation, /1\.1/);
  for (const status of ["affected", "will_not_fix", "fix_deferred"]) assert.equal(testing.trivyFinding({ Status: status }).status, "failed");
  assert.equal(testing.trivyFinding({ Status: "end_of_life" }).status, "manual");
});

test("Astra inventory preserves release and never becomes complete Debian CVE coverage", async (t) => {
  const h = harness(t);
  h.report.packageInventory.osRelease = { ID: "astra", ID_LIKE: "debian", NAME: "Astra Linux", VERSION_ID: "1.7_x86-64" };
  h.report.packageInventory.astraVersion = "1.7.6.15";
  h.save();
  const result = await h.scan();
  assert.equal(result.partial, true);
  assert.equal(result.report.vulnerabilityScan.ecosystem, null);
  assert.match(result.report.vulnerabilityScan.coverage.reasons.join(" "), /Astra/);
  const sbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", result.report.vulnerabilityScan.sbomFile), "utf8"));
  assert.equal(sbom.metadata.component.name, "astra");
  assert.ok(sbom.metadata.component.properties.some((property) => property.name === "hcp:astra-version" && property.value === "1.7.6.15"));
});

test("SBOM preserves distro, source version, epoch, arch and OS identity", (t) => {
  const h = harness(t);
  h.report.packages[0].sourceVersion = "2:3.0.2-0ubuntu1";
  h.report.packages[0].version = "2:3.0.2-0ubuntu1";
  const out = h.testing.writePackageSbom({ report: h.report, sourcePackageReportId: "lab-host-packages-run1", scanRunId: "fixture-sbom-run1" });
  const sbom = JSON.parse(readFileSync(out.sbomPath, "utf8"));
  assert.equal(sbom.metadata.component.name, "ubuntu");
  assert.equal(sbom.components[0].name, "libssl3");
  assert.match(sbom.components[0].purl, /arch=amd64&distro=ubuntu-22\.04&epoch=2/);
  const props = Object.fromEntries(sbom.components[0].properties.map((p) => [p.name, p.value]));
  assert.equal(props["aquasecurity:trivy:SrcName"], "openssl");
  assert.equal(props["aquasecurity:trivy:SrcVersion"], "3.0.2");
  assert.equal(props["aquasecurity:trivy:SrcRelease"], "0ubuntu1");
  assert.equal(props["aquasecurity:trivy:SrcEpoch"], "2");
  assert.deepEqual(sbom.dependencies[0].dependsOn, [sbom.components[0]["bom-ref"]]);
});

test("complete contract result records coverage without inventing a security score", async (t) => {
  const h = harness(t);
  const result = await h.scan();
  assert.equal(result.partial, false);
  assert.equal(result.report.summary.score, null);
  assert.equal(result.report.vulnerabilityScan.checkedPackages, 1);
  assert.equal(result.report.vulnerabilityScan.coverage.complete, true);
  assert.equal(result.report.inventoryHost, "lab-host");
  const { args, env } = JSON.parse(readFileSync(path.join(h.dir, "args.json"), "utf8"));
  for (const flag of ["--offline-scan", "--skip-db-update", "--skip-java-db-update", "--list-all-pkgs", "--disable-telemetry"]) assert.ok(args.includes(flag));
  assert.equal(args[args.indexOf("--pkg-types") + 1], "os");
  assert.equal(env.TRIVY_SERVER, undefined);
  assert.equal(env.TRIVY_SEVERITY, undefined);
  assert.equal(env.TRIVY_IGNORE_UNFIXED, undefined);
});

for (const response of ["empty", "missing-package", "wrong-os", "eosl"]) {
  test(`${response} scanner response remains incomplete after saving the report`, async (t) => {
    const h = harness(t, response);
    const result = await h.scan();
    const saved = JSON.parse(readFileSync(result.reportPath, "utf8"));
    assert.equal(result.partial, true);
    assert.equal(saved.scanner.partial, true);
    assert.equal(saved.vulnerabilityScan.partial, true);
    assert.equal(saved.summary.score, null);
    assert.ok(!saved.findings.some((f) => f.id === "trivy_no_known_vulnerabilities"));
    if (response === "empty") assert.equal(saved.vulnerabilityScan.checkedPackages, 0);
  });
}

test("CVE report retains findings beyond 1000 and fixes remain failures", async (t) => {
  const result = await harness(t, "many").scan();
  assert.equal(result.report.findings.length, 1005);
  assert.equal(result.report.summary.high, 1005);
});

test("repeated CVE scans keep separate immutable reports and SBOM snapshots", async (t) => {
  const h = harness(t);
  const first = await h.scan();
  const firstReport = readFileSync(first.reportPath, "utf8");
  const firstSbomPath = path.join(h.dir, "sbom", first.report.vulnerabilityScan.sbomFile);
  const firstSbom = readFileSync(firstSbomPath, "utf8");
  const second = await h.scan();
  assert.notEqual(second.reportId, first.reportId);
  assert.notEqual(second.report.runId, first.report.runId);
  assert.notEqual(second.report.vulnerabilityScan.sbomFile, first.report.vulnerabilityScan.sbomFile);
  assert.equal(second.report.vulnerabilityScan.sourcePackageReportId, first.report.vulnerabilityScan.sourcePackageReportId);
  assert.equal(readFileSync(first.reportPath, "utf8"), firstReport);
  assert.equal(readFileSync(firstSbomPath, "utf8"), firstSbom);
  const secondSbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", second.report.vulnerabilityScan.sbomFile), "utf8"));
  assert.equal(secondSbom.metadata.properties.find((p) => p.name === "hcp:scan-run-id").value, second.report.runId);
  assert.throws(() => h.testing.writePackageSbom({ report: h.report, sourcePackageReportId: "lab-host-packages-run1", scanRunId: first.report.runId }), /EEXIST/);
});

test("freshness requires a nonempty database and authoritative publication time", (t) => {
  const h = harness(t);
  const metadata = path.join(h.cache, "db/metadata.json");
  assert.equal(h.getTrivyDatabaseFreshness().status, "fresh");
  writeFileSync(metadata, JSON.stringify({ DownloadedAt: new Date().toISOString() }));
  assert.equal(h.getTrivyDatabaseFreshness().status, "unknown");
  rmSync(metadata);
  assert.equal(h.getTrivyDatabaseFreshness().status, "unknown");
  writeFileSync(metadata, JSON.stringify({ UpdatedAt: new Date(Date.now() - 168 * 3_600_000 - 1_000).toISOString() }));
  assert.equal(h.getTrivyDatabaseFreshness().status, "stale");
  writeFileSync(metadata, JSON.stringify({ UpdatedAt: new Date(Date.now() + 600_000).toISOString() }));
  assert.equal(h.getTrivyDatabaseFreshness().status, "unknown");
  writeFileSync(path.join(h.cache, "db/trivy.db"), "");
  assert.equal(h.getTrivyDatabaseFreshness().status, "missing");
});

test("host mismatch and empty/invalid inventory fail before invoking the scanner", async (t) => {
  const h = harness(t);
  await assert.rejects(h.scanPackageInventory({ hostAlias: "other-host", reportId: "lab-host-packages-run1" }), /не принадлежит/);
  h.report.inventoryHost = "../../escape";
  h.save();
  await assert.rejects(h.scanPackageInventory({ reportId: "lab-host-packages-run1" }), /некорректный alias/);
  h.report.inventoryHost = "lab-host";
  h.report.packages = [];
  h.save();
  await assert.rejects(h.scan(), /список пуст/);
});

test("dpkg inventory includes held installed packages and source metadata, excludes residual records", () => {
  const playbook = readFileSync(path.join(webDir, "../ansible/playbooks/package-inventory.yml"), "utf8");
  const body = playbook.split("python3 - <<'PY'\n")[1].split("\n        PY")[0].split("\n").map((line) => line.slice(8)).join("\n");
  const definitions = body.split("os_release = read_os_release()\n")[0];
  const script = `import json\nnamespace = {}\nexec(${JSON.stringify(definitions)}, namespace)\ncommands = []\ndef fake_run(command):\n    commands.append(command)\n    return 0, 'ii \\tlibssl3:amd64\\t3.0.2-1\\tamd64\\topenssl\\t3.0.2-1\\nhi \\tbash\\t5.2-1\\tamd64\\tbash\\t5.2-1\\nrc \\tremoved\\t1.0\\tamd64\\tremoved\\t1.0', ''\nnamespace['run'] = fake_run\npackages, error = namespace['debian_packages']()\nprint(json.dumps({'packages': packages, 'error': error, 'command': commands[0]}))`;
  const result = JSON.parse(execFileSync("python3", ["-c", script], { encoding: "utf8" }));
  assert.equal(result.error, "");
  assert.equal(result.packages.length, 2);
  assert.equal(result.packages[0].sourceName, "openssl");
  assert.equal(result.packages[1].name, "bash");
  assert.match(result.command.at(-1), /\$\{source:Version\}/);
});
