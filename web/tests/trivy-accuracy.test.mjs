import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import test from "node:test";
import { execFileSync } from "node:child_process";
import ts from "typescript";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiledOutputGuard = compileServerModules(["trivy-output"]);
const outputGuard = await import(compiledOutputGuard.url("trivy-output"));
test.after(() => rmSync(compiledOutputGuard.directory, { recursive: true, force: true }));

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const source = readFileSync(path.join(webDir, "lib/vulnerability-scan.ts"), "utf8");
const compiled = ts.transpileModule(source + "\nexport const testing = { trivyFinding, packagePurl, writePackageSbom, scanCoverage, packageProvenance, findingProvenance };", { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText;
const platform = {};
vm.runInNewContext(ts.transpileModule(readFileSync(path.join(webDir, "lib/linux-platform.ts"), "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText, { exports: platform });

function harness(t, response = "normal", mode = "offline", repositories = "") {
  const dir = mkdtempSync(path.join(tmpdir(), "hcp-trivy-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const reports = path.join(dir, "reports");
  const cache = path.join(dir, "cache");
  mkdirSync(reports);
  mkdirSync(path.join(cache, "db"), { recursive: true });
  writeFileSync(path.join(cache, "db/trivy.db"), "fixture, not a real Trivy database");
  writeFileSync(path.join(cache, "db/metadata.json"), JSON.stringify({ Version: 2, UpdatedAt: new Date().toISOString() }));
  // This executable is a contract fixture. These tests do not claim a live Trivy scan.
  const binary = path.join(dir, "trivy-fixture");
  writeFileSync(binary, `#!/usr/bin/env node\nconst fs = require('node:fs');\nconst args = process.argv.slice(2);\nconst response = ${JSON.stringify(response)};\nfs.writeFileSync(${JSON.stringify(path.join(dir, "args.json"))}, JSON.stringify({args, env: Object.fromEntries(Object.entries(process.env).filter(([name]) => name.startsWith('TRIVY_')))}));\nif(args.includes('--download-db-only')) fs.appendFileSync(${JSON.stringify(path.join(dir, "downloads.jsonl"))}, JSON.stringify(args) + '\\n');\nif(args.includes('--download-db-only') && response.startsWith('fallback-') && args[args.indexOf('--db-repository') + 1] !== 'ghcr.io/aquasecurity/trivy-db') { console.error(response === 'fallback-network' ? 'context deadline exceeded' : 'manifest unknown: 404'); process.exit(1); }\nif(args.includes('--download-db-only') && response === 'download-dns') { console.error('lookup ghcr.io: no such host'); process.exit(1); }\nif(args.includes('--download-db-only')) {\n  const activeCache = args[args.indexOf('--cache-dir') + 1];\n  fs.mkdirSync(activeCache + '/db', {recursive: true});\n  fs.writeFileSync(activeCache + '/db/trivy.db', 'downloaded fixture');\n  fs.writeFileSync(activeCache + '/db/metadata.json', JSON.stringify({Version: 2, UpdatedAt: new Date().toISOString()}));\n  process.exit(0);\n}\nif(args.includes('--version')) { console.log('Version: 0.74.0-contract-fixture'); process.exit(0); }\nconst sbom = JSON.parse(fs.readFileSync(args.at(-1), 'utf8'));\nlet output = {SchemaVersion: 2, Metadata: {OS: {Family: sbom.metadata.component.name, Name: sbom.metadata.component.version}}, Results: [{Class: 'os-pkgs', Type: sbom.metadata.component.name, Packages: sbom.components.map(p => ({Name: p.name, Version: p.version, Identifier: {BOMRef: p['bom-ref'], PURL: p.purl}})), Vulnerabilities: []}]};\nif(response === 'mutate-db') fs.appendFileSync(process.env.TRIVY_CACHE_DIR + '/db/trivy.db', 'changed');\nif(response === 'mutate-sbom') fs.appendFileSync(args.at(-1), ' ');\nif(response === 'vulnerable') output.Results[0].Vulnerabilities = [{VulnerabilityID:'CVE-2023-0286', PkgName:sbom.components[0].name, InstalledVersion:sbom.components[0].version, PkgIdentifier:{BOMRef:sbom.components[0]['bom-ref']}, FixedVersion:'3.0.2-0ubuntu1.8', Status:'fixed', Severity:'HIGH', DataSource:{ID:sbom.metadata.component.name}}];\nif(response === 'empty') output = {};\nif(response === 'missing-package') output.Results[0].Packages = [];\nif(response === 'wrong-os') output.Metadata.OS.Family = 'alpine';\nif(response === 'eosl') output.Metadata.OS.EOSL = true;\nif(response === 'many') output.Results[0].Vulnerabilities = Array.from({length: 1005}, (_,i) => ({VulnerabilityID:'CVE-2026-' + i, PkgName:'libssl3', InstalledVersion:'3.0.2-0ubuntu1', FixedVersion:'3.0.2-0ubuntu2', Status:'fixed', Severity:'HIGH'}));\nconsole.log(JSON.stringify(output));\n`);
  chmodSync(binary, 0o700);
  const env = { ...process.env, HCP_TRIVY_BIN: binary, HCP_TRIVY_CACHE_DIR: cache, HCP_TRIVY_MAX_DB_AGE_HOURS: "168", HCP_TRIVY_DB_REPOSITORY: repositories, TRIVY_SERVER: "https://must-not-be-used.invalid", TRIVY_SEVERITY: "LOW", TRIVY_IGNORE_UNFIXED: "true" };
  const exports = {};
  const mocks = {
    "@/lib/linux-platform": platform,
    "@/lib/trivy-output": outputGuard,
    "@/lib/ansible-control": { getStateDir: () => dir, getRepoRoot: () => path.resolve(webDir, "..") },
    "@/lib/ansible-reports": { getReportsDir: () => reports, listAnsibleReports: () => [], targetAliasFromReport: (r) => r.inventoryHost ?? r.fileName.replace(/-packages(?:-.*)?\.json$/, "") },
    "@/lib/state-store": { getVulnerabilityDatabaseSettings: () => ({ mode, source: "environment" }), appendAuditEvent: () => {} },
    "@/lib/astra-oval-policy": { describeAstraOvalNextStep: () => ({ ready: true, message: "OVAL-источник группы linux_hosts уже назначен. Запустите CVE Astra — OVAL / OpenSCAP.", href: "/hosts" }) },
  };
  vm.runInNewContext(compiled, { exports, require: (name) => mocks[name] ?? require(name), process: { env }, URLSearchParams, console: { warn: () => {}, log: () => {}, error: () => {} } });
  const report = { mode: "packages", profileId: "packages", inventoryHost: "lab-host", hostname: "different-hostname", createdAt: new Date().toISOString(), packageInventory: { packageCount: 1, manager: "dpkg", osRelease: { ID: "ubuntu", VERSION_ID: "22.04" }, error: "" }, packages: [{ name: "libssl3:amd64", version: "3.0.2-0ubuntu1", arch: "amd64", manager: "dpkg", sourceName: "openssl", sourceVersion: "3.0.2-0ubuntu1", maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", origin: "Ubuntu" }] };
  const save = () => writeFileSync(path.join(reports, "lab-host-packages-run1.json"), JSON.stringify(report));
  save();
  return { ...exports, dir, reports, cache, report, save, scan: () => exports.scanPackageInventory({ hostAlias: "lab-host", reportId: "lab-host-packages-run1" }), refresh: () => exports.refreshTrivyDatabase() };
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
  assert.match(result.message, /уже назначен/);
  assert.doesNotMatch(result.message, /один раз назначьте/);
  const sbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", result.report.vulnerabilityScan.sbomFile), "utf8"));
  assert.equal(sbom.metadata.component.name, "astra");
  assert.ok(sbom.metadata.component.properties.some((property) => property.name === "hcp:astra-version" && property.value === "1.7.6.15"));
});

test("Astra result without Results is incomplete coverage, not an unreadable SBOM", (t) => {
  const h = harness(t);
  h.report.packageInventory.osRelease = { ID: "astra", NAME: "Astra Linux", VERSION_ID: "1.7_x86-64" };
  h.report.packageInventory.astraVersion = "1.7.6.15";
  const coverage = h.testing.scanCoverage({
    SchemaVersion: 2,
    Metadata: { OS: { Family: "astra", Name: "1.7_x86-64" } },
  }, h.report);
  assert.equal(coverage.complete, false);
  assert.match(coverage.reasons.join(" "), /не вернул секцию результатов/);
  assert.match(coverage.reasons.join(" "), /Astra/);
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
  const evidence = result.report.vulnerabilityScan.sourceEvidence;
  assert.equal(evidence.status, "unchanged");
  assert.match(evidence.engineVersion, /0\.74\.0-contract-fixture/);
  assert.equal(evidence.before.database.sha256, createHash("sha256").update(readFileSync(path.join(h.cache, "db/trivy.db"))).digest("hex"));
  assert.deepEqual(evidence.before, evidence.after);
  assert.equal(result.report.vulnerabilityScan.packageProvenance.cryptographicallyVerified, false);
});

test("SBOM keeps observed maintainer/origin without inventing repository attestation", (t) => {
  const h = harness(t);
  const out = h.testing.writePackageSbom({ report: h.report, sourcePackageReportId: "lab-host-packages-run1", scanRunId: "provenance-fixture" });
  const component = JSON.parse(readFileSync(out.sbomPath, "utf8")).components[0];
  const props = Object.fromEntries(component.properties.map((p) => [p.name, p.value]));
  assert.equal(component.supplier.name, h.report.packages[0].maintainer);
  assert.equal(props["hcp:origin"], "Ubuntu");
  assert.equal(props["hcp:package-provenance"], "distribution-maintainer");
  assert.match(props["hcp:provenance-method"], /unverified/);
});

test("third-party and unknown package matches remain visible with unverified applicability", async (t) => {
  for (const metadata of [
    { maintainer: "NodeSource <support@nodesource.com>", origin: "" },
    { maintainer: "Unknown Builder <builder@example.org>", origin: "" },
    { maintainer: "Ubuntu Developers <dev@ubuntu.com.attacker.invalid>", origin: "Ubuntu" },
    { maintainer: "Ubuntu Developers <dev@ubuntu.com>", origin: "Unrelated repository" },
  ]) {
    const h = harness(t, "vulnerable");
    Object.assign(h.report.packages[0], metadata);
    h.save();
    const result = await h.scan();
    const matching = result.report.findings.find((finding) => finding.id.startsWith("trivy_CVE-2023-0286_"));
    assert.ok(matching, "Potential CVE observations must be retained");
    assert.equal(matching.status, "manual");
    assert.match(matching.evidence, /applicability=unverified/);
    assert.equal(result.partial, true);
    assert.equal(result.report.vulnerabilityScan.vendorAssessment.verified, false);
    assert.equal(result.report.vulnerabilityScan.coverage.complete, false);
  }
});

test("legacy inventory remains readable but does not assert complete vendor coverage", async (t) => {
  const h = harness(t);
  delete h.report.packages[0].maintainer;
  delete h.report.packages[0].origin;
  h.save();
  const result = await h.scan();
  assert.equal(result.partial, true);
  assert.equal(result.report.vulnerabilityScan.checkedPackages, 1);
  assert.match(result.report.vulnerabilityScan.coverage.reasons.join(" "), /старых инвентарей/);
  assert.ok(!result.report.findings.some((finding) => finding.id === "trivy_no_known_vulnerabilities"));
  assert.equal(result.report.assetBinding, undefined);
});

test("derived CVE report retains only the asset binding captured with its source inventory", async (t) => {
  const h = harness(t);
  const binding = { version: 1, assetId: "asset-observed-at-collection", alias: "lab-host", generation: 3,
    machineIdSha256: "a".repeat(64), sshHostKeyFingerprint: "SHA256:collection-time", verifiedAt: "2026-10-28T08:00:00Z" };
  h.report.assetBinding = binding;
  h.save();
  const result = await h.scan();
  assert.equal(JSON.stringify(result.report.assetBinding), JSON.stringify(binding));
});

test("architecture and source epoch remain distinct through the complete scan", async (t) => {
  const h = harness(t);
  const original = h.report.packages[0];
  original.version = original.sourceVersion = "2:3.0.2-0ubuntu1";
  h.report.packages.push({ ...original, name: "libssl3:i386", arch: "i386" });
  h.report.packageInventory.packageCount = 2;
  h.save();
  const result = await h.scan();
  assert.equal(result.partial, false);
  assert.equal(result.report.vulnerabilityScan.coverage.scannedPackages, 2);
  const sbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", result.report.vulnerabilityScan.sbomFile), "utf8"));
  assert.equal(new Set(sbom.components.map((component) => component["bom-ref"])).size, 2);
  for (const component of sbom.components) assert.match(component.purl, /epoch=2/);
});

for (const response of ["mutate-db", "mutate-sbom"]) {
  test(`${response} cannot publish an empty successful CVE verdict`, async (t) => {
    const h = harness(t, response);
    const result = await h.scan();
    assert.equal(result.partial, true);
    assert.equal(result.report.vulnerabilityScan.sourceEvidence.status, "changed");
    assert.match(result.report.findings[0].evidence, /source_failure=source_changed/);
    assert.equal(result.report.vulnerabilityScan.coverage.complete, false);
    assert.ok(!result.report.findings.some((finding) => finding.status === "passed"));
  });
}

test("concurrent scans use separate config files and both retain unchanged evidence", async (t) => {
  const h = harness(t);
  const results = await Promise.all([h.scan(), h.scan()]);
  for (const result of results) {
    assert.equal(result.partial, false);
    assert.equal(result.report.vulnerabilityScan.sourceEvidence.status, "unchanged");
  }
  const configs = results.map((result) => {
    const args = result.report.vulnerabilityScan.sourceEvidence.parameters;
    return args[args.indexOf("--config") + 1];
  });
  assert.notEqual(configs[0], configs[1]);
});

test("online source downloads the Trivy database before a CVE audit", async (t) => {
  const h = harness(t, "normal", "online");
  const freshness = await h.refresh();
  assert.equal(freshness.status, "fresh");
  const { args, env } = JSON.parse(readFileSync(path.join(h.dir, "args.json"), "utf8"));
  for (const flag of ["image", "--download-db-only", "--disable-telemetry", "--quiet", "--cache-dir"]) assert.ok(args.includes(flag));
  assert.deepEqual(args.filter((item) => item.includes("trivy-db")), ["mirror.gcr.io/aquasec/trivy-db"]);
  assert.equal(env.TRIVY_SERVER, undefined);
  assert.equal(env.TRIVY_SEVERITY, undefined);
  assert.equal(env.TRIVY_IGNORE_UNFIXED, undefined);
});

for (const response of ["fallback-network", "fallback-source"]) {
  test(`database refresh reaches a healthy registry after ${response}`, async (t) => {
    const h = harness(t, response, "online");
    writeFileSync(path.join(h.cache, "db/metadata.json"), JSON.stringify({ UpdatedAt: "2020-01-01T00:00:00Z" }));
    assert.equal((await h.refresh()).status, "fresh");
    const attempts = readFileSync(path.join(h.dir, "downloads.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
    assert.deepEqual(attempts.map((args) => args[args.indexOf("--db-repository") + 1]), [
      "mirror.gcr.io/aquasec/trivy-db", "ghcr.io/aquasecurity/trivy-db",
    ]);
  });
}

test("configured mirrors fail without silently contacting public repositories", async (t) => {
  const h = harness(t, "download-dns", "online", "registry.internal/first,registry.internal/second");
  await assert.rejects(h.refresh(), /настроенного OCI-зеркала.*DNS/);
  const attempts = readFileSync(path.join(h.dir, "downloads.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  assert.deepEqual(attempts.map((args) => args[args.indexOf("--db-repository") + 1]), ["registry.internal/first", "registry.internal/second"]);
});

test("online package audit consumes the downloaded snapshot without another registry request", async (t) => {
  const h = harness(t, "normal", "online");
  const result = await h.scan();
  assert.equal(result.partial, false);
  const { args } = JSON.parse(readFileSync(path.join(h.dir, "args.json"), "utf8"));
  assert.ok(args.includes("--skip-db-update"));
  assert.ok(args.includes("--skip-java-db-update"));
  assert.ok(!args.includes("--offline-scan"));
  assert.ok(!args.includes("--db-repository"));
});

test("online package audit automatically prepares the shared database when it is missing", async (t) => {
  const h = harness(t, "normal", "online");
  rmSync(path.join(h.cache, "db", "trivy.db"));
  const result = await h.scan();
  assert.equal(result.partial, false);
  assert.equal(existsSync(path.join(h.cache, "db", "trivy.db")), true);
  assert.equal(h.getTrivyDatabaseFreshness().status, "fresh");
  assert.equal(existsSync(path.join(h.dir, "sbom", result.report.vulnerabilityScan.sbomFile)), true);
});

test("database refresh classifies a container DNS failure without exposing command output", async (t) => {
  const h = harness(t, "download-dns", "online");
  await assert.rejects(h.refresh(), /Контейнер HCP не смог разрешить адрес registry по DNS/);
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

test("partial source inventory never becomes a complete CVE result", async (t) => {
  const cases = [
    (report) => { report.partial = true; },
    (report) => { report.scanner = { partial: true }; },
    (report) => { report.scanner = { error: "Incomplete collection" }; },
    (report) => { report.packageInventory.partial = true; },
    (report) => { report.packageInventory.partialReasons = ["Interrupted package configuration"]; },
  ];
  for (const markPartial of cases) {
    const h = harness(t);
    markPartial(h.report);
    h.save();
    const result = await h.scan();
    assert.equal(result.partial, true);
    assert.equal(result.report.vulnerabilityScan.coverage.complete, false);
    assert.match(result.report.vulnerabilityScan.coverage.reasons.join(" "), /Исходная инвентаризация/);
    assert.ok(!result.report.findings.some((finding) => finding.status === "passed"));
  }
});

test("unconfigured dpkg packages are checked with their state and remain partial", async (t) => {
  const h = harness(t, "many");
  h.report.packages[0].dpkgStatus = "iU ";
  h.report.packageInventory.partial = true;
  h.report.packageInventory.partialReasons = ["dpkg package is unpacked"];
  h.save();
  const result = await h.scan();
  assert.equal(result.partial, true);
  assert.equal(result.report.vulnerabilityScan.coverage.scannedPackages, 1);
  assert.equal(result.report.findings.filter((finding) => finding.status === "failed").length, 1005);
  assert.match(result.report.vulnerabilityScan.coverage.reasons.join(" "), /dpkg package is unpacked/);
  const sbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", result.report.vulnerabilityScan.sbomFile), "utf8"));
  assert.equal(sbom.components[0].properties.find((p) => p.name === "hcp:dpkg-status").value, "iU ");

  // Even if an older producer omits its aggregate partial flag, package state
  // itself cannot be converted into a complete negative assessment.
  delete h.report.packageInventory.partial;
  delete h.report.packageInventory.partialReasons;
  h.save();
  assert.equal((await h.scan()).partial, true);
});

test("malformed completeness metadata is rejected before a scanner invocation", async (t) => {
  for (const partialMetadata of [{ partial: "false" }, { partialReasons: "lost packages" }, { partialReasons: [false] }]) {
    const h = harness(t);
    Object.assign(h.report.packageInventory, partialMetadata);
    h.save();
    await assert.rejects(h.scan(), /сведения о полноте/);
    assert.equal(existsSync(path.join(h.dir, "args.json")), false);
  }
});

test("dpkg inventory includes held installed packages and source metadata, excludes residual records", () => {
  const definitions = readFileSync(path.join(webDir, "../ansible/scripts/hcp-package-inventory.py"), "utf8");
  const script = `import json\nnamespace = {}\nexec(${JSON.stringify(definitions)}, namespace)\ncommands = []\ndef fake_run(command):\n    commands.append(command)\n    return 0, 'ii \\tlibssl3:amd64\\t3.0.2-1\\tamd64\\topenssl\\t3.0.2-1\\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\\t\\nhi \\tbash\\t5.2-1\\tamd64\\tbash\\t5.2-1\\tDebian Bash Team <pkg-bash@lists.debian.org>\\t\\nrc \\tremoved\\t1.0\\tamd64\\tremoved\\t1.0', ''\nnamespace['run'] = fake_run\npackages, error = namespace['debian_packages']()\nprint(json.dumps({'packages': packages, 'error': error, 'command': commands[0]}))`;
  const result = JSON.parse(execFileSync("python3", ["-c", script], { encoding: "utf8" }));
  assert.equal(result.error, "");
  assert.equal(result.packages.length, 2);
  assert.equal(result.packages[0].sourceName, "openssl");
  assert.equal(result.packages[1].name, "bash");
  assert.equal(result.packages[1].dpkgStatus, "hi ");
  assert.match(result.command.at(-1), /\$\{source:Version\}/);
});

function nativeApk(h) {
  h.report.packageInventory = { manager: "apk", packageCount: 1, error: "", osRelease: { ID: "alpine", VERSION_ID: "3.22.2" },
    apkRepositories: { status: "observed", branches: ["v3.22"], unknownEntries: 0, scope: "configured-repositories; installed-origin-not-attested" } };
  h.report.packages = [{ name: "libcrypto3", version: "3.3.3-r0", arch: "x86_64", manager: "apk", sourceName: "openssl",
    sourceVersion: "3.3.3-r0", apkOrigin: "openssl", apkCommit: "observed-aports-commit", sourceEpochKnown: true,
    maintainer: "Alpine Build Team <team@alpinelinux.org>" }];
  h.save();
  return h;
}

function nativeRpm(h, id = "almalinux", vendor = "AlmaLinux") {
  h.report.packageInventory = { manager: "rpm", packageCount: 1, error: "", osRelease: { ID: id, VERSION_ID: "9.6" } };
  h.report.packages = [{ name: "openssl-libs", version: "1:3.2.2-6.el9_5.1", arch: "x86_64", manager: "rpm",
    sourceName: "openssl", sourceVersion: "3.2.2-6.el9_5.1", sourceRpm: "openssl-3.2.2-6.el9_5.1.src.rpm", sourceEpochKnown: false,
    vendor, maintainer: vendor, packager: `${vendor} Packaging Team`, distribution: vendor, modularityLabel: "",
    rpmModularityQueried: true, rpmRepositoryEvidence: "not-recorded-in-rpmdb" }];
  h.save();
  return h;
}

test("APK source origin and full revision survive SBOM and package coverage", async (t) => {
  const h = nativeApk(harness(t));
  const result = await h.scan();
  assert.equal(result.partial, false);
  assert.equal(result.report.vulnerabilityScan.coverage.scannedPackages, 1);
  assert.match(result.report.vulnerabilityScan.coverage.scope, /apk/);
  const sbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", result.report.vulnerabilityScan.sbomFile), "utf8"));
  assert.equal(sbom.metadata.component.name, "alpine");
  const component = sbom.components[0];
  assert.equal(component.version, "3.3.3-r0");
  assert.match(component.purl, /^pkg:apk\/alpine\/libcrypto3@3\.3\.3-r0\?arch=x86_64&distro=alpine-3\.22\.2$/);
  const props = Object.fromEntries(component.properties.map((p) => [p.name, p.value]));
  assert.equal(props["aquasecurity:trivy:SrcName"], "openssl");
  assert.equal(props["aquasecurity:trivy:SrcVersion"], "3.3.3-r0");
  assert.equal(props["aquasecurity:trivy:SrcRelease"], "");
  assert.equal(props["hcp:apk-origin"], "openssl");
  assert.equal(props["hcp:apk-commit"], "observed-aports-commit");
  assert.equal(props["hcp:source-epoch-known"], "true");
  assert.equal(result.report.vulnerabilityScan.packageProvenance.cryptographicallyVerified, false);
});

test("APK mixed releases, edge, unknown origins and damaged source versions never become PASS", async (t) => {
  const mutations = [
    (h) => { h.report.packageInventory.apkRepositories.branches = ["v3.22", "edge"]; },
    (h) => { h.report.packageInventory.apkRepositories.branches = ["edge"]; },
    (h) => { delete h.report.packageInventory.apkRepositories; },
    (h) => { h.report.packageInventory.apkRepositories.unknownEntries = 1; },
    (h) => { h.report.packages[0].sourceVersion = "3.3.3"; },
    (h) => { h.report.packages[0].apkOrigin = "unrelated-source"; },
    (h) => { h.report.packages[0].maintainer = "Unknown builder <builder@example.org>"; },
  ];
  for (const mutate of mutations) {
    const h = nativeApk(harness(t));
    mutate(h);
    h.save();
    const result = await h.scan();
    assert.equal(result.partial, true);
    assert.equal(result.report.vulnerabilityScan.coverage.scannedPackages, 1);
    assert.ok(!result.report.findings.some((finding) => finding.status === "passed"));
  }
});

test("RPM binary epoch is preserved while unobserved source epoch does not block binary EVR detectors", async (t) => {
  for (const [id, vendor, expectedFamily] of [["almalinux", "AlmaLinux", "alma"], ["rocky", "Rocky Enterprise Software Foundation", "rocky"],
    ["ol", "Oracle America", "oracle"], ["amzn", "Amazon Linux", "amazon"], ["sles", "SUSE LLC", "sles"],
    ["opensuse-leap", "openSUSE", "opensuse-leap"]]) {
    const h = nativeRpm(harness(t), id, vendor);
    const result = await h.scan();
    assert.equal(result.partial, false, id);
    const sbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", result.report.vulnerabilityScan.sbomFile), "utf8"));
    assert.equal(sbom.metadata.component.name, expectedFamily);
    const expectedNamespace = expectedFamily === "sles" ? "suse" : expectedFamily === "opensuse-leap" ? "opensuse" : expectedFamily;
    assert.ok(sbom.components[0].purl.startsWith(`pkg:rpm/${expectedNamespace}/`), "Native Trivy rejects mismatched OS PURL namespaces");
    assert.match(sbom.components[0].purl, /epoch=1/);
    const props = Object.fromEntries(sbom.components[0].properties.map((p) => [p.name, p.value]));
    assert.equal(props["aquasecurity:trivy:SrcVersion"], "3.2.2");
    assert.equal(props["aquasecurity:trivy:SrcRelease"], "6.el9_5.1");
    assert.equal(props["aquasecurity:trivy:SrcEpoch"], undefined);
    assert.equal(props["hcp:source-epoch-known"], "false");
    assert.equal(props["hcp:rpm-vendor"], vendor);
    assert.equal(props["hcp:source-rpm"], "openssl-3.2.2-6.el9_5.1.src.rpm");
    assert.equal(props["hcp:rpm-repository-evidence"], "not-recorded-in-rpmdb");
  }
});

test("RPM missing module evidence and mismatched vendors cannot become complete coverage", async (t) => {
  const mutations = [
    (h) => { h.report.packages[0].rpmModularityQueried = false; },
    (h) => { h.report.packages[0].version = "1:3.2.2-6.module_el9_5.1"; },
    (h) => { h.report.packages[0].vendor = "Independent Repository"; },
    (h) => { delete h.report.packages[0].vendor; },
  ];
  for (const mutate of mutations) {
    const h = nativeRpm(harness(t));
    mutate(h);
    h.save();
    const result = await h.scan();
    assert.equal(result.partial, true);
    assert.ok(!result.report.findings.some((finding) => finding.status === "passed"));
  }
});

test("RPM trust records stay in inventory and SBOM but are not counted as CVE-tested software", async (t) => {
  const h = nativeRpm(harness(t));
  const key = { name: "gpg-pubkey", version: "b86b3716-61e69f29", manager: "rpm", arch: "None",
    sourceEpochKnown: false, rpmModularityQueried: true, packager: "AlmaLinux OS 9 <packager@almalinux.org>" };
  h.report.packages.push(key);
  h.report.packageInventory.packageCount = 2;
  h.save();
  const result = await h.scan();
  const scan = result.report.vulnerabilityScan;
  assert.equal(result.partial, false);
  assert.deepEqual([scan.coverage.inventoryPackages, scan.coverage.decodedRecords, scan.coverage.eligiblePackages, scan.coverage.scannedPackages], [2, 2, 1, 1]);
  assert.equal(scan.checkedPackages, 1);
  assert.equal(scan.packageProvenance.unknown, 0);
  assert.equal(scan.packageProvenance.excludedNonSoftwareRecords, 1);
  assert.equal(scan.coverage.excludedNonSoftware[0].reason, "rpm-public-key-record");
  assert.equal(scan.coverage.excludedNonSoftware[0].version, key.version);
  const sbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", scan.sbomFile), "utf8"));
  assert.equal(sbom.components.length, 2);
  const component = sbom.components.find((pkg) => pkg.name === "gpg-pubkey");
  assert.equal(component.version, key.version);
  assert.equal(component["bom-ref"], scan.coverage.excludedNonSoftware[0].purl);
  assert.ok(component.properties.some((property) => property.name === "hcp:record-kind" && property.value === "rpm-public-key-record"));
  assert.match(result.report.findings.find((finding) => finding.status === "passed").evidence, /checked=1; non_software_records=1/);

  // A native record for the key cannot conceal a missing software package.
  const output = { SchemaVersion: 2, Metadata: { OS: { Family: "alma", Name: "9.6" } },
    Results: [{ Class: "os-pkgs", Type: "alma", Packages: [{ Name: key.name, Identifier: { BOMRef: component["bom-ref"] } }] }] };
  const coverage = h.testing.scanCoverage(output, h.report);
  assert.equal(coverage.complete, false);
  assert.equal(coverage.scannedPackages, 0);
  assert.match(coverage.reasons.join(" "), /0 из 1/);
});

test("key-only inventories and software names resembling RPM trust records cannot issue an empty PASS", async (t) => {
  for (const variant of ["key-only", "prefix", "non-rpm"]) {
    const h = variant === "non-rpm" ? harness(t) : nativeRpm(harness(t));
    h.report.packages[0].name = variant === "prefix" ? "gpg-pubkey-helper" : "gpg-pubkey";
    delete h.report.packages[0].vendor;
    delete h.report.packages[0].maintainer;
    h.save();
    const result = await h.scan();
    assert.equal(result.partial, true, variant);
    assert.equal(result.report.vulnerabilityScan.coverage.excludedNonSoftware.length, variant === "key-only" ? 1 : 0);
    assert.ok(!result.report.findings.some((finding) => finding.status === "passed"), variant);
  }
});

test("RHEL content sets and native modularity properties are preserved instead of assuming coverage", async (t) => {
  const h = nativeRpm(harness(t), "rhel", "Red Hat, Inc.");
  const first = await h.scan();
  assert.equal(first.partial, true);
  assert.match(first.report.vulnerabilityScan.coverage.reasons.join(" "), /content sets/);
  Object.assign(h.report.packages[0], { contentSets: ["rhel-9-for-x86_64-baseos-rpms", "rhel-9-for-x86_64-appstream-rpms"],
    buildNvr: "openssl-3.2.2-6.el9_5.1", buildArch: "x86_64", modularityLabel: "openssl:3.2:90001:context" });
  h.save();
  const second = await h.scan();
  assert.equal(second.partial, false);
  const sbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", second.report.vulnerabilityScan.sbomFile), "utf8"));
  const props = sbom.components[0].properties;
  assert.deepEqual(props.filter((p) => p.name === "aquasecurity:trivy:ContentSet").map((p) => p.value), h.report.packages[0].contentSets);
  assert.equal(props.find((p) => p.name === "aquasecurity:trivy:Modularitylabel").value, "openssl:3.2:90001:context");
  assert.equal(props.find((p) => p.name === "aquasecurity:trivy:NVR").value, "openssl-3.2.2-6.el9_5.1");
  assert.equal(props.find((p) => p.name === "aquasecurity:trivy:Arch").value, "x86_64");
  assert.match(sbom.components[0].purl, /^pkg:rpm\/redhat\//);
});

test("unknown derivatives and CentOS Stream never inherit a parent advisory database", async (t) => {
  for (const identity of [{ ID: "private-linux", ID_LIKE: "ubuntu debian", VERSION_ID: "22.04" },
    { ID: "centos", NAME: "CentOS Stream", ID_LIKE: "rhel fedora", VERSION_ID: "9" }]) {
    const h = harness(t);
    h.report.packageInventory.osRelease = identity;
    h.save();
    const result = await h.scan();
    assert.equal(result.partial, true);
    assert.equal(result.report.vulnerabilityScan.ecosystem, null);
    assert.match(result.report.vulnerabilityScan.coverage.reasons.join(" "), /точного дистрибутива/);
    const sbom = JSON.parse(readFileSync(path.join(h.dir, "sbom", result.report.vulnerabilityScan.sbomFile), "utf8"));
    assert.equal(sbom.metadata.component.name, identity.ID);
  }
});

test("CentOS vendor metadata cannot confirm CVE applicability for CentOS Stream", async (t) => {
  for (const stream of [false, true]) {
    const h = nativeRpm(harness(t, "vulnerable"), "centos", "CentOS");
    h.report.packageInventory.osRelease = { ID: "centos", NAME: stream ? "CentOS Stream" : "CentOS Linux", VERSION_ID: "9" };
    h.save();
    const result = await h.scan();
    const observation = result.report.findings.find((finding) => finding.id.startsWith("trivy_CVE-2023-0286_"));
    assert.ok(observation, "Potential matches must remain visible");
    assert.equal(observation.status, stream ? "manual" : "failed");
    assert.equal(result.report.vulnerabilityScan.vendorAssessment.verified, !stream);
    assert.equal(result.report.vulnerabilityScan.packageProvenance["distribution-maintainer"], 1, "The observed vendor metadata remains preserved separately");
    if (stream) {
      assert.equal(result.partial, true);
      assert.match(observation.evidence, /applicability=unverified/);
      assert.match(result.report.vulnerabilityScan.coverage.reasons.join(" "), /точного дистрибутива/);
    }
  }
});

test("native manager mismatch and malformed ecosystem metadata cannot bypass completeness checks", async (t) => {
  const h = nativeApk(harness(t));
  h.report.packageInventory.osRelease = { ID: "ubuntu", VERSION_ID: "22.04" };
  h.save();
  assert.match((await h.scan()).report.vulnerabilityScan.coverage.reasons.join(" "), /Менеджер пакетов/);
  for (const invalid of [{ contentSets: "all" }, { sourceEpochKnown: "true" }, { rpmModularityQueried: "false" }, { modularityLabel: "line\nbreak" }]) {
    const fixture = nativeRpm(harness(t));
    Object.assign(fixture.report.packages[0], invalid);
    fixture.save();
    await assert.rejects(fixture.scan(), /сведения о полноте/);
    assert.equal(existsSync(path.join(fixture.dir, "args.json")), false);
  }
});
