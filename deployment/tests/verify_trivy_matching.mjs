#!/usr/bin/env node
/**
 * Native Trivy acceptance over labelled synthetic inventories. No vulnerable
 * package is installed and no host is scanned. Requires Node 24, web/npm ci,
 * the real Trivy binary and a fresh real vulnerability database.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs, promisify } from "node:util";

const { values } = parseArgs({ options: {
  "web-dir": { type: "string", default: fileURLToPath(new URL("../../web", import.meta.url)) },
  output: { type: "string", default: ".lab/trivy-matching-acceptance" },
  binary: { type: "string", default: process.env.HCP_TRIVY_BIN || "trivy" },
  "cache-dir": { type: "string", default: process.env.HCP_TRIVY_CACHE_DIR },
  "expected-version": { type: "string", default: "0.74.0" },
  refresh: { type: "boolean", default: false },
} });
const webDir = path.resolve(values["web-dir"]);
const output = path.resolve(values.output);
const binary = values.binary.includes(path.sep) ? path.resolve(values.binary) : values.binary;
const runtime = mkdtempSync(path.join(tmpdir(), "hcp-trivy-matching-"));
const cache = path.resolve(values["cache-dir"] || path.join(runtime, "trivy-cache"));
const run = promisify(execFile);
const cve = "CVE-2023-0286";
const fixedVersion = "3.0.2-0ubuntu1.8";
const references = ["https://ubuntu.com/security/notices/USN-5844-1", "https://ubuntu.com/security/CVE-2023-0286"];
const protocol = {
  startedAt: new Date().toISOString(), status: "running", cve, references,
  scope: "Native Trivy Ubuntu vendor-advisory matching through production HCP SBOM generation, scanPackageInventory and report normalization",
  syntheticInventory: true, installedVulnerablePackages: false, scannedLiveHost: false,
  limitations: [
    "One Ubuntu 22.04 amd64 backport pair; not an estimate of overall false-positive or false-negative rates",
    "The fixed control is expected to omit this CVE only; unrelated vulnerabilities may remain",
    "Saved native stdout is a separate replay of each production-generated SBOM against the same unchanged database",
    "This acceptance bypasses HTTP and SSH inventory collection; those are covered by the separate lab checks",
  ],
  cases: [],
};
let compiled;
let ownsOutput = false;

function save(name, value) {
  writeFileSync(path.join(output, name), typeof value === "string" ? value : JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
}

async function sha256(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

function matchingFindings(report) {
  return report.findings.filter((finding) => finding.source === "trivy" && finding.id.startsWith(`trivy_${cve}_`));
}

try {
  assert.ok(!existsSync(path.join(output, "protocol.json")), "Choose a new output directory; an earlier protocol already exists");
  mkdirSync(output, { recursive: true, mode: 0o700 });
  ownsOutput = true;
  mkdirSync(path.join(runtime, "reports"));
  // Set storage before loading the full production module graph. No application
  // database, report or integration setting from the running lab is modified.
  process.env.HCP_STATE_DIR = runtime;
  process.env.HCP_REPORTS_DIR = path.join(runtime, "reports");
  process.env.HCP_TRIVY_BIN = binary;
  process.env.HCP_TRIVY_CACHE_DIR = cache;
  process.env.HCP_TRIVY_MODE = "offline";
  process.env.HCP_TRIVY_MAX_DB_AGE_HOURS = "24";
  process.chdir(webDir);
  const { compileServerModules } = await import(pathToFileURL(path.join(webDir, "tests/_typescript-loader.mjs")).href);
  compiled = compileServerModules(["vulnerability-scan", "ansible-reports", "state-store"]);
  const { scanPackageInventory, getTrivyDatabaseFreshness, refreshTrivyDatabase } = await import(compiled.url("vulnerability-scan"));
  const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
  const { setVulnerabilityDatabaseMode } = await import(compiled.url("state-store"));

  const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("TRIVY_")));
  environment.TRIVY_CACHE_DIR = cache;
  const version = await run(binary, ["--version"], { env: environment, timeout: 30_000, maxBuffer: 1024 * 1024 });
  save("native-version.stdout.txt", version.stdout);
  save("native-version.stderr.txt", version.stderr);
  const actualVersion = /^Version:\s*(\S+)/m.exec(version.stdout)?.[1];
  assert.equal(actualVersion, values["expected-version"], "Acceptance must use the expected native Trivy version");
  protocol.trivyVersion = actualVersion;
  protocol.sourceSha256 = Object.fromEntries(await Promise.all(
    ["vulnerability-scan.ts", "ansible-reports.ts", "state-store.ts"].map(async (name) => [name, await sha256(path.join(webDir, "lib", name))]),
  ));

  if (values.refresh) {
    setVulnerabilityDatabaseMode("online");
    await refreshTrivyDatabase();
  }
  setVulnerabilityDatabaseMode("offline");
  const freshness = getTrivyDatabaseFreshness();
  protocol.databaseFreshness = freshness;
  assert.equal(freshness.status, "fresh", "A real database published within 24 hours is required; use --refresh or a freshly prepared lab cache");
  const databasePath = path.join(cache, "db/trivy.db");
  const metadataPath = path.join(cache, "db/metadata.json");
  const metadata = readFileSync(metadataPath, "utf8");
  save("db-metadata.json", metadata);
  protocol.database = { sha256: await sha256(databasePath), bytes: statSync(databasePath).size, metadataSha256: await sha256(metadataPath), metadata: JSON.parse(metadata) };
  assert.equal(protocol.database.metadata.Version, 2, "Unexpected vulnerability database schema");
  save("protocol.json", protocol);

  for (const control of [
    { name: "vulnerable", version: "3.0.2-0ubuntu1.7", expectedCve: true },
    { name: "vendor-fixed-backport", version: fixedVersion, expectedCve: false },
  ]) {
    const hostAlias = "acceptance-ubuntu2204-" + control.name;
    const reportId = hostAlias + "-packages-fixture";
    const inventory = {
      schemaVersion: 1, mode: "packages", profileId: "packages", inventoryHost: hostAlias, hostname: hostAlias,
      createdAt: new Date().toISOString(), os: "Ubuntu 22.04 LTS (synthetic acceptance inventory)", partial: false,
      acceptanceFixture: { synthetic: true, installedPackage: false, cve, references, expectedCve: control.expectedCve },
      packageInventory: {
        osRelease: { ID: "ubuntu", NAME: "Ubuntu", VERSION_ID: "22.04", VERSION_CODENAME: "jammy" },
        manager: "dpkg", packageCount: 1, error: "", partial: false, partialReasons: [],
      },
      packages: [{ name: "libssl3:amd64", version: control.version, arch: "amd64", manager: "dpkg", sourceName: "openssl", sourceVersion: control.version, dpkgStatus: "ii " }],
      findings: [],
    };
    writeFileSync(path.join(runtime, "reports", reportId + ".json"), JSON.stringify(inventory), { flag: "wx", mode: 0o600 });
    save(control.name + ".inventory.json", inventory);
    const result = await scanPackageInventory({ hostAlias, reportId });
    save(control.name + ".hcp-report.json", result.report);
    const normalized = readAnsibleReport(result.reportId);
    save(control.name + ".normalized-report.json", normalized);
    assert.ok(normalized, "Production report normalizer must read the saved report");
    assert.ok(result.report.vulnerabilityScan.sbomFile, "Production adapter must produce an SBOM");
    const sbomPath = path.join(runtime, "sbom", result.report.vulnerabilityScan.sbomFile);
    const sbomContents = readFileSync(sbomPath, "utf8");
    save(control.name + ".sbom.cdx.json", sbomContents);
    const sbom = JSON.parse(sbomContents);

    // Replay with the real binary, without wrapping/substituting its output.
    // The original scan above also invoked the same binary via production code.
    const args = ["sbom", "--config", path.join(runtime, "trivy-scan-config.yaml"), "--format", "json", "--quiet", "--scanners", "vuln", "--pkg-types", "os", "--list-all-pkgs", "--disable-telemetry", "--ignorefile", "/dev/null", "--skip-db-update", "--skip-java-db-update", "--offline-scan", sbomPath];
    let native;
    try {
      native = await run(binary, args, { env: environment, timeout: 300_000, maxBuffer: 16 * 1024 * 1024 });
    } catch (error) {
      save(control.name + ".native.stdout.txt", error.stdout ?? "");
      save(control.name + ".native.stderr.txt", error.stderr ?? "");
      throw new Error(`Native Trivy replay failed (${error.code ?? error.signal ?? "unknown"}); see ${control.name}.native.stderr.txt`);
    }
    save(control.name + ".native.stdout.json", native.stdout);
    save(control.name + ".native.stderr.txt", native.stderr);
    const parsed = JSON.parse(native.stdout);
    assert.equal(parsed.SchemaVersion, 2, "Native replay must return a recognized report");
    assert.deepEqual([parsed.Metadata?.OS?.Family, parsed.Metadata?.OS?.Name], ["ubuntu", "22.04"]);
    const nativeOsResults = (parsed.Results ?? []).filter((entry) => entry.Class === "os-pkgs" && entry.Type === "ubuntu");
    const nativePackages = nativeOsResults.flatMap((entry) => entry.Packages ?? []);
    assert.equal(nativePackages.length, 1, "A missing native package result cannot prove the negative control");
    assert.equal(nativePackages[0].Identifier?.BOMRef ?? nativePackages[0].Identifier?.PURL, sbom.components[0]["bom-ref"]);
    assert.equal(result.partial, false, JSON.stringify(result.report.vulnerabilityScan));
    assert.equal(normalized.partial, false, "Normalization must preserve complete coverage");
    assert.equal(normalized.reportTimeValid, true);
    assert.equal(normalized.inventoryHost, hostAlias);
    assert.equal(normalized.score, null, "A CVE report must not invent a security percentage");
    assert.equal(result.report.vulnerabilityScan.databaseFreshness.status, "fresh");
    assert.deepEqual([result.report.vulnerabilityScan.coverage.inventoryPackages, result.report.vulnerabilityScan.coverage.scannedPackages], [1, 1]);
    assert.equal(result.report.vulnerabilityScan.coverage.complete, true);
    const nativeMatches = nativeOsResults.flatMap((entry) => entry.Vulnerabilities ?? []).filter((entry) => entry.VulnerabilityID === cve);
    const rawMatches = matchingFindings(result.report);
    const normalizedMatches = matchingFindings(normalized);
    const actual = {
      ...control, nativeMatches, hcpMatches: rawMatches, normalizedMatches,
      nativeTargetDetected: nativeMatches.length > 0, hcpTargetDetected: rawMatches.some((finding) => finding.status === "failed"),
      normalizedTargetDetected: normalizedMatches.some((finding) => finding.status === "failed"),
      allHcpFindings: normalized.findings.length, coverage: result.report.vulnerabilityScan.coverage,
      nativeStdoutSha256: createHash("sha256").update(native.stdout).digest("hex"), sbomSha256: await sha256(sbomPath),
    };
    protocol.cases.push(actual);
    save("protocol.json", protocol);
    assert.equal(actual.nativeTargetDetected, control.expectedCve, "Native advisory matching disagrees with the Ubuntu control");
    assert.equal(actual.hcpTargetDetected, control.expectedCve, "HCP adapter disagrees with the Ubuntu control");
    assert.equal(actual.normalizedTargetDetected, control.expectedCve, "HCP report normalization disagrees with the Ubuntu control");
    if (control.expectedCve) {
      assert.equal(nativeMatches.length, 1);
      assert.equal(nativeMatches[0].DataSource?.ID, "ubuntu");
      assert.equal(nativeMatches[0].FixedVersion, fixedVersion);
      assert.equal(nativeMatches[0].InstalledVersion, control.version);
      assert.equal(nativeMatches[0].Status, "fixed", "Vendor fixed status describes a patch available for the vulnerable installed version");
    } else {
      assert.equal(rawMatches.length, 0);
      assert.equal(normalizedMatches.length, 0);
    }
    console.log(`PASS ${control.name}: ${cve} ${control.expectedCve ? "detected" : "absent after vendor backport"}; native + HCP + normalized`);
  }

  protocol.databaseUnchanged = protocol.database.sha256 === await sha256(databasePath)
    && protocol.database.metadataSha256 === await sha256(metadataPath);
  assert.equal(protocol.databaseUnchanged, true, "Both controls must use the same unchanged database snapshot");
  protocol.status = "passed";
} catch (error) {
  protocol.status = "failed";
  protocol.error = error instanceof Error ? error.message : String(error);
  console.error(protocol.error);
  process.exitCode = 1;
} finally {
  protocol.finishedAt = new Date().toISOString();
  if (ownsOutput) save("protocol.json", protocol);
  if (compiled) rmSync(compiled.directory, { recursive: true, force: true });
  rmSync(runtime, { recursive: true, force: true });
}
