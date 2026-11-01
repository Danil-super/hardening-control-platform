#!/usr/bin/env node
/**
 * node deployment/tests/verify_linux_packages.mjs <native-inventory.json> <output-directory>
 * node deployment/tests/verify_linux_packages.mjs --controls-only=alpine|alma|rocky|debian|ubuntu <output-directory>
 * Node 24 + web/npm ci; HCP_TRIVY_BIN and HCP_TRIVY_CACHE_DIR select the real
 * pinned engine/cache. A missing/stale DB is refreshed through production HCP.
 * The calling VM harness establishes SSH/collector provenance for the input.
 * This helper installs no packages and never invokes a fixture scanner.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const webDir = path.join(repoRoot, "web");
const run = promisify(execFile);
const fixtures = JSON.parse(readFileSync(new URL("fixtures/linux-package-controls.json", import.meta.url), "utf8"));

async function sha256(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

export function versionParts(value) {
  const epochMatch = /^(?:(\d+):)?(.+)$/.exec(value);
  const body = epochMatch[2];
  const split = body.lastIndexOf("-");
  return { epoch: Number(epochMatch[1] || 0), version: split < 0 ? body : body.slice(0, split), release: split < 0 ? "" : body.slice(split + 1) };
}

export function assertPackageConservation(inventory, sbom, native) {
  assert.equal(sbom.components.length, inventory.packages.length, "SBOM must preserve every installed record");
  const osResults = (native.Results ?? []).filter((entry) => entry.Class === "os-pkgs" && entry.Type === sbom.metadata.component.name);
  const nativePackages = osResults.flatMap((entry) => entry.Packages ?? []);
  const byRef = new Map(nativePackages.map((pkg) => [pkg.Identifier?.BOMRef ?? pkg.Identifier?.PURL, pkg]));
  assert.equal(nativePackages.length, inventory.packages.length, "Native decoding must neither omit nor add records");
  assert.equal(byRef.size, inventory.packages.length, "Every inventory package needs a native engine result; a skipped record is not a negative CVE result");
  for (let index = 0; index < inventory.packages.length; index++) {
    const pkg = inventory.packages[index];
    const component = sbom.components[index];
    const props = Object.fromEntries(component.properties.map((p) => [p.name, p.value]));
    const decoded = byRef.get(component["bom-ref"]);
    assert.ok(decoded, `Missing native result for ${pkg.name}`);
    const name = pkg.manager === "dpkg" && pkg.name.endsWith(`:${pkg.arch}`) ? pkg.name.slice(0, -(pkg.arch.length + 1)) : pkg.name;
    assert.equal(component.name, name);
    assert.equal(component.version, pkg.version);
    assert.equal(decoded.Name, name);
    assert.equal(decoded.Arch, pkg.arch);
    assert.equal(props["hcp:package-manager"], pkg.manager);
    assert.equal(props["hcp:architecture"], pkg.arch);
    assert.equal(component.purl, component["bom-ref"], "Stable package identity must include architecture, release and epoch");
    const qualifiers = new URLSearchParams(component.purl.split("?")[1] || "");
    assert.equal(qualifiers.get("arch"), pkg.arch);
    const binaryParts = pkg.manager === "apk" ? { epoch: 0, version: pkg.version, release: "" }
      : pkg.manager === "dpkg" ? { epoch: versionParts(pkg.version).epoch, version: pkg.version.replace(/^\d+:/, ""), release: "" } : versionParts(pkg.version);
    assert.deepEqual([decoded.Epoch ?? 0, decoded.Version, decoded.Release ?? ""], [binaryParts.epoch, binaryParts.version, binaryParts.release], `Binary version changed for ${name}`);
    if (pkg.sourceName && pkg.sourceVersion) {
      const sourceParts = pkg.manager === "apk" ? { epoch: 0, version: pkg.sourceVersion, release: "" } : versionParts(pkg.sourceVersion);
      assert.equal(decoded.SrcName, pkg.sourceName, `Source origin changed for ${name}`);
      assert.equal(props["aquasecurity:trivy:SrcName"], pkg.sourceName);
      assert.deepEqual([props["aquasecurity:trivy:SrcVersion"], props["aquasecurity:trivy:SrcRelease"]], [sourceParts.version, sourceParts.release], `SBOM source metadata changed for ${name}`);
      assert.deepEqual([decoded.SrcVersion, decoded.SrcRelease ?? ""], [sourceParts.version, sourceParts.release], `Source version changed for ${name}`);
      if (pkg.sourceEpochKnown !== false) assert.equal(decoded.SrcEpoch ?? 0, sourceParts.epoch);
      else {
        assert.equal(props["aquasecurity:trivy:SrcEpoch"], undefined, "Unknown RPM source epoch must not be manufactured");
        assert.equal(decoded.SrcEpoch ?? 0, 0, "Native decoder must not substitute a binary epoch when source name/version are present");
      }
    }
    for (const [field, property] of [["vendor", "hcp:rpm-vendor"], ["packager", "hcp:rpm-packager"], ["distribution", "hcp:rpm-distribution"],
      ["sourceRpm", "hcp:source-rpm"], ["rpmRepositoryEvidence", "hcp:rpm-repository-evidence"], ["apkOrigin", "hcp:apk-origin"], ["apkCommit", "hcp:apk-commit"],
      ["dpkgStatus", "hcp:dpkg-status"], ["maintainer", "hcp:maintainer"], ["origin", "hcp:origin"]]) {
      if (pkg[field]) assert.equal(props[property], pkg[field], `${field} must remain an observation`);
    }
    if (pkg.manager === "dpkg") {
      assert.match(component.purl, /^pkg:deb\//);
      assert.equal(props["aquasecurity:trivy:PkgID"], component.purl, "DEB native IDs must preserve multiarch identity");
      assert.equal(decoded.ID, component.purl, "The real decoder must honor the DEB package identity");
      assert.equal(qualifiers.get("distro"), `${inventory.packageInventory.osRelease.ID}-${inventory.packageInventory.osRelease.VERSION_ID}`);
      assert.equal(qualifiers.get("epoch"), binaryParts.epoch ? String(binaryParts.epoch) : null);
      if (pkg.maintainer) assert.equal(component.supplier?.name, pkg.maintainer, "Observed Maintainer must remain available to native decoding");
      if (pkg.sourceEpochKnown !== false) assert.equal(props["aquasecurity:trivy:SrcEpoch"], String(versionParts(pkg.sourceVersion).epoch));
    }
    if (pkg.modularityLabel) assert.equal(decoded.Modularitylabel, pkg.modularityLabel, "Native modular namespace was lost");
    if (pkg.manager === "apk") {
      assert.equal(pkg.sourceName, pkg.apkOrigin);
      assert.equal(pkg.sourceVersion, pkg.version);
      assert.match(component.purl, /^pkg:apk\//);
    }
  }
  return { osResults, nativePackages };
}

export function controlInventory(control, name, version, options = {}) {
  // SOURCERPM has no source epoch. Debian source:Version is a full version,
  // including its independently observed epoch; do not apply the RPM rule.
  const sourceVersion = options.sourceVersion ?? (control.manager === "rpm" ? version.replace(/^\d+:/, "") : version);
  const arch = options.arch ?? control.arch;
  const inventory = {
    schemaVersion: 1, mode: "packages", profileId: "packages", inventoryHost: `acceptance-${control.id}-${name}`,
    hostname: `synthetic-${control.id}-${name}`, createdAt: new Date().toISOString(), partial: false,
    acceptanceFixture: { synthetic: true, installedPackage: false, cve: control.cve, references: control.references,
      kind: options.kind ?? "vendor-advisory-boundary", expectedCve: options.expectedCve ?? name === "control-vulnerable",
      interpretation: options.interpretation ?? control.basis },
    packageInventory: { manager: control.manager, packageCount: 1, error: "", partial: false, partialReasons: [],
      osRelease: { ID: control.id, VERSION_ID: control.versionId, ...(control.codename ? { VERSION_CODENAME: control.codename } : {}) } },
    packages: [{ name: control.manager === "dpkg" ? `${control.packageName}:${arch}` : control.packageName, version, arch, manager: control.manager, sourceName: control.sourceName,
      sourceVersion, sourceEpochKnown: control.manager !== "rpm", maintainer: control.maintainer || control.vendor }], findings: [],
  };
  if (control.manager === "apk") {
    Object.assign(inventory.packages[0], { apkOrigin: control.sourceName, apkCommit: "labelled-control-not-an-observed-aports-commit" });
    inventory.packageInventory.apkRepositories = { status: "observed", branches: [`v${control.versionId}`], unknownEntries: 0, scope: "configured-repositories; installed-origin-not-attested" };
  } else if (control.manager === "rpm") {
    Object.assign(inventory.packages[0], { vendor: control.vendor, sourceRpm: `${control.sourceName}-${sourceVersion}.src.rpm`,
      rpmModularityQueried: true, modularityLabel: "", rpmRepositoryEvidence: "not-recorded-in-rpmdb" });
  } else {
    assert.equal(control.manager, "dpkg", "Unknown package manager in labelled control");
    Object.assign(inventory.packages[0], { dpkgStatus: "ii ", origin: options.origin ?? "", maintainer: options.maintainer ?? control.maintainer });
  }
  if (name === "control-fixed-with-trust-record") {
    assert.equal(control.manager, "rpm");
    inventory.packages.push({ name: "gpg-pubkey", version: "01234567-89abcdef", arch: "None", manager: "rpm",
      sourceEpochKnown: false, rpmModularityQueried: true, rpmRepositoryEvidence: "labelled-synthetic-key-record" });
    inventory.packageInventory.packageCount = inventory.packages.length;
  }
  return inventory;
}

export function releaseMatchesControl(platform, control) {
  if (control.manager === "apk") return platform.versionId === control.versionId || platform.versionId.startsWith(control.versionId + ".");
  if (control.manager === "rpm") return platform.versionId.split(".")[0] === control.versionId;
  return platform.versionId === control.versionId;
}

export function labelledCases(control) {
  const make = (name, version, expectedCve, options = {}) => ({ name, expectedCve, applicabilityUnverified: false,
    ...options, input: controlInventory(control, name, version, { ...options, expectedCve }) });
  const cases = [make("control-vulnerable", control.vulnerableVersion, true), make("control-fixed", control.fixedVersion, false)];
  if (control.manager === "rpm") cases.push(make("control-fixed-with-trust-record", control.fixedVersion, false));
  if (control.manager !== "dpkg") return cases;
  const kind = "synthetic-metadata-interpretation";
  const multiarch = make("control-multiarch-vulnerable", control.vulnerableVersion, true, { kind,
    interpretation: "Two architecture-qualified records at the labelled source boundary; tests identity conservation, not a claim of two installed binaries" });
  multiarch.input.packages.push(controlInventory(control, "second-architecture", control.vulnerableVersion, { arch: "i386" }).packages[0]);
  multiarch.input.packageInventory.packageCount = multiarch.input.packages.length;
  cases.push(multiarch,
    make("control-vulnerable-binnmu", control.vulnerableVersion + "+b1", true, { kind, sourceVersion: control.vulnerableVersion,
      interpretation: "Synthetic binary-only rebuild suffix with unchanged source version, following Debian binNMU metadata conventions; no corresponding release is asserted" }),
    make("control-source-vulnerable-binary-fixed", control.fixedVersion, true, { kind, sourceVersion: control.vulnerableVersion,
      interpretation: "Synthetic divergent binary/source versions isolate source-advisory routing; not a published vendor release or an exploitability claim" }),
    make("control-source-fixed-binary-vulnerable", control.vulnerableVersion, false, { kind, sourceVersion: control.fixedVersion,
      interpretation: "Synthetic divergent binary/source versions isolate source-advisory routing; absence applies only to the named source-package CVE" }),
    make("control-source-epoch", "1:" + control.vulnerableVersion, false, { kind,
      interpretation: "Synthetic epoch 1 in both binary and source versions tests Debian version ordering and epoch preservation; no vendor epoch-1 release is asserted" }),
    make("control-unknown-supplier", control.vulnerableVersion, true, { kind, applicabilityUnverified: true, expectedProvenance: "unknown",
      maintainer: "Acceptance metadata <package@unknown.invalid>",
      interpretation: "The native vendor-feed observation must remain manual/partial when installed metadata does not establish applicability" }),
    make("control-third-party-supplier", control.vulnerableVersion, true, { kind, applicabilityUnverified: true, expectedProvenance: "third-party",
      origin: "Independent acceptance repository",
      interpretation: "An explicit third-party Origin must retain the native observation without claiming the distribution advisory applies to this package" }));
  return cases;
}

function evidenceFields(finding) {
  return Object.fromEntries((finding.evidence ?? "").split("; ").map((part) => { const at = part.indexOf("="); return [part.slice(0, at), part.slice(at + 1)]; }));
}

export function assertFindingConservation(osResults, report, normalized) {
  assert.deepEqual(normalized.raw, report, "Normalization must preserve the complete saved raw report");
  const fields = ["id", "title", "status", "risk", "evidence", "source", "description", "recommendation", "remediationAvailable"];
  const select = (finding) => Object.fromEntries(fields.map((field) => [field, finding[field]]));
  assert.deepEqual(normalized.findings.map(select), report.findings.map(select), "Normalization must preserve every finding, its evidence and applicability");
  const native = osResults.flatMap((entry) => entry.Vulnerabilities ?? []);
  const unique = new Map();
  for (const item of native) {
    const key = JSON.stringify([item.VulnerabilityID, item.PkgName, item.PkgID, item.PkgIdentifier, item.InstalledVersion]);
    const rawStatus = item.Status?.trim().toLowerCase().replaceAll("-", "_") || "affected";
    const status = ["not_affected", "fixed", "will_not_fix", "end_of_life", "fix_deferred", "affected"].includes(rawStatus) ? rawStatus : "unknown";
    const tuple = [item.VulnerabilityID, item.PkgName, item.PkgID ?? "", item.PkgIdentifier?.PURL ?? "", item.InstalledVersion ?? "",
      item.FixedVersion ?? "", item.Severity ?? "", status, item.DataSource?.ID ?? "", item.DataSource?.Name ?? "", item.PrimaryURL ?? ""];
    if (unique.has(key)) assert.deepEqual(unique.get(key), tuple, "Duplicate native identity must not conceal conflicting vendor evidence");
    unique.set(key, tuple);
  }
  const hcp = report.findings.filter((finding) => finding.source === "trivy" && /^trivy_.+_[a-f0-9]{24}$/.test(finding.id));
  const actual = hcp.map((finding) => {
    const props = evidenceFields(finding);
    const identifier = /^trivy_(.+)_[a-f0-9]{24}$/.exec(finding.id)[1];
    assert.equal(finding.title, `${identifier}: ${props.package}`, "A native vulnerability must retain its identifier and package name");
    return [identifier, props.package, props.package_id ?? "", props.purl ?? "", props.installed ?? "", props.fixed ?? "", props.severity ?? "",
      props.vendor_status, props.data_source ?? "", props.data_source_name ?? "", props.source ?? ""];
  });
  const canonical = (tuples) => tuples.map((tuple) => JSON.stringify(tuple)).sort();
  assert.deepEqual(canonical(actual), canonical([...unique.values()]), "Every distinct native vulnerability tuple must survive HCP conversion without architecture or source-evidence loss");
  return { nativeVulnerabilityRecords: native.length, uniqueNativeVulnerabilities: unique.size, hcpVulnerabilityFindings: hcp.length };
}

export async function main(args = process.argv.slice(2)) {
  const controlsOnly = args[0]?.startsWith("--controls-only=") ? args[0].slice("--controls-only=".length) : null;
  const output = args[1] ? path.resolve(args[1]) : null;
  const configuredBinary = process.env.HCP_TRIVY_BIN || "trivy";
  const binary = configuredBinary.includes(path.sep) ? path.resolve(configuredBinary) : configuredBinary;
  const runtime = mkdtempSync(path.join(tmpdir(), "hcp-linux-package-acceptance-"));
  const cache = path.resolve(process.env.HCP_TRIVY_CACHE_DIR || path.join(runtime, "trivy-cache"));
  const protocol = {
    startedAt: new Date().toISOString(), status: "running", expectedTrivyVersion: "0.74.0",
    scope: "Native inventory -> production SBOM -> real Trivy -> saved and normalized HCP report, plus independent vendor-labelled metadata controls",
    installedVulnerablePackages: false,
    controlsOnly: Boolean(controlsOnly), nativeInventoryEvaluated: false,
    limitations: [
      "The caller's VM/SSH harness establishes the provenance of the supplied native inventory; this helper cannot independently attest the remote machine",
      "CVE applicability remains partial for unknown/third-party package suppliers or incomplete native metadata, even when all records were processed",
      "Labelled version controls test one vendor advisory boundary; the RPM trust-record control tests an explicit non-software exclusion. They do not estimate overall false-positive or false-negative rates",
      "Debian-family source/binary divergence, binNMU suffix, source epoch, multiarch and supplier controls are synthetic metadata-interpretation cases, not claims that these combinations were released or installed",
      "Controls are synthetic metadata and are never installed. Absence is asserted for the named CVE only, not for all possible vulnerabilities",
      "Saved native JSON is a separate replay of the production-generated SBOM against the same unchanged real database",
    ],
    cases: [],
  };
  let compiled;
  let ownsOutput = false;

  function save(name, value) {
    writeFileSync(path.join(output, name), typeof value === "string" ? value : JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
  }


  try {
    assert.equal(args.length, 2, "Usage: node deployment/tests/verify_linux_packages.mjs <native-inventory.json|--controls-only=alpine|alma|rocky|debian|ubuntu> <output-directory>");
    assert.ok(!existsSync(path.join(output, "protocol.json")), "Choose a new output directory; a protocol already exists");
    mkdirSync(output, { recursive: true, mode: 0o700 });
    ownsOutput = true;
    let inventory;
    if (controlsOnly) {
      const selected = fixtures.controls[controlsOnly];
      assert.ok(selected, "Unknown controls-only family");
      inventory = controlInventory(selected, "source-label", selected.fixedVersion);
      protocol.limitations.push("Controls-only mode: no native host inventory or SSH collection was evaluated in this run");
    } else {
      const supplied = readFileSync(path.resolve(args[0]), "utf8");
      inventory = JSON.parse(supplied);
      assert.equal(inventory.schemaVersion, 1);
      assert.equal(inventory.mode, "packages");
      assert.equal(inventory.partial, false, "Native collection must finish without an inventory error");
      assert.equal(inventory.packageInventory?.partial, false);
      assert.equal(inventory.packageInventory?.error, "");
      assert.equal(inventory.packageInventory?.collectorVersion, 2, "Use the shipped native collector");
      assert.equal(inventory.packageInventory?.managerSelection, "os-id", "The native CI target must have an exact OS identity");
      assert.ok(inventory.packages?.length > 0);
      assert.equal(inventory.packageInventory.packageCount, inventory.packages.length);
      assert.ok(!inventory.acceptanceFixture, "The supplied native inventory must not be a labelled synthetic control");
      save("native.inventory.json", supplied);
      protocol.nativeInventorySha256 = createHash("sha256").update(supplied).digest("hex");
    }

    mkdirSync(path.join(runtime, "reports"));
    process.env.HCP_STATE_DIR = runtime;
    process.env.HCP_REPORTS_DIR = path.join(runtime, "reports");
    process.env.HCP_TRIVY_BIN = binary;
    process.env.HCP_TRIVY_CACHE_DIR = cache;
    process.env.HCP_TRIVY_MODE = "offline";
    process.env.HCP_TRIVY_MAX_DB_AGE_HOURS = "24";
    process.chdir(webDir);
    const { compileServerModules } = await import(pathToFileURL(path.join(webDir, "tests/_typescript-loader.mjs")).href);
    compiled = compileServerModules(["vulnerability-scan", "ansible-reports", "state-store", "linux-platform"]);
    const { scanPackageInventory, getTrivyDatabaseFreshness, refreshTrivyDatabase } = await import(compiled.url("vulnerability-scan"));
    const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
    const { setVulnerabilityDatabaseMode } = await import(compiled.url("state-store"));
    const { resolveLinuxPlatform } = await import(compiled.url("linux-platform"));
    const platform = resolveLinuxPlatform(inventory.packageInventory.osRelease, inventory.packageInventory.astraVersion);
    const control = fixtures.controls[platform.trivyFamily];
    assert.ok(control, "No labelled native acceptance control for this exact distribution; do not substitute a parent feed");
    assert.ok(releaseMatchesControl(platform, control), "No labelled native acceptance control for this release");
    assert.equal(platform.packageCveProvider, "trivy");
    assert.equal(inventory.packageInventory.manager, platform.packageManager);
    assert.ok(inventory.packages.every((pkg) => pkg.manager === platform.packageManager));
    protocol.platform = platform;
    protocol.control = control;
    protocol.sourceSha256 = Object.fromEntries(await Promise.all([
      "web/lib/vulnerability-scan.ts", "web/lib/linux-platform.ts", "web/lib/ansible-reports.ts", "ansible/scripts/hcp-package-inventory.py",
      "ansible/scripts/hcp-trivy-source.py", "deployment/tests/fixtures/linux-package-controls.json", "deployment/tests/verify_linux_packages.mjs",
    ].map(async (file) => [file, await sha256(path.join(repoRoot, file))])));
    const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("TRIVY_")));
    environment.TRIVY_CACHE_DIR = cache;
    const version = await run(binary, ["--version"], { env: environment, timeout: 30_000, maxBuffer: 1024 * 1024 });
    const actualVersion = /^Version:\s*(\S+)/m.exec(version.stdout)?.[1];
    assert.equal(actualVersion, protocol.expectedTrivyVersion, "Acceptance requires the pinned native Trivy version");
    protocol.trivyVersion = actualVersion;
    save("native-version.txt", version.stdout);
    if (getTrivyDatabaseFreshness().status !== "fresh") {
      setVulnerabilityDatabaseMode("online");
      await refreshTrivyDatabase();
    }
    setVulnerabilityDatabaseMode("offline");
    protocol.databaseFreshness = getTrivyDatabaseFreshness();
    assert.equal(protocol.databaseFreshness.status, "fresh", "A real database published within 24 hours is required");
    const databasePath = path.join(cache, "db/trivy.db");
    const metadataPath = path.join(cache, "db/metadata.json");
    const metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
    assert.equal(metadata.Version, 2);
    protocol.database = { sha256: await sha256(databasePath), bytes: statSync(databasePath).size, metadataSha256: await sha256(metadataPath), metadata };
    save("db-metadata.json", metadata);
    save("protocol.json", protocol);

    for (const testCase of [...(controlsOnly ? [] : [{ name: "native", input: inventory, expectedCve: null }]), ...labelledCases(control)]) {
      const { name, input, expectedCve } = testCase;
      const stored = { ...input, inventoryHost: input.inventoryHost || `acceptance-${control.id}-${name}` };
      const reportId = `acceptance-${control.id}-${name}-packages-run`;
      const hostAlias = stored.inventoryHost;
      writeFileSync(path.join(runtime, "reports", reportId + ".json"), JSON.stringify(stored), { flag: "wx", mode: 0o600 });
      if (name !== "native") save(name + ".inventory.json", input);
      const result = await scanPackageInventory({ hostAlias, reportId });
      save(name + ".hcp-report.json", result.report);
      const normalized = readAnsibleReport(result.reportId);
      save(name + ".normalized-report.json", normalized);
      assert.ok(normalized, "Production report normalization must read the saved result");
      assert.equal(result.report.scanner.available, true, "CVE scanner must complete; manual error output is not acceptance");
      assert.equal(normalized.partial, result.partial, "Normalization must preserve uncertainty");
      assert.equal(normalized.score, null, "A package CVE result must not invent a host security percentage");
      assert.equal(normalized.reportTimeValid, true);
      const scan = result.report.vulnerabilityScan;
      const sbomPath = path.join(runtime, "sbom", scan.sbomFile);
      const sbomContents = readFileSync(sbomPath, "utf8");
      save(name + ".cdx.json", sbomContents);
      const sbom = JSON.parse(sbomContents);
      const nativeArgs = ["sbom", "--config", path.join(runtime, "sbom", `${result.report.runId}.trivy-config.yaml`), "--format", "json", "--quiet",
        "--scanners", "vuln", "--pkg-types", "os", "--list-all-pkgs", "--disable-telemetry", "--ignorefile", "/dev/null", "--skip-db-update", "--skip-java-db-update", "--offline-scan", sbomPath];
      let replay;
      try {
        replay = await run(binary, nativeArgs, { env: environment, timeout: 300_000, maxBuffer: 64 * 1024 * 1024 });
      } catch (error) {
        save(name + ".trivy.stderr.txt", error.stderr ?? "");
        throw new Error(`Native Trivy replay failed (${error.code ?? error.signal ?? "unknown"}); see ${name}.trivy.stderr.txt`);
      }
      save(name + ".trivy.json", replay.stdout);
      save(name + ".trivy.stderr.txt", replay.stderr);
      const native = JSON.parse(replay.stdout);
      assert.equal(native.SchemaVersion, 2);
      assert.deepEqual([native.Metadata?.OS?.Family, native.Metadata?.OS?.Name], [platform.trivyFamily, input.packageInventory.osRelease.VERSION_ID]);
      const { osResults, nativePackages } = assertPackageConservation(input, sbom, native);
      const findingConservation = assertFindingConservation(osResults, result.report, normalized);
      // --list-all-pkgs retains RPM keyring records even though Trivy's detector
      // deliberately omits them from versioned-software CVE matching. Preserve
      // every native/SBOM record above and reconcile this explicit exclusion.
      const keys = input.packages.filter((pkg) => pkg.manager === "rpm" && pkg.name === "gpg-pubkey");
      const eligible = input.packages.length - keys.length;
      assert.deepEqual([scan.coverage.inventoryPackages, scan.coverage.decodedRecords, scan.coverage.eligiblePackages, scan.coverage.scannedPackages],
        [input.packages.length, input.packages.length, eligible, eligible]);
      assert.equal(scan.checkedPackages, eligible);
      assert.deepEqual(scan.coverage.excludedNonSoftware.map(({ name, version, manager, reason }) => ({ name, version, manager, reason })),
        keys.map(({ name, version, manager }) => ({ name, version, manager, reason: "rpm-public-key-record" })));
      assert.equal(scan.packageProvenance.excludedNonSoftwareRecords, keys.length);
      for (const key of scan.coverage.excludedNonSoftware) {
        const component = sbom.components.find((item) => item["bom-ref"] === key.purl);
        assert.ok(component, "Excluded trust record must remain in the SBOM");
        assert.ok(component.properties.some((item) => item.name === "hcp:record-kind" && item.value === "rpm-public-key-record"));
      }
      assert.equal(scan.databaseFreshness.status, "fresh");
      assert.equal(scan.sourceEvidence.status, "unchanged");
      assert.equal(scan.sourceEvidence.before.database.sha256, protocol.database.sha256);
      assert.equal(scan.sourceEvidence.before.metadata.sha256, protocol.database.metadataSha256);
      assert.equal(scan.sourceEvidence.before.sbom.sha256, createHash("sha256").update(sbomContents).digest("hex"));
      assert.deepEqual(scan.sourceEvidence.before, scan.sourceEvidence.after);
      assert.equal(scan.coverage.complete, !result.partial);
      if (result.partial) {
        assert.ok(scan.coverage.reasons.length > 0, "Partial coverage must explain its actual gap");
        assert.ok(!result.report.findings.some((f) => f.id === "trivy_no_known_vulnerabilities"), "Partial coverage cannot issue an empty PASS");
      }
      const nativeMatches = osResults.flatMap((entry) => entry.Vulnerabilities ?? []).filter((entry) => entry.VulnerabilityID === control.cve);
      const hcpMatches = result.report.findings.filter((f) => f.id.startsWith(`trivy_${control.cve}_`));
      if (expectedCve !== null) {
        assert.equal(result.partial, Boolean(testCase.applicabilityUnverified), `The metadata control must preserve applicability uncertainty: ${JSON.stringify(scan.coverage)}`);
        assert.equal(nativeMatches.length > 0, expectedCve, "Real vendor advisory matching disagrees with the labelled version");
        assert.equal(hcpMatches.length > 0, expectedCve, "HCP must preserve the real engine observation");
        if (expectedCve) {
          assert.equal(nativeMatches.length, input.packages.length);
          assert.equal(hcpMatches.length, input.packages.length);
          const expectedRefs = new Set(sbom.components.map((component) => component.purl));
          for (const match of nativeMatches) {
            assert.equal(match.DataSource?.ID, control.dataSourceId);
            assert.equal(match.FixedVersion, control.fixedVersion);
            assert.ok(expectedRefs.delete(match.PkgIdentifier?.PURL), "Each architecture-qualified package must retain a separate target CVE observation");
            const pkg = input.packages[sbom.components.findIndex((component) => component.purl === match.PkgIdentifier?.PURL)];
            assert.equal(match.InstalledVersion, pkg.version, "Native evidence must preserve binary version separately from source advisory matching");
            assert.equal(match.Status, "fixed", "Vendor fixed describes an available patch for the affected source version");
          }
          assert.equal(expectedRefs.size, 0);
          for (const finding of hcpMatches) {
            assert.equal(finding.status, testCase.applicabilityUnverified ? "manual" : "failed", "Unknown/third-party applicability cannot become a confirmed CVE");
            if (testCase.expectedProvenance) {
              const fields = evidenceFields(finding);
              assert.equal(fields.package_provenance, testCase.expectedProvenance);
              assert.equal(fields.applicability, "unverified");
            }
          }
        }
      }
      protocol.cases.push({ name, syntheticInventory: expectedCve !== null, expectedCve, inputPackages: input.packages.length,
        fixtureKind: input.acceptanceFixture?.kind ?? null, interpretation: input.acceptanceFixture?.interpretation ?? null,
        applicabilityUnverified: Boolean(testCase.applicabilityUnverified), findingConservation,
        nativePackages: nativePackages.length, coverage: scan.coverage, provenance: scan.packageProvenance,
        targetCve: control.cve, nativeMatches, hcpMatches, normalizedFindings: normalized.findings.length,
        sbomSha256: createHash("sha256").update(sbomContents).digest("hex"), nativeSha256: createHash("sha256").update(replay.stdout).digest("hex") });
      if (name === "native") protocol.nativeInventoryEvaluated = true;
      save("protocol.json", protocol);
      console.log(`PASS ${platform.trivyFamily} ${name}: ${input.packages.length} package records preserved; coverage ${scan.coverage.complete ? "complete" : "partial with explicit reasons"}`);
    }
    protocol.databaseUnchanged = protocol.database.sha256 === await sha256(databasePath) && protocol.database.metadataSha256 === await sha256(metadataPath);
    assert.equal(protocol.databaseUnchanged, true, "Native inventory and every control must use one unchanged database snapshot");
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

}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
