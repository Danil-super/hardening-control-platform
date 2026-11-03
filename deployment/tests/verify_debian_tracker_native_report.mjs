#!/usr/bin/env node
/**
 * After a genuine Debian 12 KVM guest has been destroyed, evaluate its
 * independently checked native source-package versions against a REAL Debian
 * Security Tracker download. Separately replay a clearly SYNTHETIC labelled
 * vulnerable-version metadata control through production Trivy and final
 * project JSON/PDF. No vulnerable version is installed on the guest.
 * No target SSH, modifying playbooks, arbitrary URLs or test scanner mocks.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compileServerModules } from "../../web/tests/_typescript-loader.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CVE = "CVE-2024-6119";
const SOURCE = "openssl";
const CONTROL_VERSION = "3.0.14-1~deb12u1";
const SHA = /^[a-f0-9]{64}$/;
const PV = /^[A-Za-z0-9.+~:-]{1,256}$/;
let diagnosticStage = "arguments";
const sha256 = value => createHash("sha256").update(value).digest("hex");

function readJson(file) {
  const st = lstatSync(file);
  assert.ok(st.isFile() && !st.isSymbolicLink() && st.size > 2 && st.size <= 32 * 1024 * 1024);
  return JSON.parse(readFileSync(file, "utf8"));
}

export function checkNativeSources(native, vm) {
  assert.equal(native?.mode, "packages");
  assert.deepEqual([native.packageInventory?.osRelease?.ID, native.packageInventory?.osRelease?.VERSION_ID,
    native.packageInventory?.osRelease?.VERSION_CODENAME, native.packageInventory?.manager],
  ["debian", "12", "bookworm", "dpkg"]);
  assert.equal(native.packageInventory.partial, false);
  assert.equal(native.packageInventory.packageCount, native.packages.length);
  assert.equal(vm?.status, "passed");
  assert.equal(vm?.distribution, "debian");
  assert.equal(vm?.acceleration, "kvm");
  assert.equal(vm?.syntheticOsIdentity, false);
  assert.equal(vm?.publicationPrivacyVerified, true);
  assert.equal(vm?.checks?.find(x => x.name === "Production dpkg collector equals all eight independent native fields")
    ?.detail?.allEightNativeFieldsEqual, true);
  const apt = native.packageInventory?.aptRepositories;
  const aptProof = vm.checks?.find(x =>
    x.name === "Debian APT index metadata SHA equals independent native apt-cache policy")?.detail;
  assert.equal(apt?.schemaVersion, 1);
  assert.equal(apt?.status, "observed");
  assert.ok(apt.indexEntries > 0);
  assert.match(apt.policySha256, SHA);
  assert.equal(apt.releaseCodename, "bookworm");
  assert.equal(apt.policySha256, aptProof?.sha256,
    "APT release hints must match an independently observed native apt-cache policy");
  assert.equal(apt.publisherAuthenticated, false);
  assert.equal(apt.repositorySignatureVerified, false);
  assert.equal(apt.installedPackageOriginVerified, false);
  assert.equal(aptProof?.repositorySignatureVerified, false);
  assert.equal(aptProof?.installedPackageOriginVerified, false);
  const signed = native.packageInventory?.debianSignedReleases;
  const signedProof = vm.checks?.find(x =>
    x.name === "Cached Debian InRelease signatures verified by native gpgv with local keyring only")?.detail;
  assert.equal(signed?.status, "verified_with_local_keyring");
  assert.equal(signed?.localSignatureVerified, true);
  assert.ok(signed?.candidateFiles > 0 && signed.candidateFiles === signed.validLocalSignatures);
  assert.match(signed.localKeyringSha256, SHA);
  assert.equal(signed.localKeyringSha256, signedProof?.localKeyringSha256);
  assert.deepEqual(signed.inReleaseSha256, signedProof?.inReleaseSha256);
  for (const key of ["publisherAuthenticated", "publisherFreshnessVerified", "packageIndexHashesVerified",
    "installedPackageOriginVerified", "remediationAuthorized"]) assert.equal(signed[key], false);
  const indexes = native.packageInventory?.debianPackageIndexes;
  const indexProof = vm.checks?.find(x =>
    x.name === "Native Debian cached Packages SHA256 matches locally signed InRelease records")?.detail;
  assert.equal(indexes?.schemaVersion, 1);
  assert.equal(indexes?.status, "locally_hash_matched");
  assert.equal(indexes?.verifiedAgainstLocallySignedRelease, true);
  assert.ok(indexes?.candidateIndexes > 0 && indexes.candidateIndexes === indexes.matchedIndexes);
  assert.equal(indexes.missingSignedHashes, 0);
  assert.equal(indexes.mismatchedIndexes, 0);
  assert.equal(indexes.matchedIndexes, indexes.indexRecords?.length);
  assert.equal(indexes.matchedIndexes, indexProof?.matchedIndexes);
  assert.deepEqual(indexes.indexRecords, indexProof?.verifiedIndexes);
  for (const item of indexes.indexRecords) {
    assert.match(item.packagesSha256, SHA);
    assert.ok(signed.inReleaseSha256.includes(item.releaseSha256));
  }
  for (const key of ["publisherAuthenticated", "keyringIndependentlyAuthenticated",
    "publisherFreshnessVerified", "installedPackageOriginVerified", "remediationAuthorized"])
    assert.equal(indexes[key], false);
  const found = native.packages.filter(pkg => pkg.manager === "dpkg" && pkg.sourceName === SOURCE);
  assert.ok(found.length > 0);
  const versions = [...new Set(found.map(x => x.sourceVersion))];
  assert.ok(versions.length > 0 && versions.length <= 8);
  for (const pkg of found) {
    assert.match(pkg.sourceVersion, PV);
    assert.equal(pkg.sourceEpochKnown, true);
    assert.match(pkg.dpkgStatus, /^[uihrp]i $/);
    assert.ok(typeof pkg.maintainer === "string" && pkg.maintainer.length);
    assert.equal(typeof pkg.origin, "string");
  }
  return { versions, recordCount: found.length,
    aptIndexEntries: apt.indexEntries, aptPolicySha256: apt.policySha256,
    locallyVerifiedSignatures: signed.validLocalSignatures, localKeyringSha256: signed.localKeyringSha256,
    verifiedLocalPackageIndexes: indexes.matchedIndexes,
    publisherSignedPackageProvenanceVerified: false };
}

export function checkSyntheticControl(control, matching) {
  assert.equal(matching?.status, "passed");
  assert.equal(matching?.nativeInventoryEvaluated, true);
  assert.equal(matching?.controlsOnly, false);
  assert.equal(control?.inventoryHost, "acceptance-debian-control-vulnerable");
  assert.equal(control?.packageInventory?.osRelease?.ID, "debian");
  assert.equal(control?.packageInventory?.osRelease?.VERSION_CODENAME, "bookworm");
  assert.equal(control?.acceptanceFixture?.synthetic, true);
  assert.equal(control?.acceptanceFixture?.installedPackage, false);
  assert.equal(control?.acceptanceFixture?.cve, CVE);
  assert.equal(control?.acceptanceFixture?.expectedCve, true);
  assert.deepEqual(control.packages.map(pkg => [pkg.sourceName, pkg.sourceVersion]),
    [[SOURCE, CONTROL_VERSION]]);
  const original = matching.cases?.find(c => c.name === "control-vulnerable");
  assert.ok(original?.nativeMatches?.length > 0 && original?.hcpMatches?.length > 0);
  return original.nativeMatches.length;
}

function decodedPdf(pdf) {
  const python = [
    "import base64,re,sys,zlib",
    "pdf=sys.stdin.buffer.read()",
    "chunks=[]",
    "for raw in re.findall(rb'stream\\r?\\n(.*?)endstream',pdf,re.S):",
    "    try:",
    "        raw=raw.strip()",
    "        if raw.endswith(b'~>'): raw=base64.a85decode(raw,adobe=True)",
    "        chunks.append(zlib.decompress(raw))",
    "    except (ValueError,zlib.error): pass",
    "sys.stdout.buffer.write(b'\\n'.join(chunks))",
  ].join("\n");
  return execFileSync("/usr/bin/python3", ["-c", python],
    { input: pdf, timeout: 30_000, maxBuffer: 8 * 1024 * 1024 }).toString("latin1");
}

export async function accept(nativePath, matchingDir, vmProtocolPath, outDir) {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  const base = path.resolve(process.env.RUNNER_TEMP ?? "");
  assert.ok(base !== path.parse(base).root);
  for (const file of [nativePath, path.join(matchingDir, "protocol.json"),
    path.join(matchingDir, "control-vulnerable.inventory.json"), vmProtocolPath, outDir]) {
    assert.ok(path.resolve(file).startsWith(base + path.sep));
  }
  diagnosticStage = "native-inputs";
  const native = readJson(nativePath);
  const matching = readJson(path.join(matchingDir, "protocol.json"));
  const control = readJson(path.join(matchingDir, "control-vulnerable.inventory.json"));
  const vm = readJson(vmProtocolPath);
  diagnosticStage = "guest-provenance-contract";
  const real = checkNativeSources(native, vm);
  diagnosticStage = "synthetic-control-contract";
  const nativeFixtureCount = checkSyntheticControl(control, matching);

  const root = mkdtempSync(path.join(tmpdir(), "hcp-debian-real-vm-final-"));
  const stateRoot = path.join(root, "state");
  const reports = path.join(root, "reports");
  mkdirSync(stateRoot, { mode: 0o700 });
  mkdirSync(reports, { mode: 0o700 });
  const cwd = process.cwd();
  const envNames = ["HCP_STATE_DIR", "HCP_REPORTS_DIR", "HCP_TRIVY_MODE",
    "HCP_TRIVY_MAX_DB_AGE_HOURS", "HCP_DEBIAN_TRACKER_PREVIEW_SHA256"];
  const oldEnv = Object.fromEntries(envNames.map(k => [k, process.env[k]]));
  let compiled;
  try {
    process.env.HCP_STATE_DIR = stateRoot;
    process.env.HCP_REPORTS_DIR = reports;
    process.env.HCP_TRIVY_MODE = "offline";
    process.env.HCP_TRIVY_MAX_DB_AGE_HOURS = "24";
    delete process.env.HCP_DEBIAN_TRACKER_PREVIEW_SHA256;
    assert.ok(process.env.HCP_TRIVY_BIN && existsSync(process.env.HCP_TRIVY_BIN));
    assert.ok(process.env.HCP_TRIVY_CACHE_DIR && existsSync(process.env.HCP_TRIVY_CACHE_DIR));
    process.chdir(path.join(ROOT, "web"));
    compiled = compileServerModules(["debian-tracker-snapshot", "state-store", "vulnerability-scan",
      "ansible-reports", "project-report", "debian-tracker-export"]);
    const vendor = await import(compiled.url("debian-tracker-snapshot"));
    const store = await import(compiled.url("state-store"));
    const scanner = await import(compiled.url("vulnerability-scan"));
    const ansible = await import(compiled.url("ansible-reports"));
    const finalReport = await import(compiled.url("project-report"));
    const exportTools = await import(compiled.url("debian-tracker-export"));

    // One real fixed-origin GET; the snapshot is private and never uploaded.
    diagnosticStage = "official-debian-full-feed-import";
    const manifest = await vendor.importDebianTrackerFullSnapshot({ stateRoot });
    assert.equal(manifest.sourceUrl, vendor.DEBIAN_TRACKER_URL);
    assert.match(manifest.sha256, SHA);
    assert.ok(manifest.sourcePackageCount > 1000 && manifest.issueCount > manifest.sourcePackageCount);
    assert.equal(manifest.publisherAuthenticated, false);
    store.recordDebianTrackerImportedSnapshot(manifest.sha256, false);
    store.selectDebianTrackerSnapshot(manifest.sha256, null);
    assert.equal(store.getDebianTrackerSelection().sha256, manifest.sha256);

    // Actual VM-installed openssl, never a fabricated vulnerable CVE finding.
    diagnosticStage = "real-guest-openssl-source-comparison";
    const actual = real.versions.map(sourceVersion =>
      vendor.evaluatePinnedDebianTrackerFullSnapshot({
        stateRoot, snapshotSha256: manifest.sha256, osId: "debian",
        release: "bookworm", cveId: CVE, sourcePackage: SOURCE,
        sourceVersion, inventoryComplete: true,
      }));
    for (const row of actual) {
      assert.equal(row.status, "provisional");
      assert.ok(["affected", "fixed_or_not_affected"].includes(row.candidateVerdict));
      assert.equal(row.fullSnapshotSha256, manifest.sha256);
      assert.match(row.derivedExcerptSha256, SHA);
      assert.equal(row.trustedVerdict, "unknown");
      assert.equal(row.publisherAuthenticated, false);
      assert.equal(row.publisherFreshnessVerified, false);
      assert.equal(row.remediationAuthorized, false);
    }

    // Preserve actual VM inventory's Release→Packages proof through the
    // independent native-final project path; never mix this real host report
    // with the labelled synthetic vulnerable-version host.
    diagnosticStage = "real-vm-index-final-project-json-pdf";
    assert.equal(native.inventoryHost, "hcp-deb-ci");
    const realInventoryReportId = "hcp-deb-ci-packages-signed-index-native-run";
    writeFileSync(path.join(reports, realInventoryReportId + ".json"), JSON.stringify(native),
      { flag: "wx", mode: 0o600 });
    const realInventoryNormalized = ansible.readAnsibleReport(realInventoryReportId);
    assert.ok(realInventoryNormalized && realInventoryNormalized.reportTimeValid);
    const actualFinalReport = await finalReport.createProjectReport({
      hostAlias: native.inventoryHost,
      subject: { clientName: "HCP CI native guest", projectName: "Actual Debian Packages proof",
        period: "Debian KVM acceptance", specialist: "HCP CI" },
    });
    const nativeFinalJson = readJson(path.join(stateRoot, "project-reports",
      actualFinalReport.fileName.replace(/\.pdf$/, ".json")));
    assert.equal(nativeFinalJson.debianPackageIndexEvidence.length, 1);
    assert.match(nativeFinalJson.debianPackageIndexEvidenceSha256, SHA);
    const sourceIndexEvidence = nativeFinalJson.debianPackageIndexEvidence[0];
    assert.equal(sourceIndexEvidence.sourceReportId, realInventoryReportId);
    assert.equal(sourceIndexEvidence.sourceReportSha256, ansible.hashAnsibleReport(realInventoryReportId));
    assert.equal(sourceIndexEvidence.status, "locally_hash_matched");
    assert.equal(sourceIndexEvidence.matchedIndexes, indexes.matchedIndexes);
    assert.equal(sourceIndexEvidence.verifiedAgainstLocallySignedRelease, true);
    assert.deepEqual(sourceIndexEvidence.indexRecords, indexes.indexRecords);
    assert.equal(sourceIndexEvidence.publisherAuthenticated, false);
    assert.equal(sourceIndexEvidence.installedPackageOriginVerified, false);
    assert.equal(sourceIndexEvidence.remediationAuthorized, false);
    const realPdf = finalReport.readProjectReportPdf(actualFinalReport.id)?.pdf;
    assert.ok(realPdf && sha256(realPdf) === actualFinalReport.pdfSha256);
    const nativeRendered = decodedPdf(realPdf);
    for (const item of sourceIndexEvidence.indexRecords) {
      assert.ok(nativeRendered.includes(item.releaseSha256),
        "Real Debian InRelease SHA-256 was lost from the final PDF");
      assert.ok(nativeRendered.includes(item.packagesSha256),
        "Real decoded Packages SHA-256 was lost from the final PDF");
    }
    assert.ok(nativeRendered.includes(nativeFinalJson.debianPackageIndexEvidenceSha256));
    assert.ok(nativeRendered.includes(sourceIndexEvidence.sourceReportSha256));

    // Native, unmodified Trivy binary scans a LABELLED SYNTHETIC metadata
    // fixture. It runs offline on the already-verified real Trivy DB.
    diagnosticStage = "production-trivy-control-scan";
    store.setVulnerabilityDatabaseMode("offline");
    const reportId = "acceptance-debian-control-vulnerable-packages-run";
    writeFileSync(path.join(reports, reportId + ".json"), JSON.stringify(control),
      { flag: "wx", mode: 0o600 });
    const result = await scanner.scanPackageInventory({
      hostAlias: control.inventoryHost, reportId,
    });
    const cv = result.report.vulnerabilityScan;
    diagnosticStage = "production-trivy-result-coverage";
    assert.equal(result.partial, false);
    assert.equal(cv.provider, "Trivy");
    assert.equal(cv.providerMode, "offline");
    assert.equal(cv.coverage.complete, true);
    assert.equal(cv.debianTrackerPreview.state, "enabled");
    assert.equal(cv.debianTrackerPreview.snapshotSha256, manifest.sha256);
    assert.equal(result.report.summary.score, null);
    // One vulnerable source package may have many Trivy CVEs. Every eligible
    // record, including beyond the labelled control, must survive to PDF.
    diagnosticStage = "production-trivy-preview-completeness";
    const allAnnotated = result.report.findings.filter(x => x.debianTrackerPreview !== undefined);
    const hits = result.report.findings.filter(x => x.cveApplicability?.advisory.id === CVE);
    assert.ok(hits.length >= 1);
    assert.ok(allAnnotated.length >= hits.length);
    assert.equal(cv.debianTrackerPreview.annotatedFindings, allAnnotated.length);
    diagnosticStage = "production-trivy-named-cve-control";
    for (const finding of hits) {
      assert.equal(finding.source, "trivy");
      assert.equal(finding.status, "failed");
      assert.equal(finding.remediationAvailable, false);
      assert.equal(finding.cveApplicability.package.sourceName, SOURCE);
      assert.equal(finding.cveApplicability.package.sourceVersion, CONTROL_VERSION);
      const preview = finding.debianTrackerPreview;
      assert.equal(preview.status, "provisional");
      assert.equal(preview.candidateVerdict, "affected");
      assert.equal(preview.fullSnapshotSha256, manifest.sha256);
      assert.match(preview.derivedExcerptSha256, SHA);
      assert.equal(preview.publisherAuthenticated, false);
      assert.equal(preview.publisherFreshnessVerified, false);
      assert.equal(preview.remediationAuthorized, false);
      assert.equal(preview.trustedVerdict, "unknown");
    }
    diagnosticStage = "native-trivy-report-normalization";
    const normalized = ansible.readAnsibleReport(result.reportId);
    assert.ok(normalized && normalized.reportTimeValid);
    assert.equal(normalized.findings.length, result.report.findings.length);
    assert.deepEqual(normalized.raw, result.report);

    diagnosticStage = "project-pdf-render-and-export";
    const final = await finalReport.createProjectReport({
      hostAlias: control.inventoryHost,
      subject: { clientName: "HCP controlled CI", projectName: "Debian evidence acceptance",
        period: "Native Debian VM", specialist: "HCP CI" },
    });
    diagnosticStage = "project-final-json-evidence";
    const finalJson = readJson(path.join(stateRoot, "project-reports",
      final.fileName.replace(/\.pdf$/, ".json")));
    assert.equal(finalJson.debianTrackerEvidence.length, allAnnotated.length);
    assert.match(finalJson.debianTrackerEvidenceSha256, SHA);
    assert.ok(finalJson.sourceManifest.some(x => x.id === result.reportId));
    const originalDigest = ansible.hashAnsibleReport(result.reportId);
    exportTools.assertDebianTrackerEvidenceMultiset([{
      reportId: result.reportId, reportSha256: originalDigest, findings: result.report.findings,
    }], finalJson.debianTrackerEvidence);
    diagnosticStage = "project-exact-cve-tuples";
    for (const tuple of finalJson.debianTrackerEvidence) {
      const raw = allAnnotated.find(x => x.id === tuple.findingId);
      assert.ok(raw);
      assert.equal(tuple.sourceReportSha256, originalDigest);
      assert.equal(tuple.fullSnapshotSha256, manifest.sha256);
      assert.equal(tuple.derivedExcerptSha256, raw.debianTrackerPreview.derivedExcerptSha256);
      assert.equal(tuple.candidateVerdict, raw.debianTrackerPreview.candidateVerdict);
      assert.equal(tuple.publisherAuthenticated, false);
      assert.equal(tuple.remediationAuthorized, false);
      assert.equal(tuple.trustedVerdict, "unknown");
    }
    diagnosticStage = "pdf-content-and-hash-verification";
    const pdf = finalReport.readProjectReportPdf(final.id)?.pdf;
    assert.ok(pdf && pdf.subarray(0, 5).toString("ascii") === "%PDF-");
    assert.equal(sha256(pdf), final.pdfSha256);
    const text = decodedPdf(pdf);
    for (const tuple of finalJson.debianTrackerEvidence) {
      assert.ok(text.includes(tuple.findingId));
      assert.ok(text.includes(tuple.fullSnapshotSha256));
      assert.ok(text.includes(tuple.derivedExcerptSha256));
    }
    assert.ok(text.includes(finalJson.debianTrackerEvidenceSha256));
    assert.equal(store.verifyAuditChain().valid, true);

    const proof = {
      schemaVersion: 1, status: "passed", sourceCommit: process.env.GITHUB_SHA ?? null,
      nativeGuest: { distribution: "debian", version: "12", release: "bookworm",
        independentDpkgEightFieldEquality: true, observedSourceRecords: real.recordCount,
        aptIndexEntries: real.aptIndexEntries, independentlyMatchedAptPolicySha256: real.aptPolicySha256,
        locallyVerifiedInReleaseSignatures: real.locallyVerifiedSignatures,
        verifiedLocalPackageIndexes: real.verifiedLocalPackageIndexes,
        nativeIndexFinalJsonAndPdfVerified: true,
        nativeIndexProjectionSha256: nativeFinalJson.debianPackageIndexEvidenceSha256,
        localKeyringSha256: real.localKeyringSha256,
        observedSourceVersions: real.versions.length,
        candidateVerdicts: actual.map(x => x.candidateVerdict),
        packagePublisherSignatureVerified: false },
      feed: { sha256: manifest.sha256, bytes: manifest.bytes,
        packages: manifest.sourcePackageCount, issues: manifest.issueCount,
        publisherAuthenticated: false, publisherFreshnessVerified: false },
      syntheticTrivyControl: { installedOnGuest: false, cveId: CVE, sourceName: SOURCE,
        vulnerableSourceVersion: CONTROL_VERSION, nativeTrivyFindingCount: nativeFixtureCount,
        originalFindingCount: hits.length, allAnnotatedFindings: allAnnotated.length,
        candidateVerdict: "affected",
        trustedVerdict: "unknown", remediationAuthorized: false },
      projectReport: { originalReportSha256: originalDigest,
        sourceReportId: result.reportId, evidenceCount: finalJson.debianTrackerEvidence.length,
        exactMultisetVerified: true, projectionSha256: finalJson.debianTrackerEvidenceSha256,
        pdfSha256: final.pdfSha256, allPdfTuplesAndHashesVerified: true },
      limitations: [
        "Real installed Debian versions evaluated separately, not assigned synthetic CVE findings",
        "Vulnerable-version labelled control uses REAL production Trivy but is never installed on the VM",
        "dpkg Maintainer/Origin metadata does not authenticate package signatures or Debian advisory publisher",
        "One Debian release and named CVE cannot prove complete CVE coverage",
      ],
    };
    diagnosticStage = "privacy-limited-public-protocol";
    mkdirSync(outDir, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(outDir, "protocol.json"), JSON.stringify(proof, null, 2) + "\n",
      { flag: "wx", mode: 0o600 });
    return proof;
  } finally {
    process.chdir(cwd);
    for (const [key, val] of Object.entries(oldEnv)) {
      if (val === undefined) delete process.env[key]; else process.env[key] = val;
    }
    if (compiled) rmSync(compiled.directory, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert.equal(process.argv.length, 6);
    await accept(...process.argv.slice(2));
    console.log("PASS native Debian source + real Tracker + real Trivy + final JSON/PDF");
  } catch (error) {
    // Diagnostics contain only a fixed stage name and an assertion/runtime
    // class, never raw guest inventory, package names, paths or advisory bytes.
    const kind = error instanceof Error ? error.name.replace(/[^A-Za-z]/g, "").slice(0, 40) : "Unknown";
    // Print only primitive synthetic-assertion values. No paths, objects,
    // guest machine identity, credentials or raw vendor record data.
    const primitive = value => {
      if (typeof value === "number" || typeof value === "boolean") return String(value);
      if (typeof value === "string" && /^[a-zA-Z0-9_.:+~-]{1,80}$/.test(value)) return value;
      return "redacted";
    };
    const values = kind === "AssertionError" ? ";actual=" + primitive(error.actual) +
      ";expected=" + primitive(error.expected) : "";
    console.error("FAIL Debian CVE end-to-end native acceptance; stage=" + diagnosticStage +
      ";kind=" + kind + values);
    process.exitCode = 1;
  }
}
