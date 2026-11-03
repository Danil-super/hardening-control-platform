import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["project-report", "state-store", "astra-oval-config", "ansible-reports", "audit-correlation", "host-credentials", "ssh-access"]);
const state = mkdtempSync(path.join(tmpdir(), "hcp-project-report-state-"));
const reports = mkdtempSync(path.join(tmpdir(), "hcp-project-report-reports-"));
process.env.HCP_STATE_DIR = state;
process.env.HCP_REPORTS_DIR = reports;
const projectReports = await import(compiled.url("project-report"));
const store = await import(compiled.url("state-store"));
after(() => { delete process.env.HCP_STATE_DIR; delete process.env.HCP_REPORTS_DIR; rmSync(compiled.directory, { recursive: true, force: true }); rmSync(state, { recursive: true, force: true }); rmSync(reports, { recursive: true, force: true }); });

test("final PDF stores a bounded snapshot and an HMAC-audited manifest", async () => {
  const createdAt = new Date().toISOString();
  writeFileSync(path.join(reports, "astra-1-basic_linux-run.json"), JSON.stringify({ inventoryHost: "astra-1", createdAt, mode: "agentless", profileId: "basic_linux", summary: { score: 72, high: 0, medium: 0, low: 0, info: 0 }, findings: [], events: [] }));
  const record = await projectReports.createProjectReport({ hostAlias: "astra-1", subject: { clientName: "ООО Тест", projectName: "Харденинг", period: "01.10.2026", specialist: "Специалист HCP" } });
  assert.match(record.id, /^project_report_/);
  assert.match(record.pdfSha256, /^[a-f0-9]{64}$/);
  assert.equal(projectReports.listProjectReports("astra-1").length, 1);
  assert.deepEqual(projectReports.listProjectReportSourceReferences("astra-1-basic_linux-run", "astra-1"), [{
    id: record.id, hostAlias: "astra-1", snapshotReadable: true,
  }]);
  const result = projectReports.readProjectReportPdf(record.id);
  assert.ok(result);
  assert.equal(result.pdf.subarray(0, 5).toString("ascii"), "%PDF-");
  assert.equal(store.verifyAuditChain().valid, true);
  store.setRecordArchive([{kind:"pdf",id:record.id},{kind:"report",id:"astra-1-basic_linux-run"}],"archive");
  assert.equal(projectReports.listProjectReports("astra-1").length,0);
  assert.equal(projectReports.listProjectReportSourceReferences("astra-1-basic_linux-run","astra-1")[0].id,record.id);
  assert.equal(projectReports.readProjectReportPdf(record.id).record.pdfSha256,record.pdfSha256);
});

test("a 4,000-observation audit exports beyond 1 MB and retains unknown severity and final row", async () => {
  const findings = Array.from({ length: 4000 }, (_, index) => ({
    id: `oval:fixture:def:${index}`, profileId: "astra-oval", title: `CVE-2026-${String(10000 + index)}: package-${index}`,
    category: "CVE", risk: "info", severityUnknown: true, status: "failed", source: "openscap",
    description: "An observation without vendor severity", recommendation: "Проверьте бюллетень производителя. После обновления повторите аудит.",
    evidence: JSON.stringify({ vendorSeverity: null }), remediationAvailable: false,
  }));
  writeFileSync(path.join(reports, "large-astra-oval-run.json"), JSON.stringify({ inventoryHost: "large", createdAt: new Date().toISOString(), mode: "astra-oval", profileId: "astra-oval", findings, events: [] }));
  const record = await projectReports.createProjectReport({ hostAlias: "large", subject: { clientName: "ООО Тест", projectName: "Все CVE", period: "10.10.2026", specialist: "HCP" } });
  const snapshot = readFileSync(path.join(state, "project-reports", record.fileName.replace(/\.pdf$/, ".json")), "utf8");
  assert.ok(Buffer.byteLength(snapshot) > 1024 * 1024);
  const parsed = JSON.parse(snapshot);
  assert.equal(parsed.unplannedFindings.length, 4000);
  assert.ok(parsed.unplannedFindings.every((finding) => finding.severityUnknown === true));
  assert.ok(parsed.unplannedFindings.some((finding) => finding.title.includes("CVE-2026-13999")));
  const pdf = projectReports.readProjectReportPdf(record.id).pdf;
  assert.ok(pdf.byteLength > 10_000);
  // Read the actual compressed page streams using Python's standard library.
  // Checking only the snapshot would miss a renderer silently keeping 80 rows.
  const contents = execFileSync("/usr/bin/python3", ["-c", `
import base64,json,re,sys,zlib
pdf=sys.stdin.buffer.read()
streams=[]
for raw in re.findall(rb'stream\\r?\\n(.*?)endstream',pdf,re.S):
    try:
        raw=raw.strip()
        if raw.endswith(b'~>'): raw=base64.a85decode(raw,adobe=True)
        streams.append(zlib.decompress(raw))
    except (ValueError,zlib.error): pass
text=b'\\n'.join(streams)
print(json.dumps({'count':len(re.findall(rb'CVE-2026-\\d{5}',text)),'last':b'CVE-2026-13999' in text}))
`], { input: pdf, encoding: "utf8" });
  assert.deepEqual(JSON.parse(contents), { count: 4000, last: true });
  assert.equal(store.verifyAuditChain().valid, true);
});


test("final project snapshot and actual PDF retain Trivy and provisional Ubuntu OSV evidence", async () => {
  const id = "osv-host-vulnerabilities-run";
  const cve = "CVE-2024-6119";
  const findingId = "trivy_CVE-2024-6119_abcdef";
  const digest = "c".repeat(64);
  const revision = "d".repeat(40);
  const rawFinding = {
    id: findingId, profileId: "cve_packages", title: cve + ": libssl3t64",
    description: "Potential vulnerable OpenSSL binary", recommendation: "Verify the vendor advisory",
    category: "CVE пакеты", risk: "high", status: "failed", source: "trivy", remediationAvailable: false,
    cveApplicability: {
      schemaVersion: 1, verdict: "affected", confidence: "metadata-consistent",
      advisory: { id: cve },
      package: { name: "libssl3t64", installedVersion: "3.0.13-0ubuntu3", sourceName: "openssl", sourceVersion: "3.0.13-0ubuntu3" },
    },
    ubuntuOsvPreview: {
      schemaVersion: 1, status: "provisional", reason: "native_source_version_at_or_after_fixed",
      candidateVerdict: "fixed_or_not_affected", trustedVerdict: "unknown",
      sourcePackage: "openssl", sourceVersion: "3.0.13-0ubuntu3",
      snapshotSha256: digest, sourceRevision: revision, conflictingWithTrivy: true,
      publisherAuthenticated: false, remediationAuthorized: false,
    },
  };
  writeFileSync(path.join(reports, id + ".json"), JSON.stringify({
    schemaVersion: 1, inventoryHost: "osv-host", hostname: "osv-host",
    createdAt: new Date().toISOString(), mode: "vulnerabilities", profileId: "cve_packages",
    scanner: { available: true, partial: false },
    findings: [rawFinding], events: [],
  }));
  const record = await projectReports.createProjectReport({
    hostAlias: "osv-host",
    subject: { clientName: "Тестовый заказчик", projectName: "Проверка OSV", period: "02.11.2026", specialist: "Специалист HCP" },
  });
  const saved = JSON.parse(readFileSync(path.join(state, "project-reports", record.fileName.replace(/\.pdf$/, ".json")), "utf8"));
  assert.equal(saved.vendorAdvisoryEvidence.length, 1);
  const evidence = saved.vendorAdvisoryEvidence[0];
  assert.equal(evidence.findingId, findingId);
  assert.equal(evidence.cveId, cve);
  assert.equal(evidence.sourceReportId, id);
  assert.match(evidence.sourceReportSha256, /^[a-f0-9]{64}$/);
  assert.equal(evidence.snapshotSha256, digest);
  assert.equal(evidence.sourceRevision, revision);
  assert.equal(evidence.scannerStatus, "failed");
  assert.equal(evidence.trivyApplicability, "affected");
  assert.equal(evidence.candidateVerdict, "fixed_or_not_affected");
  assert.equal(evidence.conflictingWithTrivy, true);
  assert.equal(evidence.publisherAuthenticated, false);
  assert.equal(evidence.trustedVerdict, "unknown");
  assert.equal(evidence.remediationAuthorized, false);
  assert.match(saved.vendorAdvisoryEvidenceSha256, /^[a-f0-9]{64}$/);
  const pdf = projectReports.readProjectReportPdf(record.id).pdf;
  const python = [
    "import base64,re,sys,zlib",
    "pdf=sys.stdin.buffer.read()",
    "out=[]",
    "for raw in re.findall(rb'stream\\r?\\n(.*?)endstream',pdf,re.S):",
    "    try:",
    "        raw=raw.strip()",
    "        if raw.endswith(b'~>'): raw=base64.a85decode(raw,adobe=True)",
    "        out.append(zlib.decompress(raw))",
    "    except (ValueError,zlib.error): pass",
    "sys.stdout.write(b'\\n'.join(out).decode('latin1'))",
  ].join("\n");
  const rendered = execFileSync("/usr/bin/python3", ["-c", python], { input: pdf, encoding: "utf8", maxBuffer: 12 * 1024 * 1024 });
  assert.ok(rendered.includes(cve), "Actual PDF output omitted the CVE ID");
  assert.ok(rendered.includes(findingId), "Actual PDF output omitted the original finding ID");
  assert.equal(store.verifyAuditChain().valid, true);
});


test("final Debian project JSON and actual PDF preserve every paired CVE×source×version with two SHA-256 provenance levels", async () => {
  const reportId = "debian-evidence-host-vulnerabilities-original";
  const capturedAt = "2026-11-03T14:30:00.000Z";
  const full = "d".repeat(64);
  const excerpt = "e".repeat(64);
  const base = {
    profileId: "cve_packages", category: "CVE пакеты", risk: "high", status: "failed",
    source: "trivy", remediationAvailable: false,
    description: "Original Trivy finding", recommendation: "Review the vendor advisory",
  };
  const make = (id, cveId, sourceVersion, candidateVerdict, reason, disagree, status = "provisional") => ({
    ...base, id, title: cveId + ": libssl3",
    cveApplicability: {
      schemaVersion: 1, verdict: "affected", distribution: { id: "debian", versionId: "12" },
      advisory: { id: cveId, sourceMatch: "matched" },
      package: { name: "libssl3", installedVersion: sourceVersion,
        sourceName: "openssl", sourceVersion,
        manager: "dpkg", provenance: "distribution-maintainer" },
    },
    debianTrackerPreview: {
      schemaVersion: 1, status, reason, candidateVerdict, trustedVerdict: "unknown",
      sourcePackage: "openssl", sourceVersion, release: "bookworm",
      fixedVersion: status === "unavailable" ? null : "3.0.14-1~deb12u2",
      fullSnapshotSha256: full, derivedExcerptSha256: status === "unavailable" ? null : excerpt,
      capturedAt, pinMode: "observed-at-capture", conflictingWithTrivy: disagree,
      publisherAuthenticated: false, publisherFreshnessVerified: false, remediationAuthorized: false,
    },
  });
  const findings = [
    make("trivy_CVE-2024-6119_affected", "CVE-2024-6119", "3.0.14-1~deb12u1",
      "affected", "source_version_before_tracker_fixed", false),
    make("trivy_CVE-2024-6119_fixed", "CVE-2024-6119", "3.0.14-1~deb12u2",
      "fixed_or_not_affected", "source_version_at_or_after_tracker_fixed", true),
    make("trivy_CVE-2024-6120_unknown", "CVE-2024-6120", "3.0.14-1~deb12u1",
      "unknown", "cve_not_listed_unknown_not_clean", false, "unavailable"),
  ];
  writeFileSync(path.join(reports, reportId + ".json"), JSON.stringify({
    schemaVersion: 1, inventoryHost: "debian-evidence-host", hostname: "debian-evidence-host",
    mode: "vulnerabilities", profileId: "cve_packages", createdAt: new Date().toISOString(),
    scanner: { available: true, partial: false }, findings, events: [],
  }));
  const record = await projectReports.createProjectReport({
    hostAlias: "debian-evidence-host", subject: {
      clientName: "ООО Контроль", projectName: "Debian CVE export",
      period: "Ноябрь 2026", specialist: "Специалист HCP",
    },
  });
  const snapshot = JSON.parse(readFileSync(path.join(state, "project-reports", record.fileName.replace(/\.pdf$/, ".json")), "utf8"));
  assert.equal(snapshot.debianTrackerEvidence.length, findings.length);
  assert.deepEqual(snapshot.debianTrackerEvidence.map(x => x.findingId),
    ["trivy_CVE-2024-6119_affected", "trivy_CVE-2024-6119_fixed", "trivy_CVE-2024-6120_unknown"]);
  assert.equal(snapshot.debianTrackerEvidence[0].candidateVerdict, "affected");
  assert.equal(snapshot.debianTrackerEvidence[1].candidateVerdict, "fixed_or_not_affected");
  assert.equal(snapshot.debianTrackerEvidence[1].conflictingWithTrivy, true);
  assert.equal(snapshot.debianTrackerEvidence[2].candidateVerdict, "unknown");
  assert.equal(snapshot.debianTrackerEvidence[2].derivedExcerptSha256, null);
  assert.ok(snapshot.debianTrackerEvidence.every(x => x.fullSnapshotSha256 === full &&
    x.trustedVerdict === "unknown" && x.publisherAuthenticated === false &&
    x.publisherFreshnessVerified === false && x.remediationAuthorized === false));
  assert.match(snapshot.debianTrackerEvidenceSha256, /^[a-f0-9]{64}$/);
  const pdf = projectReports.readProjectReportPdf(record.id).pdf;
  assert.equal(pdf.subarray(0, 5).toString("ascii"), "%PDF-");
  const code = [
    "import base64,re,sys,zlib",
    "buf=sys.stdin.buffer.read()",
    "out=[]",
    "for stream in re.findall(rb'stream\\r?\\n(.*?)endstream',buf,re.S):",
    "    try:",
    "        stream=stream.strip()",
    "        if stream.endswith(b'~>'): stream=base64.a85decode(stream,adobe=True)",
    "        out.append(zlib.decompress(stream))",
    "    except (ValueError,zlib.error): pass",
    "sys.stdout.write(b'\\n'.join(out).decode('latin1'))",
  ].join("\n");
  const rendered = execFileSync("/usr/bin/python3", ["-c", code], {
    input: pdf, encoding: "utf8", maxBuffer: 12 * 1024 * 1024,
  });
  for (const item of findings) assert.ok(rendered.includes(item.id), "PDF dropped CVE finding " + item.id);
  assert.ok(rendered.includes(full), "PDF dropped the full snapshot SHA-256");
  assert.ok(rendered.includes(excerpt), "PDF dropped the derived excerpt SHA-256");
  assert.ok(rendered.includes(snapshot.debianTrackerEvidenceSha256), "PDF dropped the projection SHA-256");
  assert.ok(rendered.includes("CVE-2024-6120"), "PDF dropped an unknown CVE observation");
  assert.equal(store.verifyAuditChain().valid, true);
});


test("Debian APT source-index metadata retains report identity and trust caveats in final JSON and real PDF", async () => {
  const sourceId = "apt-source-host-packages-native-run";
  const aptDigest = "e".repeat(64);
  writeFileSync(path.join(reports, sourceId + ".json"), JSON.stringify({
    inventoryHost: "apt-source-host", hostname: "apt-source-host", mode: "packages",
    profileId: "packages", createdAt: new Date().toISOString(),
    packageInventory: {
      manager: "dpkg", packageCount: 1, osRelease: {
        ID: "debian", VERSION_ID: "12", VERSION_CODENAME: "bookworm",
      },
      debianSignedReleases: {
        schemaVersion: 1, status: "verified_with_local_keyring", releaseCodename: "bookworm",
        candidateFiles: 1, validLocalSignatures: 1, invalidOrUnverifiable: 0,
        signedReleases: ["bookworm"], signerFingerprints: ["a".repeat(40)],
        inReleaseSha256: ["b".repeat(64)], localKeyringSha256: "c".repeat(64),
        localSignatureVerified: true, publisherAuthenticated: false,
        publisherFreshnessVerified: false, packageIndexHashesVerified: false,
        installedPackageOriginVerified: false, remediationAuthorized: false,
        scope: "cached-inrelease-gpgv-installed-archive-keyring-only",
      },
      aptRepositories: {
        schemaVersion: 1, status: "observed", releaseCodename: "bookworm",
        indexEntries: 2, debianLabelEntries: 2, otherLabelEntries: 0,
        unknownLabelEntries: 0, suites: ["bookworm", "bookworm-security"],
        releaseLabels: ["Debian"], suiteConsistent: true, policySha256: aptDigest,
        publisherAuthenticated: false, repositorySignatureVerified: false,
        installedPackageOriginVerified: false,
        scope: "apt-cache-policy-index-metadata-only; no-installed-origin-or-signature-attestation",
      },
    },
    packages: [{ name: "libssl3:amd64", version: "3.0.14-1~deb12u2", manager: "dpkg",
      arch: "amd64", sourceName: "openssl", sourceVersion: "3.0.14-1~deb12u2",
      sourceEpochKnown: true, maintainer: "Debian Team", origin: "" }],
    findings: [], events: [],
  }));
  const record = await projectReports.createProjectReport({ hostAlias: "apt-source-host",
    subject: { clientName: "ООО Тест", projectName: "APT evidence", period: "Ноябрь 2026",
      specialist: "Специалист HCP" },
  });
  const snapshot = JSON.parse(readFileSync(path.join(state, "project-reports",
    record.fileName.replace(/\.pdf$/, ".json")), "utf8"));
  assert.equal(snapshot.debianAptIndexEvidence.length, 1);
  const observation = snapshot.debianAptIndexEvidence[0];
  assert.equal(observation.sourceReportId, sourceId);
  assert.match(observation.sourceReportSha256, /^[a-f0-9]{64}$/);
  assert.equal(observation.state, "observed");
  assert.equal(observation.policySha256, aptDigest);
  assert.deepEqual(observation.suites, ["bookworm", "bookworm-security"]);
  assert.equal(observation.publisherAuthenticated, false);
  assert.equal(observation.repositorySignatureVerified, false);
  assert.equal(observation.installedPackageOriginVerified, false);
  assert.match(snapshot.debianAptIndexEvidenceSha256, /^[a-f0-9]{64}$/);
  assert.equal(snapshot.debianSignedReleaseEvidence.length, 1);
  const signature = snapshot.debianSignedReleaseEvidence[0];
  assert.equal(signature.sourceReportId, sourceId);
  assert.equal(signature.status, "verified_with_local_keyring");
  assert.equal(signature.localSignatureVerified, true);
  assert.equal(signature.publisherAuthenticated, false);
  assert.equal(signature.publisherFreshnessVerified, false);
  assert.equal(signature.packageIndexHashesVerified, false);
  assert.equal(signature.installedPackageOriginVerified, false);
  assert.equal(signature.remediationAuthorized, false);
  assert.equal(signature.localKeyringSha256, "c".repeat(64));
  assert.match(snapshot.debianSignedReleaseEvidenceSha256, /^[a-f0-9]{64}$/);
  const pdf = projectReports.readProjectReportPdf(record.id).pdf;
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
    "sys.stdout.write(b'\\n'.join(chunks).decode('latin1'))",
  ].join("\n");
  const rendered = execFileSync("/usr/bin/python3", ["-c", python], {
    input: pdf, encoding: "utf8", maxBuffer: 12 * 1024 * 1024,
  });
  for (const marker of [sourceId, observation.sourceReportSha256, aptDigest,
    snapshot.debianAptIndexEvidenceSha256, snapshot.debianSignedReleaseEvidenceSha256, "bookworm-security",
    signature.localKeyringSha256, signature.inReleaseSha256[0], signature.signerFingerprints[0]]) {
    assert.ok(rendered.includes(marker), "Final PDF dropped APT source identity or metadata hash");
  }
  assert.equal(store.verifyAuditChain().valid, true);
});
