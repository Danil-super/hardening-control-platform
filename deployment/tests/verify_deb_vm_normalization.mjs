#!/usr/bin/env node
/**
 * Publish six actual owned-VM reports with the production asset-binding and
 * report-publication code, then read them through the production normalizer.
 * Usage: node verify_deb_vm_normalization.mjs <artifacts-dir> <private-identity.json> <outdir>
 * The caller establishes authenticated SSH/VM provenance before collection.
 * This helper neither performs browser onboarding nor attests its own input.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { compileServerModules } from "../../web/tests/_typescript-loader.mjs";

assert.equal(process.argv.length, 5, "Usage: node verify_deb_vm_normalization.mjs <artifacts-dir> <private-identity.json> <outdir>");
const [artifacts, observationFile, output] = process.argv.slice(2).map((value) => path.resolve(value));
mkdirSync(output, { mode: 0o700 });
mkdirSync(path.join(output, "normalized"), { mode: 0o700 });
const runtime = mkdtempSync(path.join(tmpdir(), "hcp-deb-report-publication-"));
const stage = path.join(runtime, "stage");
mkdirSync(stage, { mode: 0o700 });
process.env.HCP_STATE_DIR = runtime;
process.env.HCP_REPORTS_DIR = path.join(output, "published");
const phases = [
  { phase: "baseline", finding: "world_writable_dirs", status: "passed", cron: "active" },
  { phase: "violated", finding: "world_writable_dirs", status: "failed", cron: "inactive" },
  { phase: "restored", finding: "world_writable_dirs", status: "passed", cron: "active" },
  { phase: "firewall-baseline", finding: "firewall_active", status: "passed" },
  { phase: "firewall-allow-all", finding: "firewall_active", status: "failed" },
  { phase: "firewall-restored", finding: "firewall_active", status: "passed" },
];
const protocol = {
  schemaVersion: 1, status: "running", alias: "hcp-deb-ci", startedAt: new Date().toISOString(),
  scope: "Authenticated pre-scan identity -> production publication -> production normalized agentless reports",
  nativeExecutionProvenance: "Established by the calling owned-VM SSH harness, not by this helper",
  browserOnboardingEvaluated: false, rawMachineIdPublished: false,
  packetModel: "new_non_loopback_non_dnat_tcp_udp", externalReachability: "unverified",
  checks: [],
};
let compiled;
let privateMachineId;
const digest = (value) => createHash("sha256").update(value).digest("hex");
const conservedFindings = (findings) => findings.map(({ id, status, risk, evidence }) => ({ id, status, risk, evidence }));
function save(name, value) {
  const bytes = JSON.stringify(value, null, 2) + "\n";
  assert.ok(!privateMachineId || !bytes.includes(privateMachineId), "Raw machine identity must remain private");
  writeFileSync(path.join(output, name), bytes, { mode: 0o600 });
}
function uniqueFinding(native, id) {
  const matches = native.findings.filter((finding) => finding.id === id);
  assert.equal(matches.length, 1, `Expected exactly one ${id} finding`);
  return matches[0];
}

try {
  save("protocol.json", protocol);
  let observed;
  try { observed = JSON.parse(readFileSync(observationFile, "utf8")); }
  catch { throw new Error("Private identity input could not be read as JSON"); }
  privateMachineId = typeof observed?.machineId === "string" ? observed.machineId : undefined;
  assert.ok(observed && typeof observed === "object" && !Array.isArray(observed), "Private identity input must be an object");
  assert.ok(privateMachineId && /^[a-f0-9]{32}$/.test(privateMachineId), "A private machine identity is required");
  assert.equal(observed.alias, protocol.alias);
  assert.equal(observed.connection?.address, "127.0.0.1");
  assert.equal(observed.connection?.user, "hcp-ci");
  assert.ok(Number.isSafeInteger(observed.connection?.port) && observed.connection.port > 0 && observed.connection.port <= 65535);
  compiled = compileServerModules(["ansible-reports", "asset-report-publication", "asset-binding", "state-store"]);
  const { assetConnectionId, machineIdentityHash } = await import(compiled.url("asset-binding"));
  const { recordAssetObservation } = await import(compiled.url("state-store"));
  const { publishCapturedAssetReports } = await import(compiled.url("asset-report-publication"));
  const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
  const binding = recordAssetObservation({
    alias: observed.alias, connectionId: assetConnectionId(observed.connection),
    observation: { machineIdSha256: machineIdentityHash(observed.machineId), sshHostKeyFingerprint: observed.sshHostKeyFingerprint, observedAt: observed.observedAt },
  });
  const inputs = phases.map((expected) => {
    const id = `${protocol.alias}-basic_linux-${expected.phase}`;
    const file = `${id}.json`;
    const source = path.join(artifacts, "reports", file);
    const bytes = readFileSync(source);
    assert.ok(!bytes.toString("utf8").includes(privateMachineId), "A native report must not expose the raw machine identity");
    const native = JSON.parse(bytes.toString("utf8"));
    assert.ok(!JSON.stringify(native).includes(privateMachineId), "A decoded native report must not expose the raw machine identity");
    assert.equal(native.inventoryHost, protocol.alias);
    assert.equal(native.runId, expected.phase);
    assert.equal(native.profileId, "basic_linux");
    assert.equal(native.mode, "agentless");
    assert.ok(Date.parse(binding.verifiedAt) <= Date.parse(native.createdAt), "Authenticated identity must be observed before scanning");
    assert.ok(Array.isArray(native.findings));
    assert.equal(typeof native.scanner?.partial, "boolean");
    assert.ok(Array.isArray(native.scanner.incompleteChecks));
    if (native.scanner.incompleteChecks.length) assert.equal(native.scanner.partial, true);
    assert.ok(!native.scanner.incompleteChecks.includes(expected.finding), "The independently controlled finding cannot be incomplete");
    const finding = uniqueFinding(native, expected.finding);
    assert.equal(finding.status, expected.status, `${expected.phase}: wrong native control verdict`);
    if (expected.cron) {
      assert.equal(native.agentless?.serviceManager, "systemd");
      const cron = native.agentless.serviceObservations?.filter((entry) => entry.service === "cron");
      assert.equal(cron?.length, 1);
      assert.equal(cron[0].state, expected.cron, "Native service observation must follow the actual service state");
      assert.match(uniqueFinding(native, "critical_services_review").evidence, new RegExp(`(?:^|; )cron=${expected.cron};`));
    } else {
      for (const marker of [`packet_model=${protocol.packetModel}`, "evaluation=conditional_ruleset_path", "external_reachability=unverified"]) {
        assert.ok(finding.evidence?.includes(marker), `Missing declared firewall scope: ${marker}`);
      }
    }
    writeFileSync(path.join(stage, file), bytes, { flag: "wx", mode: 0o600 });
    return { ...expected, id, file, native, nativeSha256: digest(bytes) };
  });
  publishCapturedAssetReports(stage, new Map(inputs.map(({ file }) => [file, binding])));
  for (const input of inputs) {
    const { id, phase, native } = input;
    const report = readAnsibleReport(id);
    assert.ok(report, "Production normalizer must read the published report");
    assert.equal(report.id, id);
    assert.equal(report.available, true);
    assert.equal(report.reportTimeValid, true);
    assert.equal(report.assetBindingInvalid, false);
    assert.deepEqual(report.assetBinding, binding);
    assert.deepEqual(report.raw, { ...native, assetBinding: binding }, "Publication must preserve all native observations and incomplete-check reasons");
    assert.equal(report.mode, native.mode);
    assert.equal(report.profileId, native.profileId);
    assert.equal(report.findingsCount, native.findings.length);
    assert.deepEqual(conservedFindings(report.findings), conservedFindings(native.findings), "Every finding identity, verdict, risk and evidence must survive normalization");
    assert.equal(report.partial, native.scanner.partial, "Normalization must preserve incomplete coverage");
    if (native.scanner.partial) {
      assert.equal(native.summary?.score, null);
      assert.equal(report.score, null, "An incomplete report cannot acquire a security score");
    } else assert.equal(report.score, native.summary?.score);
    for (const risk of ["high", "medium", "low"]) {
      assert.equal(report[risk], native.findings.filter((finding) => finding.status === "failed" && finding.risk === risk).length);
    }
    save(`normalized/${phase}.json`, report);
    const published = readFileSync(path.join(process.env.HCP_REPORTS_DIR, input.file));
    assert.ok(!published.toString("utf8").includes(privateMachineId));
    protocol.checks.push({
      phase, reportId: id, controlFinding: input.finding, controlStatus: input.status,
      ...(input.cron ? { cronState: input.cron } : {}),
      findingCount: report.findingsCount, score: report.score, partial: report.partial,
      incompleteChecks: native.scanner.incompleteChecks,
      identityCapturedBeforeScan: true, assetBindingConserved: true, rawConserved: true,
      findingIdentityStatusRiskEvidenceConserved: true,
      nativeSha256: input.nativeSha256, publishedSha256: digest(published),
      normalizedSha256: digest(readFileSync(path.join(output, "normalized", `${phase}.json`))),
    });
    save("protocol.json", protocol);
  }
  protocol.sourceSha256 = Object.fromEntries(["ansible-reports", "asset-report-publication", "asset-binding", "state-store"].map((name) => [
    `web/lib/${name}.ts`, digest(readFileSync(new URL(`../../web/lib/${name}.ts`, import.meta.url))),
  ]));
  protocol.status = "passed";
  protocol.finishedAt = new Date().toISOString();
  save("protocol.json", protocol);
  process.stdout.write(JSON.stringify(protocol) + "\n");
} catch (error) {
  protocol.status = "failed";
  const message = String(error.message);
  protocol.error = { type: error.name, message: privateMachineId ? message.split(privateMachineId).join("[private machine identity]") : message };
  save("protocol.json", protocol);
  process.stderr.write(`${protocol.error.type}: ${protocol.error.message}\n`);
  process.exitCode = 1;
} finally {
  if (compiled) rmSync(compiled.directory, { recursive: true, force: true });
  rmSync(runtime, { recursive: true, force: true });
}
