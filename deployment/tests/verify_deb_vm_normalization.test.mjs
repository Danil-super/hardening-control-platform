/** Synthetic controller regressions; they do not execute or attest a native VM. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const helper = fileURLToPath(new URL("verify_deb_vm_normalization.mjs", import.meta.url));
const phases = ["baseline", "violated", "restored", "firewall-baseline", "firewall-allow-all", "firewall-restored"];
const machineId = "123456789abcdef0123456789abcdef0";
function fixture(phase, partial) {
  const field = (id, status, evidence) => ({
    id, status, risk: status === "failed" ? "medium" : "info", evidence,
    title: `Synthetic ${id}`, description: "Controller regression", recommendation: "Fixture only",
    category: "Synthetic", profileId: "basic_linux", source: "agentless",
  });
  const cron = phase === "violated" ? "inactive" : "active";
  return {
    schemaVersion: 1, inventoryHost: "hcp-deb-ci", hostname: "hcp-deb-ci", mode: "agentless",
    profileId: "basic_linux", runId: phase, createdAt: new Date(Date.now() - 1000).toISOString(),
    acceptanceFixture: { synthetic: true, nativeExecution: false },
    scanner: { source: "agentless", partial, incompleteChecks: partial ? ["unrelated_unavailable_check"] : [] },
    agentless: { serviceManager: "systemd", serviceObservations: [{ service: "cron", state: cron, evidence: "synthetic service observation" }] },
    summary: { score: partial ? null : 75 },
    findings: [
      field("world_writable_dirs", phase === "violated" ? "failed" : "passed", "synthetic permissions observation"),
      field("critical_services_review", "manual", `ssh=active; synthetic; cron=${cron}; synthetic`),
      field("firewall_active", phase === "firewall-allow-all" ? "failed" : "passed", "packet_model=new_non_loopback_non_dnat_tcp_udp; evaluation=conditional_ruleset_path; external_reachability=unverified"),
      field("unrelated_check", "passed", "preserved unrelated evidence"),
    ],
  };
}

function execute({ partial = false, changeReport, changeIdentity, malformedIdentity = false, encodeMachineId = false } = {}) {
  const work = mkdtempSync(path.join(tmpdir(), "hcp-deb-publication-test-"));
  const artifacts = path.join(work, "artifacts");
  const output = path.join(artifacts, "publication");
  try {
    mkdirSync(path.join(artifacts, "reports"), { recursive: true });
    const observed = { alias: "hcp-deb-ci", machineId, sshHostKeyFingerprint: "SHA256:" + "A".repeat(43),
      observedAt: new Date(Date.now() - 5000).toISOString(), connection: { address: "127.0.0.1", port: 22022, user: "hcp-ci" } };
    if (changeIdentity) changeIdentity(observed);
    const observationFile = path.join(work, "private-identity.json");
    writeFileSync(observationFile, malformedIdentity ? `invalid-json-${machineId}` : JSON.stringify(observed), { mode: 0o600 });
    for (const phase of phases) {
      const native = fixture(phase, partial);
      if (changeReport) changeReport(native, phase);
      let bytes = JSON.stringify(native);
      if (encodeMachineId) bytes = bytes.replaceAll(machineId, [...machineId].map((char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`).join(""));
      writeFileSync(path.join(artifacts, "reports", `hcp-deb-ci-basic_linux-${phase}.json`), bytes);
    }
    const result = spawnSync(process.execPath, [helper, artifacts, observationFile, output], { encoding: "utf8", timeout: 30000 });
    assert.equal(result.error, undefined);
    const protocolText = readFileSync(path.join(output, "protocol.json"), "utf8");
    assert.ok(!protocolText.includes(machineId), "A protocol, including failures, must not reveal machine-id");
    assert.ok(!result.stdout.includes(machineId) && !result.stderr.includes(machineId), "Helper logs must not reveal machine-id");
    const protocol = JSON.parse(protocolText);
    const published = protocol.status === "passed" ? readdirSync(path.join(output, "published")).map((file) => {
      const text = readFileSync(path.join(output, "published", file), "utf8");
      assert.ok(!text.includes(machineId));
      return JSON.parse(text);
    }) : [];
    return { result, protocol, published };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

test("production publication binds all six reports to pre-scan identity and preserves native observations", () => {
  const { result, protocol, published } = execute();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(protocol.status, "passed");
  assert.equal(protocol.browserOnboardingEvaluated, false);
  assert.equal(protocol.rawMachineIdPublished, false);
  assert.equal(published.length, 6);
  assert.equal(new Set(published.map((report) => report.assetBinding.assetId)).size, 1);
  assert.ok(published.every((report) => report.assetBinding.status === "verified" && report.assetBinding.alias === "hcp-deb-ci"));
  assert.deepEqual(protocol.checks.map((check) => check.controlStatus), ["passed", "failed", "passed", "passed", "failed", "passed"]);
  assert.deepEqual(protocol.checks.slice(0, 3).map((check) => check.cronState), ["active", "inactive", "active"]);
  assert.ok(protocol.checks.every((check) => check.identityCapturedBeforeScan && check.assetBindingConserved && check.rawConserved
    && check.findingIdentityStatusRiskEvidenceConserved && check.findingCount === 4 && !check.partial && check.score === 75));
});

test("unrelated incomplete evidence stays partial and has no configuration score after publication", () => {
  const { result, protocol } = execute({ partial: true });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(protocol.checks.every((check) => check.partial && check.score === null && check.incompleteChecks[0] === "unrelated_unavailable_check"));
});

test("late or wrong identity and unproven native controls cannot yield accepted publication evidence", () => {
  for (const options of [
    { changeIdentity: (observed) => { observed.observedAt = new Date(Date.now() + 60000).toISOString(); } },
    { changeIdentity: (observed) => { observed.alias = observed.machineId; } },
    { malformedIdentity: true },
    { changeReport: (native) => { native.inventoryHost = "another-host"; } },
    { changeReport: (native, phase) => { if (phase === "violated") native.agentless.serviceObservations[0].state = "unknown"; } },
    { changeReport: (native, phase) => { if (phase === "firewall-allow-all") native.findings[2].status = "manual"; } },
    { changeReport: (native, phase) => { if (phase === "firewall-baseline") native.findings[2].evidence = "ufw is active"; } },
    { changeReport: (native) => { native.findings[3].risk = "invalid-risk"; } },
    { changeReport: (native) => { native.scanner.available = false; } },
    { changeReport: (native) => { native.findings[3].evidence = machineId; } },
    { changeReport: (native) => { native.findings[3].evidence = machineId; }, encodeMachineId: true },
  ]) {
    const { result, protocol } = execute(options);
    assert.notEqual(result.status, 0, "Invalid evidence was accepted");
    assert.equal(protocol.status, "failed");
  }
});
