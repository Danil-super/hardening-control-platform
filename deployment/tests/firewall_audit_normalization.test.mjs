/** Synthetic publication regressions; these do not execute or attest a VM. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const helper = fileURLToPath(new URL("verify_firewall_audit_normalization.mjs", import.meta.url));
function nativeFixture(phase, status, partial) {
  const finding = {
    id: "firewall_active", title: "Synthetic firewall fixture", description: "Controller regression only",
    recommendation: "Fixture", category: "network", profileId: "basic_linux", source: "agentless",
    risk: status === "failed" ? "medium" : "info", status,
    evidence: "packet_model=new_non_loopback_non_dnat_tcp_udp; evaluation=conditional_ruleset_path; external_reachability=unverified; nftables={\"nftables\":[]}",
  };
  return {
    schemaVersion: 1, runId: `firewall-audit-${phase}`, inventoryHost: "hcp-rpm-ci", hostname: "hcp-rpm-ci",
    createdAt: new Date().toISOString(), profileId: "basic_linux", mode: "agentless",
    acceptanceFixture: { synthetic: true, nativeExecution: false },
    scanner: { source: "agentless", partial, incompleteChecks: partial ? ["unrelated_unavailable_check"] : [] },
    summary: { score: partial ? null : 75 },
    findings: [finding, { ...finding, id: "unrelated_check", status: "passed", evidence: "fixture-preserved-evidence" }],
  };
}

function execute(change, partial = false) {
  const artifacts = mkdtempSync(path.join(tmpdir(), "hcp-firewall-normalization-test-"));
  try {
    mkdirSync(path.join(artifacts, "reports"));
    for (const [phase, status] of [["baseline", "passed"], ["allow-all", "failed"], ["restored", "passed"]]) {
      const native = nativeFixture(phase, status, partial);
      if (change) change(native, phase);
      writeFileSync(path.join(artifacts, "reports", `hcp-rpm-ci-basic_linux-firewall-audit-${phase}.json`), JSON.stringify(native));
    }
    const result = spawnSync(process.execPath, [helper, artifacts], { encoding: "utf8", timeout: 30000 });
    assert.equal(result.error, undefined);
    const protocol = JSON.parse(readFileSync(path.join(artifacts, "firewall-audit-normalized", "protocol.json"), "utf8"));
    return { result, protocol };
  } finally {
    rmSync(artifacts, { recursive: true, force: true });
  }
}

test("actual production normalizer preserves all native findings and raw observations", () => {
  const { result, protocol } = execute();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(protocol.status, "passed");
  assert.deepEqual(protocol.checks.map((check) => check.firewallStatus), ["passed", "failed", "passed"]);
  assert.ok(protocol.checks.every((check) => check.findingCount === 2 && check.rawConserved && !check.partial));
});

test("unrelated incomplete checks remain partial and cannot gain a score", () => {
  const { result, protocol } = execute(undefined, true);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(protocol.checks.every((check) => check.partial && check.incompleteChecks[0] === "unrelated_unavailable_check"));
});

test("a wrong expected decision, invalid native finding or missing scope cannot be normalized into PASS", () => {
  for (const change of [
    (native) => { native.findings[0].status = "manual"; },
    (native) => { native.findings[1].risk = "invalid-risk"; },
    (native) => { native.findings[0].evidence = "firewalld=running"; },
    (native) => { native.scanner.available = false; },
    (native) => { native.scanner.incompleteChecks = ["firewall_active"]; native.scanner.partial = true; native.summary.score = null; },
  ]) {
    const { result, protocol } = execute((native, phase) => { if (phase === "allow-all") change(native); });
    assert.notEqual(result.status, 0, "Malformed or unproven evidence was accepted");
    assert.equal(protocol.status, "failed");
  }
});
