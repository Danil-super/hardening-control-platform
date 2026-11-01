#!/usr/bin/env node
/**
 * node deployment/tests/verify_firewall_audit_normalization.mjs <artifacts-dir>
 * Read the three actual RPM-VM agentless reports with the production web
 * normalizer. The calling VM harness establishes native execution/provenance;
 * this helper proves that the saved observations survive normalization.
 * Node 24 and web/npm ci are required. No host configuration is modified.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { compileServerModules } from "../../web/tests/_typescript-loader.mjs";

assert.equal(process.argv.length, 3, "Usage: node deployment/tests/verify_firewall_audit_normalization.mjs <artifacts-dir>");
const artifacts = path.resolve(process.argv[2]);
const output = path.join(artifacts, "firewall-audit-normalized");
mkdirSync(output, { mode: 0o700 });
const runtime = mkdtempSync(path.join(tmpdir(), "hcp-firewall-audit-normalization-"));
process.env.HCP_STATE_DIR = runtime;
process.env.HCP_REPORTS_DIR = path.join(artifacts, "reports");
const protocol = {
  status: "running", packetModel: "new_non_loopback_non_dnat_tcp_udp",
  evaluation: "conditional_ruleset_path", externalReachability: "unverified",
  nativeExecutionProvenance: "established by the calling owned-VM harness, not by normalization",
  checks: [],
};
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const save = (name, value) => writeFileSync(path.join(output, name), JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
const conservedFields = (findings) => findings.map(({ id, status, risk, evidence }) => ({ id, status, risk, evidence }));
let compiled;
try {
  save("protocol.json", protocol);
  compiled = compileServerModules(["ansible-reports"]);
  const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
  for (const [phase, expected] of [["baseline", "passed"], ["allow-all", "failed"], ["restored", "passed"]]) {
    const runId = `firewall-audit-${phase}`;
    const id = `hcp-rpm-ci-basic_linux-${runId}`;
    const nativeBytes = readFileSync(path.join(process.env.HCP_REPORTS_DIR, `${id}.json`));
    const native = JSON.parse(nativeBytes.toString("utf8"));
    assert.equal(native.runId, runId);
    assert.equal(native.inventoryHost, "hcp-rpm-ci");
    assert.equal(native.profileId, "basic_linux");
    assert.equal(native.mode, "agentless");
    assert.ok(Array.isArray(native.findings));
    assert.equal(typeof native.scanner?.partial, "boolean");
    assert.ok(Array.isArray(native.scanner.incompleteChecks));
    assert.ok(!native.scanner.incompleteChecks.includes("firewall_active"), "Proven firewall control cannot remain an incomplete check");
    if (native.scanner.incompleteChecks.length) assert.equal(native.scanner.partial, true);
    const control = native.findings.filter((finding) => finding.id === "firewall_active");
    assert.equal(control.length, 1, "Exactly one native firewall finding is required");
    assert.equal(control[0].status, expected, `${phase} must retain its independently expected decision`);
    for (const marker of [`packet_model=${protocol.packetModel}`, "evaluation=conditional_ruleset_path", "external_reachability=unverified"]) {
      assert.ok(control[0].evidence?.includes(marker), `Missing declared native packet scope: ${marker}`);
    }

    const normalized = readAnsibleReport(id);
    assert.ok(normalized, "Production normalizer must read the actual native report");
    assert.equal(normalized.id, id);
    assert.equal(normalized.available, true);
    assert.equal(normalized.reportTimeValid, true);
    assert.equal(normalized.mode, native.mode);
    assert.equal(normalized.profileId, native.profileId);
    assert.deepEqual(normalized.raw, native, "Every original native field and incomplete-check reason must survive normalization");
    assert.equal(normalized.findingsCount, native.findings.length, "Normalizer must not silently drop native findings");
    assert.deepEqual(conservedFields(normalized.findings), conservedFields(native.findings), "Finding identity/status/risk/evidence changed");
    assert.equal(normalized.partial, native.scanner.partial, "Coverage must remain truthful after normalization");
    assert.deepEqual(normalized.raw.scanner.incompleteChecks, native.scanner.incompleteChecks);
    if (native.scanner.partial) {
      assert.equal(native.summary?.score, null);
      assert.equal(normalized.score, null, "Partial evidence must not turn into an unqualified score");
    }
    save(`${phase}.json`, normalized);
    protocol.checks.push({
      phase, reportId: id, firewallStatus: expected, findingCount: native.findings.length,
      partial: normalized.partial, incompleteChecks: native.scanner.incompleteChecks,
      nativeSha256: digest(nativeBytes), normalizedSha256: digest(readFileSync(path.join(output, `${phase}.json`))),
      rawConserved: true, findingIdentityStatusRiskEvidenceConserved: true,
    });
    save("protocol.json", protocol);
  }
  protocol.normalizerSourceSha256 = digest(readFileSync(new URL("../../web/lib/ansible-reports.ts", import.meta.url)));
  protocol.status = "passed";
  save("protocol.json", protocol);
  process.stdout.write(JSON.stringify(protocol) + "\n");
} catch (error) {
  protocol.status = "failed";
  protocol.error = { type: error.name, message: error.message };
  save("protocol.json", protocol);
  throw error;
} finally {
  if (compiled) rmSync(compiled.directory, { recursive: true, force: true });
  rmSync(runtime, { recursive: true, force: true });
}
