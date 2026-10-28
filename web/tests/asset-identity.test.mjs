import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test, { after, afterEach, beforeEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["state-store", "asset-binding", "asset-report-publication", "ansible-reports", "audit-correlation", "remediation-plan-evidence"]);
const store = await import(compiled.url("state-store"));
const identity = await import(compiled.url("asset-binding"));
const reports = await import(compiled.url("ansible-reports"));
const { explicitInventoryConnectionId } = await import(compiled.url("inventory"));
const { buildHostCorrelation } = await import(compiled.url("audit-correlation"));
const { assertPlanVerification } = await import(compiled.url("remediation-plan-evidence"));
const { publishCapturedAssetReports } = await import(compiled.url("asset-report-publication"));
const { currentOperationOwner, operationOwnerState } = await import(compiled.url("operation-owner"));
const saved = Object.fromEntries(["HCP_STATE_DIR", "HCP_REPORTS_DIR", "HCP_AUDIT_HMAC_KEY"].map((key) => [key, process.env[key]]));
const originalCwd = process.cwd();
let directory;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-asset-identity-"));
  mkdirSync(path.join(directory, "web")); mkdirSync(path.join(directory, "ansible"));
  // Correlation resolves the current effective inventory as well as persisted
  // identity. Never inherit the developer's real inventory from process.cwd().
  writeFileSync(path.join(directory, "ansible/inventory.ini"), "[linux_hosts]\nhost-one ansible_host=192.0.2.20 ansible_port=22 ansible_user=audit\n");
  process.chdir(path.join(directory, "web"));
  process.env.HCP_STATE_DIR = directory; process.env.HCP_REPORTS_DIR = path.join(directory, "reports");
  process.env.HCP_AUDIT_HMAC_KEY = "asset-test-ledger-key";
  mkdirSync(process.env.HCP_REPORTS_DIR);
});
afterEach(() => { process.chdir(originalCwd); rmSync(directory, { recursive: true, force: true }); });
after(() => { for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } rmSync(compiled.directory, { recursive: true, force: true }); });
const fingerprint = `SHA256:${"A".repeat(43)}`;
const observation = (machine = "1") => ({ machineIdSha256: identity.machineIdentityHash(machine.repeat(32)), sshHostKeyFingerprint: fingerprint, observedAt: new Date().toISOString() });
const connectionId = identity.assetConnectionId({ address: "192.0.2.20", port: 22, user: "audit" });
const bind = (alias = "host-one", observed = observation()) => store.recordAssetObservation({ alias, connectionId, observation: observed });
function rebind(alias, current, observed) {
  return store.recordAssetObservation({ alias, connectionId, observation: observed }, { expectedGeneration: current.generation, expectedAssetId: current.assetId,
    observedAssetId: identity.assetIdForObservation(observed), reason: "Independently verified replacement via the console and reviewed ticket ASSET-42." });
}
function transaction(id, binding) {
  return store.createRemediationTransaction({ id, hostAlias: binding.alias, action: "closePort", profileId: "basic_linux", reason: "Controlled asset fixture",
    parameters: { target_port: "8080", _hcp_asset_binding: JSON.stringify(binding) } });
}
function databaseOperation(operation) {
  const database = new DatabaseSync(path.join(directory, "hcp.sqlite"));
  try { return operation(database); } finally { database.close(); }
}
function deadLease(operationId) {
  const owner = JSON.stringify({ ...JSON.parse(currentOperationOwner), pid: 2147483647, start: "fixture-dead-process" });
  assert.equal(operationOwnerState(owner), "dead");
  databaseOperation((database) => database.prepare("UPDATE asset_execution_leases SET owner = ? WHERE operation_id = ?").run(owner, operationId));
}
const leaseCount = () => databaseOperation((database) => database.prepare("SELECT COUNT(*) AS count FROM asset_execution_leases").get().count);
const closeoutInput = (alias = "host-two", credentialId = "a".repeat(64)) => ({ credentialId,
  identity: { alias, address: "192.0.2.20", port: 22, user: "audit" }, fingerprint });
const finding = { id: "fixture", profileId: "basic_linux", source: "agentless", title: "Asset finding", description: "Fixture", recommendation: "Review",
  category: "Fixture", risk: "high", status: "failed", remediationAvailable: false };
function save(id, binding, status = "failed") {
  writeFileSync(path.join(process.env.HCP_REPORTS_DIR, `${id}.json`), JSON.stringify({ inventoryHost: "host-one", hostname: "host-one", createdAt: new Date().toISOString(),
    mode: "agentless", profileId: "basic_linux", scanner: { available: true, partial: false }, ...(binding ? { assetBinding: binding } : {}), findings: [{ ...finding, status }] }));
  return reports.readAnsibleReport(id);
}

test("identical authenticated identity joins aliases; equal IP or machine-id alone never does", () => {
  const one = bind(); const two = bind("host-two");
  assert.equal(one.assetId, two.assetId);
  assert.deepEqual(store.aliasesForAsset("host-one").sort(), ["host-one", "host-two"]);
  const sameAddressOtherMachine = bind("host-three", observation("2"));
  const sameMachineOtherKey = bind("host-four", { ...observation(), sshHostKeyFingerprint: `SHA256:${"B".repeat(43)}` });
  assert.notEqual(sameAddressOtherMachine.assetId, one.assetId); assert.notEqual(sameMachineOtherKey.assetId, one.assetId);
  assert.throws(() => identity.machineIdentityHash("0".repeat(32)));
  assert.throws(() => identity.machineIdentityHash("uninitialized"));
  assert.equal(JSON.stringify(one).includes("1".repeat(32)), false, "raw machine-id is not persisted");
});

test("binding changes require exact observation/generation and append immutable history", () => {
  const first = bind(); const other = observation("2");
  assert.equal(bind().generation, 1);
  assert.throws(() => bind("host-one", other), { code: "asset_identity_changed" });
  assert.deepEqual(store.currentAssetBinding("host-one"), first);
  assert.throws(() => store.recordAssetObservation({ alias: "host-one", connectionId, observation: other }, {
    expectedGeneration: 99, expectedAssetId: first.assetId, observedAssetId: identity.assetIdForObservation(other), reason: "Independent check was completed" }), { code: "asset_binding_stale" });
  const second = rebind("host-one", first, other);
  assert.equal(second.generation, 2); assert.notEqual(second.assetId, first.assetId);
  assert.deepEqual(store.assetBindingHistory("host-one").map((entry) => entry.binding.generation), [2, 1]);
  const database = new DatabaseSync(path.join(directory, "hcp.sqlite"));
  try { assert.throws(() => database.exec("UPDATE asset_bindings SET asset_id='changed'"), /immutable/); assert.throws(() => database.exec("DELETE FROM asset_bindings"), /immutable/); }
  finally { database.close(); }
  assert.equal(store.verifyAuditChain().valid, true);
});

test("a connection-only observation cannot invalidate a backed-up transaction generation", () => {
  const first = bind();
  transaction("protected-backup", first);
  store.updateRemediationTransaction("protected-backup", { status: "backed_up", backupRef: "/fixture/archive" });
  const nextConnection = identity.assetConnectionId({ address: "192.0.2.21", port: 22, user: "audit" });
  assert.throws(() => store.recordAssetObservation({ alias: first.alias, connectionId: nextConnection, observation: observation() }), { code: "asset_operation_active" });
  assert.equal(store.currentAssetBinding(first.alias).generation, first.generation);
  assert.equal(bind().generation, first.generation, "a fresh observation of the same connection remains harmless");
  const lease = store.acquireAssetExecution([{ alias: first.alias, binding: first }], "protected-backup");
  store.releaseAssetExecution(lease);
});

test("first identity observation permits its queued audit but cannot move an active alias lease", () => {
  const queued = store.createAuditJob({ action: "agentlessAudit", hostAlias: "host-one", profileId: "basic_linux", requestKey: "initial" });
  assert.equal(bind().generation, 1);
  store.finishAuditJob(queued.job.id, { ok: true });
  const lease = store.acquireAssetExecution([{ alias: "unbound-host", binding: null }]);
  assert.throws(() => bind("unbound-host"), { code: "asset_operation_active" });
  assert.equal(store.currentAssetBinding("unbound-host"), null);
  store.releaseAssetExecution(lease);
  assert.equal(bind("unbound-host").generation, 1);
});

test("transaction creation rejects stale generation and connection snapshots atomically", () => {
  const first = bind();
  const nextConnection = identity.assetConnectionId({ address: "192.0.2.21", port: 22, user: "audit" });
  const current = store.recordAssetObservation({ alias: first.alias, connectionId: nextConnection, observation: observation() });
  for (const stale of [first, { ...current, connectionId: first.connectionId }]) {
    assert.throws(() => transaction("must-not-be-created", stale), { code: "asset_binding_stale" });
    assert.equal(store.getRemediationTransaction("must-not-be-created"), null);
  }
  assert.equal(transaction("current-snapshot", current).status, "preparing");
});

test("dead read-only leases are recovered before queue, rebind and mutation admission", () => {
  const first = bind(); const peer = bind("host-two");
  deadLease(store.acquireAssetExecution([{ alias: first.alias, binding: first }]));
  const queued = store.createAuditJob({ action: "agentlessAudit", hostAlias: peer.alias, profileId: "basic_linux", requestKey: "retry" });
  assert.equal(queued.created, true); assert.equal(leaseCount(), 0);
  store.finishAuditJob(queued.job.id, { ok: true });
  deadLease(store.acquireAssetExecution([{ alias: first.alias, binding: first }]));
  const changed = store.recordAssetObservation({ alias: first.alias,
    connectionId: identity.assetConnectionId({ address: "192.0.2.21", port: 22, user: "audit" }), observation: observation() });
  assert.equal(changed.generation, 2); assert.equal(leaseCount(), 0);
  deadLease(store.acquireAssetExecution([{ alias: peer.alias, binding: peer }]));
  assert.equal(transaction("after-dead-audit", peer).status, "preparing");
  assert.equal(leaseCount(), 0);
});

test("read-only lease recovery preserves interrupted target mutations across aliases", () => {
  const first = bind(); const peer = bind("host-two");
  transaction("interrupted-change", first);
  deadLease(store.acquireAssetExecution([{ alias: first.alias, binding: first }], "interrupted-change"));
  store.updateRemediationTransaction("interrupted-change", { status: "interrupted", backupRef: "/fixture/archive" });
  assert.throws(() => store.createAuditJob({ action: "agentlessAudit", hostAlias: peer.alias, profileId: "basic_linux", requestKey: "blocked" }), { code: "asset_operation_active" });
  assert.equal(leaseCount(), 1);
  assert.equal(store.getRemediationTransaction("interrupted-change").status, "interrupted");
});

test("closeout and remediation block each other atomically across known aliases", () => {
  const first = bind(); const peer = bind("host-two");
  const closeout = store.claimHostCloseout(closeoutInput());
  assert.equal(store.hasUnresolvedHostCloseout(first.alias), true);
  assert.throws(() => transaction("blocked-by-closeout", first), { code: "host_operation_active" });
  assert.throws(() => store.acquireAssetExecution([{ alias: first.alias, binding: first }]), { code: "host_operation_active" });
  assert.throws(() => rebind(first.alias, first, observation("2")), { code: "host_operation_active" });
  assert.throws(() => store.claimHostCloseout(closeoutInput(first.alias, "b".repeat(64))), { code: "host_operation_active" });
  store.recordHostCloseoutResult(closeout.credentialId, closeout.claim, "not_changed");
  store.releaseHostCloseout(closeout.credentialId, closeout.claim);
  transaction("active-peer-change", first);
  assert.throws(() => store.claimHostCloseout(closeoutInput(peer.alias)), { code: "host_operation_active" });
});

test("unresolved closeout keeps a stale execution barrier until recovery finishes", () => {
  const first = bind(); bind("host-two");
  const closeout = store.claimHostCloseout(closeoutInput());
  // Simulate an old controller snapshot with both records present. New claims
  // now prevent this overlap; migration/restart must still preserve its guard.
  databaseOperation((database) => database.prepare("INSERT INTO asset_execution_leases VALUES (?, ?, ?, ?, ?)")
    .run(first.assetId, "legacy-overlap", first.alias, currentOperationOwner, new Date().toISOString()));
  deadLease("legacy-overlap");
  assert.throws(() => store.createAuditJob({ action: "agentlessAudit", hostAlias: first.alias, profileId: "basic_linux", requestKey: "blocked" }), { code: "host_operation_active" });
  assert.equal(leaseCount(), 1);
  store.recordHostCloseoutResult(closeout.credentialId, closeout.claim, "not_changed");
  store.releaseHostCloseout(closeout.credentialId, closeout.claim);
  assert.equal(store.createAuditJob({ action: "agentlessAudit", hostAlias: first.alias, profileId: "basic_linux", requestKey: "recovered" }).created, true);
  assert.equal(leaseCount(), 0);
});

test("an alias-keyed lease cannot be bypassed after identity registration", () => {
  const first = bind(); const peer = bind("host-two");
  const lease = store.acquireAssetExecution([{ alias: first.alias, binding: first }]);
  databaseOperation((database) => database.prepare("UPDATE asset_execution_leases SET resource_id = ? WHERE operation_id = ?").run(`alias:${first.alias}`, lease));
  assert.throws(() => store.acquireAssetExecution([{ alias: peer.alias, binding: peer }]), { code: "asset_operation_active" });
  store.releaseAssetExecution(lease);
});

test("audit queues, running audits and remediation share an asset lock across aliases", () => {
  const one = bind(); const two = bind("host-two");
  const queued = store.createAuditJob({ action: "agentlessAudit", hostAlias: one.alias, profileId: "basic_linux", requestKey: "one" });
  const competing = store.createAuditJob({ action: "collectFacts", hostAlias: two.alias, profileId: "basic_linux", requestKey: "two" });
  assert.equal(competing.created, false); assert.equal(competing.matches, false); assert.equal(competing.job.id, queued.job.id);
  assert.throws(() => transaction("blocked-by-job", two), { code: "asset_operation_active" });
  store.finishAuditJob(queued.job.id, { ok: true });
  const lease = store.acquireAssetExecution([{ alias: one.alias, binding: one }]);
  assert.throws(() => store.acquireAssetExecution([{ alias: two.alias, binding: two }]), { code: "asset_operation_active" });
  assert.throws(() => transaction("blocked-by-execution", two), { code: "asset_operation_active" });
  assert.throws(() => rebind(one.alias, one, observation("3")), { code: "asset_operation_active" });
  store.releaseAssetExecution(lease);
  transaction("active-change", one);
  assert.equal(store.hasActiveRemediationForHost(two.alias), true);
  assert.throws(() => store.acquireAssetExecution([{ alias: two.alias, binding: two }]), { code: "asset_operation_active" });
  const own = store.acquireAssetExecution([{ alias: one.alias, binding: one }], "active-change");
  store.releaseAssetExecution(own);
});

test("a newer completed mutation through another alias blocks stale rollback even after that alias is rebound", () => {
  const one = bind(); const two = bind("host-two");
  transaction("older", one); store.updateRemediationTransaction("older", { status: "applied", backupRef: "/fixture/older" });
  transaction("newer", two); store.updateRemediationTransaction("newer", { status: "applied", backupRef: "/fixture/newer" });
  rebind(two.alias, two, observation("3"));
  assert.throws(() => store.claimRemediationRollback("older"), { code: "newer_remediation_exists" });
  assert.equal(store.getRemediationTransaction("older").status, "applied");
});

test("launch identity is published before visibility and never inferred from a later alias binding", () => {
  const first = bind(); const stage = path.join(directory, "stage"); mkdirSync(stage);
  const file = "host-one-basic_linux-run-fixture.json";
  writeFileSync(path.join(stage, file), JSON.stringify({ inventoryHost: first.alias, mode: "agentless", scanner: { error: "Scanner unavailable", partial: true }, findings: [] }));
  rebind(first.alias, first, observation("2"));
  publishCapturedAssetReports(stage, new Map([[file, first]]));
  const savedReport = JSON.parse(readFileSync(path.join(process.env.HCP_REPORTS_DIR, file), "utf8"));
  assert.equal(savedReport.assetBinding.assetId, first.assetId);
  assert.equal(savedReport.scanner.error, "Scanner unavailable", "failed scanner diagnostics are retained");
  assert.throws(() => publishCapturedAssetReports(stage, new Map([[file, first]])), /уже существует/);
  rmSync(path.join(stage, file)); symlinkSync(path.join(process.env.HCP_REPORTS_DIR, file), path.join(stage, file));
  assert.throws(() => publishCapturedAssetReports(stage, new Map([[file, first]])), /ELOOP/);
});

test("rebound alias cannot merge old findings or verify an old plan with a different machine's pass", () => {
  assert.equal(explicitInventoryConnectionId("host-one"), connectionId, "the native resolver must see the isolated fixture connection");
  const first = bind(); const oldReport = save("old", first); save("legacy", null);
  const oldBytes = readFileSync(oldReport.path);
  assert.ok(buildHostCorrelation("host-one").findings.some((item) => item.sources.some((source) => source.reportId === "old")));
  const second = rebind("host-one", first, observation("2"));
  const fresh = save("fresh", second, "passed");
  assert.equal(reports.reportScopesCompatible(oldReport, fresh), false);
  const correlation = buildHostCorrelation("host-one");
  assert.equal(correlation.findings.length, 0);
  assert.equal(correlation.coverage.find((entry) => entry.reportId === "old").auditEvidence, false);
  assert.ok(correlation.coverage.find((entry) => entry.reportId === "legacy").coverageIssues.includes("legacy_identity_unknown"));
  assert.throws(() => assertPlanVerification({ hostAlias: "host-one", updatedAt: new Date(Date.now() - 1000).toISOString(), evidence: [{ reportId: "old", findingId: "fixture", source: "agentless", reportSha256: reports.hashAnsibleReport("old") }] }, fresh), /Не подтверждено совпадение/);
  assert.deepEqual(readFileSync(oldReport.path), oldBytes);
  assert.equal(reports.readAnsibleReport("legacy").assetBinding, null);
});
