import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { promisify } from "node:util";
import { after, afterEach, beforeEach, test } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["state-store", "operation-owner"]);
const store = await import(compiled.url("state-store"));
const owner = await import(compiled.url("operation-owner"));
const execute = promisify(execFile);
const original = { state: process.env.HCP_STATE_DIR, key: process.env.HCP_AUDIT_HMAC_KEY };
let directory;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-operation-recovery-"));
  process.env.HCP_STATE_DIR = directory;
  process.env.HCP_AUDIT_HMAC_KEY = "recovery-tests-only";
});
afterEach(() => rmSync(directory, { recursive: true, force: true }));
after(() => {
  for (const [name, value] of [["HCP_STATE_DIR", original.state], ["HCP_AUDIT_HMAC_KEY", original.key]]) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
  rmSync(compiled.directory, { recursive: true, force: true });
});
const host = "fixture-host";
const transaction = id => ({ id, hostAlias: host, action: "closePort", profileId: "basic_linux", reason: "fixture",
  parameters: { target_port: "8080", _hcp_connection: JSON.stringify({ alias: host, address: "192.0.2.10", user: "root", port: 22 }) } });
const evidence = id => ({ confirmedHost: host, confirmedOperation: id, processesStopped: true, outcomeVerified: true,
  expectedRecoveryVersion: store.getRemediationTransaction(id)?.recoveryVersion,
  inspectionNote: "Independent console checked firewall and all previous worker processes.", evidenceReference: "incident:recovery-fixture" });
async function child(code) {
  return execute(process.execPath, ["--input-type=module", "-e", `const store = await import(${JSON.stringify(compiled.url("state-store"))});\n${code}`],
    { env: { ...process.env }, timeout: 10000 });
}
async function interrupted(id, phase = "preparing") {
  await child(`store.createRemediationTransaction(${JSON.stringify(transaction(id))});
    ${phase === "backed_up" ? `store.updateRemediationTransaction(${JSON.stringify(id)}, {status:"backed_up",backupRef:"/var/lib/hcp-backups/${id}/firewall-state.tar.gz"});` : ""}
    ${phase === "rolling_back" ? `store.updateRemediationTransaction(${JSON.stringify(id)}, {status:"applied",backupRef:"/var/lib/hcp-backups/${id}/firewall-state.tar.gz"}); store.claimRemediationRollback(${JSON.stringify(id)});` : ""}
    // Simulate a worker exiting without completing its remote-operation path.
    process.exit(0);`);
}

test("process restart marks each unfinished firewall phase interrupted without unlocking or retrying it", async () => {
  for (const phase of ["preparing", "backed_up", "rolling_back"]) {
    const id = `txn-crashed-${phase.replaceAll("_", "-")}`;
    await interrupted(id, phase);
    const value = store.listRemediationTransactions().find(item => item.id === id);
    assert.equal(value.status, "interrupted");
    assert.equal(value.recoveryRequired, true);
    assert.equal(store.hasActiveRemediationForHost(host), true);
    assert.throws(() => store.createRemediationTransaction(transaction(`txn-competing-${phase}`)), /UNIQUE constraint/);
    assert.throws(() => store.claimRemediationRollback(id), { code: "rollback_not_available" });
    assert.throws(() => store.cancelRemediationTransaction(id, host), { code: "cancel_not_available" });
    store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "restored_manually" });
    assert.equal(store.hasActiveRemediationForHost(host), false);
  }
  assert.equal(store.verifyAuditChain().valid, true);
});

test("live owners, legacy rows and different containers cannot be mistaken for a completed remote operation", () => {
  const id = "txn-owner-validation";
  store.createRemediationTransaction(transaction(id));
  assert.equal(store.listRemediationTransactions()[0].status, "preparing");
  assert.throws(() => store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "not_applied" }), { code: "operation_owner_live" });
  const db = new DatabaseSync(path.join(directory, "hcp.sqlite"));
  for (const serialized of [null, JSON.stringify({ ...JSON.parse(owner.currentOperationOwner), host: "previous-container" })]) {
    db.prepare("UPDATE remediation_transactions SET owner_json=?, recovery_version=NULL WHERE id=?").run(serialized, id);
    const value = store.listRemediationTransactions()[0];
    assert.equal(value.status, "preparing");
    assert.equal(value.recoveryRequired, true);
    assert.equal(value.recoveryVersion, `legacy-remediation:${id}`);
    assert.throws(() => store.reconcileRemediationTransaction(id, { resolution: "not_applied" }), { code: "recovery_confirmation_required" });
  }
  db.close();
  assert.equal(store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "not_applied" }).status, "cancelled");
  assert.equal(store.hasActiveRemediationForHost(host), false);
});

test("owner identity distinguishes PID reuse and treats malformed or different boots conservatively", () => {
  const current = JSON.parse(owner.currentOperationOwner);
  assert.equal(owner.operationOwnerState(owner.currentOperationOwner), "live");
  assert.equal(owner.operationOwnerState("invalid"), "unknown");
  assert.equal(owner.operationOwnerState(JSON.stringify({ ...current, boot: "other-boot" })), "unknown");
  if (current.boot && current.start) assert.equal(owner.operationOwnerState(JSON.stringify({ ...current, start: `${current.start}0` })), "dead");
});

test("old unresolved transactions stay visible ahead of newer completed work", () => {
  const id = "txn-older-visible-recovery";
  store.createRemediationTransaction(transaction(id));
  for (let index = 0; index < 12; index++) {
    const completedId = `txn-completed-${index}`;
    store.createRemediationTransaction({ ...transaction(completedId), hostAlias: `completed-host-${index}` });
    store.updateRemediationTransaction(completedId, { status: "applied" });
  }
  const db = new DatabaseSync(path.join(directory, "hcp.sqlite"));
  db.prepare("UPDATE remediation_transactions SET owner_json=NULL, created_at='2000-01-01T00:00:00.000Z' WHERE id=?").run(id);
  db.close();
  assert.equal(store.listRemediationTransactions(5)[0].id, id);
  assert.equal(store.listRemediationTransactions(5)[0].recoveryRequired, true);
});

test("recovery requires exact confirmations, stopped processes, independent evidence and the permitted phase", async () => {
  const id = "txn-attestation-checks";
  await interrupted(id, "backed_up");
  for (const change of [{ confirmedHost: "other" }, { confirmedOperation: "other" }, { expectedRecoveryVersion: undefined }, { processesStopped: false }, { outcomeVerified: false }, { inspectionNote: "short" }, { evidenceReference: "" }]) {
    assert.throws(() => store.reconcileRemediationTransaction(id, { ...evidence(id), ...change, resolution: "restored_manually" }), /./);
    assert.equal(store.hasActiveRemediationForHost(host), true);
  }
  assert.throws(() => store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "not_applied" }), { code: "recovery_resolution_invalid" });
  assert.throws(() => store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "prepare_rollback" }), { code: "recovery_resolution_invalid" });
});

test("a crash between remote backup creation and DB checkpoint can prepare a separately claimed rollback", async () => {
  const id = "txn-backup-before-checkpoint";
  await interrupted(id);
  const value = store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "prepare_rollback", backupVerified: true });
  assert.equal(value.status, "recovery_ready");
  assert.equal(value.backupRef, `/var/lib/hcp-backups/${id}/firewall-state.tar.gz`);
  assert.equal(store.hasActiveRemediationForHost(host), true);
  assert.throws(() => store.createRemediationTransaction(transaction("txn-new-during-recovery")), /UNIQUE constraint/);
  assert.equal(store.claimRemediationRollback(id).status, "rolling_back");
  assert.throws(() => store.claimRemediationRollback(id), { code: "rollback_not_available" });
  // The rollback executor retains this lock on failure. It can then be retried
  // separately or independently restored and reconciled by an operator.
  store.updateRemediationTransaction(id, { status: "recovery_ready", error: "fixture reload failure" });
  assert.equal(store.getRemediationTransaction(id).recoveryRequired, true);
  assert.equal(store.hasActiveRemediationForHost(host), true);
  assert.equal(store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "restored_manually" }).status, "rolled_back");
  assert.equal(store.verifyAuditChain().valid, true);
});

test("legacy backups without a saved connection cannot be prepared for automatic rollback", async () => {
  const id = "txn-legacy-no-identity";
  await child(`store.createRemediationTransaction(${JSON.stringify({ ...transaction(id), parameters: {} })});`);
  assert.throws(() => store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "prepare_rollback", backupVerified: true }), { code: "legacy_backup_identity_missing" });
  assert.equal(store.hasActiveRemediationForHost(host), true);
});

test("reconciliation and recovered rollback keep reverse chronological restoration mandatory", () => {
  const oldId = "txn-older-recovery";
  const newId = "txn-newer-recovery";
  for (const id of [oldId, newId]) {
    store.createRemediationTransaction(transaction(id));
    store.updateRemediationTransaction(id, { status: "applied", backupRef: `/var/lib/hcp-backups/${id}/firewall-state.tar.gz` });
  }
  // A legacy/imported unfinished record must not bypass newer retained changes.
  const db = new DatabaseSync(path.join(directory, "hcp.sqlite"));
  db.prepare("UPDATE remediation_transactions SET status='interrupted', owner_json=NULL WHERE id=?").run(oldId);
  for (const resolution of ["restored_manually", "prepare_rollback"]) {
    assert.throws(() => store.reconcileRemediationTransaction(oldId, { ...evidence(oldId), resolution, backupVerified: true }), { code: "newer_remediation_exists" });
  }
  db.prepare("UPDATE remediation_transactions SET status='recovery_ready' WHERE id=?").run(oldId);
  assert.throws(() => store.claimRemediationRollback(oldId), { code: "newer_remediation_exists" });
  db.close();
});

test("two recovery processes cannot both cancel a stale operation or lose its audit chain", async () => {
  const id = "txn-concurrent-recovery";
  await interrupted(id);
  const code = `try { store.reconcileRemediationTransaction(${JSON.stringify(id)}, ${JSON.stringify({ ...evidence(id), resolution: "not_applied" })}); process.stdout.write("resolved"); }
    catch (error) { process.stdout.write(error.code); }`;
  const results = await Promise.all([child(code), child(code)]);
  assert.deepEqual(results.map(value => value.stdout).sort(), ["recovery_not_available", "resolved"]);
  assert.equal(store.verifyAuditChain().valid, true);
});

test("a recovery snapshot is consumed atomically and cannot authorize a later crashed rollback attempt", async () => {
  const id = "txn-recovery-version-fencing";
  await interrupted(id);
  const oldAttestation = { ...evidence(id), resolution: "prepare_rollback", backupVerified: true };
  const code = `try { store.reconcileRemediationTransaction(${JSON.stringify(id)}, ${JSON.stringify(oldAttestation)}); process.stdout.write("prepared"); }
    catch (error) { process.stdout.write(error.code); }`;
  const results = await Promise.all([child(code), child(code)]);
  assert.deepEqual(results.map(value => value.stdout).sort(), ["prepared", "recovery_version_stale"]);
  const preparedVersion = store.getRemediationTransaction(id).recoveryVersion;
  assert.notEqual(preparedVersion, oldAttestation.expectedRecoveryVersion);
  assert.equal(store.listRemediationTransactions()[0].recoveryVersion, preparedVersion);
  assert.equal(store.listRemediationTransactions()[0].recoveryVersion, preparedVersion);
  await child(`store.claimRemediationRollback(${JSON.stringify(id)}); process.exit(0);`);
  assert.equal(store.listRemediationTransactions()[0].status, "interrupted");
  assert.notEqual(store.getRemediationTransaction(id).recoveryVersion, preparedVersion);
  assert.throws(() => store.reconcileRemediationTransaction(id, oldAttestation), { code: "recovery_version_stale" });
  assert.equal(store.hasActiveRemediationForHost(host), true);
  store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "restored_manually" });
  assert.equal(store.verifyAuditChain().valid, true);
});

test("failed audit persistence cannot release an unresolved host", async () => {
  const id = "txn-audit-atomic-recovery";
  await interrupted(id);
  const db = new DatabaseSync(path.join(directory, "hcp.sqlite"));
  db.exec("CREATE TRIGGER reject_recovery_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END;");
  assert.throws(() => store.reconcileRemediationTransaction(id, { ...evidence(id), resolution: "not_applied" }), /fixture audit failure/);
  assert.equal(store.getRemediationTransaction(id).status, "preparing");
  db.close();
});
