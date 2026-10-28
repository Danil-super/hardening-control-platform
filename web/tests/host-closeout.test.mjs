import assert from "node:assert/strict";
import childProcess, { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { promisify } from "node:util";
import { syncBuiltinESMExports } from "node:module";
import { after, afterEach, beforeEach, test } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

// Real SQLite, inventory, credential storage and subprocess JSON boundaries.
// Only the Python SSH helper is a local fixture; it never opens a connection.
const compiled = compileServerModules(["host-closeout", "state-store", "host-credentials", "inventory-closeout"]);
const closeout = await import(compiled.url("host-closeout"));
const store = await import(compiled.url("state-store"));
const credentials = await import(compiled.url("host-credentials"));
const inventory = await import(compiled.url("inventory-closeout"));
const execute = promisify(execFile);
const original = { cwd: process.cwd(), state: process.env.HCP_STATE_DIR, key: process.env.HCP_AUDIT_HMAC_KEY };
const host = { alias: "fixture-closeout", address: "192.0.2.10", user: "fixture", port: 22 };
let directory, id, fingerprint;

function setRemoteResult(result) {
  writeFileSync(path.join(directory, "ansible/scripts/hcp-ssh-revoke.py"), `import json, pathlib, sys
request = json.load(sys.stdin)
assert request["address"] == "192.0.2.10"
with pathlib.Path(${JSON.stringify(path.join(directory, "invocations"))}).open("a") as output:
    output.write("called\\n")
print(${JSON.stringify(JSON.stringify(result))})
`);
}
function countInvocations() {
  const file = path.join(directory, "invocations");
  return existsSync(file) ? readFileSync(file, "utf8").trim().split("\n").length : 0;
}
function enroll() {
  const prepared = credentials.beginHostCredential(host);
  try {
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", prepared.keyPath]);
    const publicKey = readFileSync(prepared.keyPath + ".pub", "utf8").trim();
    const nextFingerprint = execFileSync("ssh-keygen", ["-lf", prepared.keyPath, "-E", "sha256"], { encoding: "utf8" }).split(/\s+/)[1];
    credentials.markHostCredentialVerified(prepared.credential.id, host, publicKey, nextFingerprint);
    credentials.markHostCredentialSudoOnDemand(prepared.credential.id, host);
    writeFileSync(path.join(directory, "ansible/inventory.ini"), `[fixture]\n${host.alias} ansible_host=${host.address} ansible_user=${host.user} ansible_port=22 hcp_ssh_credential_id=${prepared.credential.id}\n`);
    return { id: prepared.credential.id, fingerprint: nextFingerprint };
  } finally { prepared.release(); }
}
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-closeout-recovery-"));
  mkdirSync(path.join(directory, "web"));
  mkdirSync(path.join(directory, "ansible/scripts"), { recursive: true });
  process.chdir(path.join(directory, "web"));
  process.env.HCP_STATE_DIR = path.join(directory, "state");
  process.env.HCP_AUDIT_HMAC_KEY = "closeout-tests-only";
  ({ id, fingerprint } = enroll());
  setRemoteResult({ ok: true, status: "removed" });
});
afterEach(() => { process.chdir(original.cwd); rmSync(directory, { recursive: true, force: true }); });
after(() => {
  for (const [name, value] of [["HCP_STATE_DIR", original.state], ["HCP_AUDIT_HMAC_KEY", original.key]]) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
  rmSync(compiled.directory, { recursive: true, force: true });
});
const evidence = () => ({ confirmedHost: host.alias, confirmedOperation: id, processesStopped: true, outcomeVerified: true,
  expectedRecoveryVersion: closeout.hostCloseoutStatus(host.alias).recoveryVersion,
  inspectionNote: "Console inspected the exact HCP key, authorized_keys and managed sudoers file.", evidenceReference: "incident:closeout-fixture" });
const absent = () => ({ ...evidence(), resolution: "remote_absent", remoteKeyAbsent: true, sudoRuleResolved: true });
function claimInput() { return { credentialId: id, identity: host, fingerprint }; }
async function child(code) {
  return execute(process.execPath, ["--input-type=module", "-e", `
    const store = await import(${JSON.stringify(compiled.url("state-store"))});
    const credentials = await import(${JSON.stringify(compiled.url("host-credentials"))});
    ${code}`], { cwd: process.cwd(), env: { ...process.env }, timeout: 10000 });
}
async function crashCloseout(status) {
  await child(`const record = store.claimHostCloseout(${JSON.stringify(claimInput())});
    credentials.acquireHostCredentialCloseoutLock(record.credentialId);
    ${status ? `store.recordHostCloseoutResult(record.credentialId, record.claim, ${JSON.stringify(status)});` : ""}
    process.exit(0);`);
}

test("successful closeout checkpoints remote revocation before local cleanup and allows later enrollment", async () => {
  const result = await closeout.decommissionHost(host.alias);
  assert.equal(result.ok, true);
  assert.equal(store.getHostCloseout(id).status, "completed");
  assert.equal(store.getHostCloseout(id).claim, null);
  assert.equal(existsSync(credentials.credentialDirectory(id)), false);
  assert.equal(inventory.readInventoryCloseoutHost(host.alias), null);
  assert.equal(countInvocations(), 1);
  const next = enroll();
  assert.equal(next.id, id);
  assert.notEqual(next.fingerprint, fingerprint);
  await closeout.decommissionHost(host.alias);
  assert.equal(countInvocations(), 2);
  assert.equal(store.verifyAuditChain().valid, true);
});

test("known partial key removal survives Python JSON and is recovered without another SSH attempt", async () => {
  setRemoteResult({ ok: false, error: "unsafe_sudo_rule", keyRemoved: true });
  await assert.rejects(closeout.decommissionHost(host.alias), error => error.code === "closeout_recovery_required" && error.remoteRevoked === true);
  assert.equal(store.getHostCloseout(id).status, "remote_partial");
  assert.equal(existsSync(credentials.credentialKeyPath(id)), true);
  assert.equal(closeout.hostCloseoutStatus(host.alias).recoveryRequired, true);
  assert.throws(() => closeout.recoverHostCloseout(host.alias, id, { ...evidence(), resolution: "not_changed" }), { code: "recovery_resolution_invalid" });
  assert.throws(() => closeout.recoverHostCloseout(host.alias, id, { ...absent(), sudoRuleResolved: false }), { code: "recovery_inspection_required" });
  assert.equal(closeout.recoverHostCloseout(host.alias, id, absent()).completed, true);
  assert.equal(countInvocations(), 1);
  assert.equal(store.getHostCloseout(id).status, "completed");
  assert.equal(inventory.readInventoryCloseoutHost(host.alias), null);
});

test("unknown outcomes remain locked until attested; a known false is preserved as a safe negative", async () => {
  setRemoteResult({ ok: false, error: "revocation_failed" });
  await assert.rejects(closeout.decommissionHost(host.alias), error => error.code === "closeout_recovery_required" && !("remoteRevoked" in error));
  assert.equal(store.getHostCloseout(id).status, "unknown");
  await assert.rejects(closeout.decommissionHost(host.alias), { code: "closeout_recovery_required" });
  assert.throws(() => credentials.beginHostCredential(host), { code: "credential_busy" });
  assert.throws(() => closeout.recoverHostCloseout(host.alias, id, { resolution: "not_changed" }), { code: "recovery_confirmation_required" });
  assert.equal(countInvocations(), 1);
  assert.equal(closeout.recoverHostCloseout(host.alias, id, { ...evidence(), resolution: "not_changed" }).completed, false);
  assert.equal(store.getHostCloseout(id).status, "not_changed");
  assert.equal(countInvocations(), 1);
  setRemoteResult({ ok: false, error: "unsafe_authorized_keys", keyRemoved: false });
  await assert.rejects(closeout.decommissionHost(host.alias), error => error.remoteRevoked === false);
  assert.equal(store.getHostCloseout(id).status, "not_changed");
  assert.equal(closeout.hostCloseoutStatus(host.alias).recoveryRequired, false);
});

test("proved pre-dispatch failure permits a separate normal retry without a false recovery requirement", async () => {
  setRemoteResult({ ok: false, error: "host_not_trusted", keyRemoved: false });
  await assert.rejects(closeout.decommissionHost(host.alias), error => error.code === "host_not_trusted" && error.remoteRevoked === false);
  assert.equal(store.getHostCloseout(id).status, "not_changed");
  assert.equal(closeout.hostCloseoutStatus(host.alias).recoveryRequired, false);
  assert.equal(existsSync(credentials.credentialKeyPath(id)), true);
  setRemoteResult({ ok: true, status: "removed" });
  assert.equal((await closeout.decommissionHost(host.alias)).ok, true);
  assert.equal(countInvocations(), 2);
});

test("a real helper spawn failure proves no remote work and permits a separate retry", async (context) => {
  const nativeSpawn = childProcess.spawn;
  const mocked = context.mock.method(childProcess, "spawn", (_command, args, options) => nativeSpawn(path.join(directory, "missing-python"), args, options));
  syncBuiltinESMExports();
  try {
    await assert.rejects(closeout.decommissionHost(host.alias), error => error.code === "ssh_dependency_missing" && error.remoteRevoked === false);
    assert.equal(store.getHostCloseout(id).status, "not_changed");
    assert.equal(closeout.hostCloseoutStatus(host.alias).recoveryRequired, false);
    assert.equal(countInvocations(), 0);
    assert.equal(existsSync(credentials.credentialKeyPath(id)), true);
  } finally { mocked.mock.restore(); syncBuiltinESMExports(); }
  assert.equal((await closeout.decommissionHost(host.alias)).ok, true);
  assert.equal(countInvocations(), 1);
});

test("a child error after successful helper spawn retains an unknown remote outcome", async (context) => {
  const nativeSpawn = childProcess.spawn;
  const mocked = context.mock.method(childProcess, "spawn", (...args) => {
    const child = nativeSpawn(...args);
    child.once("spawn", () => queueMicrotask(() => {
      child.emit("error", Object.assign(new Error("fixture post-spawn process error"), { code: "EPERM" }));
      child.kill("SIGKILL");
    }));
    return child;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(closeout.decommissionHost(host.alias), error => error.code === "closeout_recovery_required" && !("remoteRevoked" in error));
    assert.equal(store.getHostCloseout(id).status, "unknown");
    assert.equal(existsSync(credentials.credentialKeyPath(id)), true);
    await assert.rejects(closeout.decommissionHost(host.alias), { code: "closeout_recovery_required" });
  } finally { mocked.mock.restore(); syncBuiltinESMExports(); }
});

test("a stale closeout attestation cannot unlock a later unknown attempt for the same credential", async () => {
  setRemoteResult({ ok: false, error: "revocation_failed" });
  await assert.rejects(closeout.decommissionHost(host.alias), { code: "closeout_recovery_required" });
  const firstAttestation = { ...evidence(), resolution: "not_changed" };
  closeout.recoverHostCloseout(host.alias, id, firstAttestation);
  await assert.rejects(closeout.decommissionHost(host.alias), { code: "closeout_recovery_required" });
  const nextVersion = store.getHostCloseout(id).recoveryVersion;
  assert.notEqual(nextVersion, firstAttestation.expectedRecoveryVersion);
  assert.equal(closeout.hostCloseoutStatus(host.alias).recoveryVersion, nextVersion);
  assert.equal(closeout.hostCloseoutStatus(host.alias).recoveryVersion, nextVersion);
  assert.throws(() => closeout.recoverHostCloseout(host.alias, id, firstAttestation), { code: "recovery_version_stale" });
  assert.equal(store.getHostCloseout(id).status, "unknown");
  assert.equal(store.getHostCloseout(id).recoveryVersion, nextVersion);
  assert.equal(countInvocations(), 2);
});

test("consumed recovery snapshots cannot claim again even when the current owner is in an unknown container", async () => {
  await crashCloseout("unknown");
  const snapshot = evidence();
  const first = store.claimHostCloseout(claimInput(), snapshot);
  const db = new DatabaseSync(path.join(process.env.HCP_STATE_DIR, "hcp.sqlite"));
  const foreignOwner = { ...first, owner: JSON.stringify({ ...JSON.parse(first.owner), host: "other-container" }) };
  db.prepare("UPDATE runtime_settings SET setting_value=? WHERE setting_key=?").run(JSON.stringify(foreignOwner), `host_closeout:${id}`);
  db.close();
  assert.throws(() => store.claimHostCloseout(claimInput(), snapshot), { code: "recovery_version_stale" });
  assert.equal(store.getHostCloseout(id).claim, first.claim);
  store.releaseHostCloseout(id, first.claim);
});

test("a legacy lock snapshot can be claimed by only one concurrent recovery worker", async () => {
  mkdirSync(path.join(credentials.hostKeysDirectory(), `${id}.decommission-lock`));
  const snapshot = { ...evidence(), resolution: "not_changed" };
  assert.equal(snapshot.expectedRecoveryVersion, `legacy-closeout:${id}`);
  const code = `const closeout = await import(${JSON.stringify(compiled.url("host-closeout"))});
    try { closeout.recoverHostCloseout(${JSON.stringify(host.alias)}, ${JSON.stringify(id)}, ${JSON.stringify(snapshot)}); process.stdout.write("resolved"); }
    catch (error) { process.stdout.write(error.code); }`;
  const results = await Promise.all([child(code), child(code)]);
  assert.deepEqual(results.map(value => value.stdout).sort(), ["recovery_version_stale", "resolved"]);
  assert.notEqual(store.getHostCloseout(id).recoveryVersion, snapshot.expectedRecoveryVersion);
  assert.equal(countInvocations(), 0);
  assert.equal(store.verifyAuditChain().valid, true);
});

test("process death leaves durable and filesystem evidence and has a supported manual recovery", async () => {
  await crashCloseout("remote_partial");
  assert.equal(credentials.hasHostCredentialCloseoutLock(id), true);
  assert.equal(closeout.hostCloseoutStatus(host.alias).ownerLive, false);
  await assert.rejects(closeout.decommissionHost(host.alias), { code: "closeout_recovery_required" });
  assert.throws(() => closeout.recoverHostCloseout(host.alias, id, { ...absent(), processesStopped: false }), { code: "recovery_inspection_required" });
  assert.equal(closeout.recoverHostCloseout(host.alias, id, absent()).completed, true);
  assert.equal(credentials.hasHostCredentialCloseoutLock(id), false);
  assert.equal(countInvocations(), 0);
  assert.equal(store.verifyAuditChain().valid, true);
});

test("live durable and filesystem lock owners cannot be reclaimed", () => {
  const record = store.claimHostCloseout(claimInput());
  const release = credentials.acquireHostCredentialCloseoutLock(id);
  try {
    assert.throws(() => closeout.recoverHostCloseout(host.alias, id, absent()), { code: "operation_owner_live" });
    assert.throws(() => credentials.releaseInterruptedHostCloseoutLock(id), { code: "operation_owner_live" });
    assert.equal(credentials.hasHostCredentialCloseoutLock(id), true);
  } finally { release(); store.releaseHostCloseout(id, record.claim); }
});

test("old empty closeout locks require inspected recovery and are never cleared by a normal retry", async () => {
  mkdirSync(path.join(credentials.hostKeysDirectory(), `${id}.decommission-lock`));
  await assert.rejects(closeout.decommissionHost(host.alias), { code: "closeout_recovery_required" });
  assert.equal(store.getHostCloseout(id), null);
  assert.throws(() => closeout.recoverHostCloseout(host.alias, id, { resolution: "not_changed" }), { code: "recovery_confirmation_required" });
  closeout.recoverHostCloseout(host.alias, id, { ...evidence(), resolution: "not_changed" });
  assert.equal(credentials.hasHostCredentialCloseoutLock(id), false);
  assert.equal(countInvocations(), 0);
});

test("known remote success recovers local cleanup failures without needing a usable private key", async () => {
  const extra = path.join(credentials.credentialDirectory(id), "unexpected-backup");
  writeFileSync(extra, "fixture");
  await assert.rejects(closeout.decommissionHost(host.alias), { code: "closeout_recovery_required" });
  assert.equal(store.getHostCloseout(id).status, "remote_revoked");
  rmSync(extra);
  rmSync(credentials.credentialKeyPath(id));
  assert.equal(closeout.recoverHostCloseout(host.alias, id, absent()).completed, true);
  assert.equal(countInvocations(), 1);
  assert.equal(existsSync(credentials.credentialDirectory(id)), false);
});

test("a crash after local deletion or inventory removal remains recoverable through its saved record", async () => {
  await crashCloseout("remote_revoked");
  const credentialDirectory = credentials.credentialDirectory(id);
  for (const name of readdirSync(credentialDirectory)) rmSync(path.join(credentialDirectory, name));
  inventory.removeInventoryCloseoutHost(host.alias);
  assert.equal(closeout.hostCloseoutStatus(host.alias).recoveryRequired, true);
  assert.equal(closeout.hostCloseoutStatus(host.alias).credentialId, id);
  closeout.recoverHostCloseout(host.alias, id, absent());
  assert.equal(existsSync(credentialDirectory), false);
  assert.equal(store.getHostCloseout(id).status, "completed");
  assert.equal(countInvocations(), 0);
});

test("old revocation evidence cannot delete a replacement key or another inventory binding", async () => {
  await crashCloseout("remote_partial");
  const metadataPath = path.join(credentials.credentialDirectory(id), "metadata.json");
  const metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
  writeFileSync(metadataPath, JSON.stringify({ ...metadata, fingerprint: "SHA256:DIFFERENT" }));
  assert.throws(() => closeout.recoverHostCloseout(host.alias, id, absent()), { code: "credential_identity_mismatch" });
  assert.equal(existsSync(credentials.credentialKeyPath(id)), true);
  writeFileSync(metadataPath, JSON.stringify(metadata));
  const inventoryPath = path.join(directory, "ansible/inventory.ini");
  writeFileSync(inventoryPath, readFileSync(inventoryPath, "utf8").replace(host.address, "192.0.2.99"));
  assert.throws(() => closeout.recoverHostCloseout(host.alias, id, absent()), { code: "credential_identity_mismatch" });
  assert.equal(existsSync(credentials.credentialKeyPath(id)), true);
  assert.equal(countInvocations(), 0);
});

test("closeout and firewall changes atomically exclude each other and retain interrupted locks", () => {
  const txn = { id: "txn-exclusive-closeout", hostAlias: host.alias, action: "closePort", profileId: "basic_linux", reason: "fixture", parameters: {} };
  const record = store.claimHostCloseout(claimInput());
  assert.throws(() => store.createRemediationTransaction(txn), { code: "host_operation_active" });
  store.releaseHostCloseout(id, record.claim);
  assert.throws(() => store.createRemediationTransaction(txn), { code: "host_operation_active" });
  assert.throws(() => store.claimHostCloseout({ ...claimInput(), credentialId: "f".repeat(64) }), { code: "host_operation_active" });
  assert.throws(() => credentials.beginHostCredential({ ...host, address: "192.0.2.11" }), { code: "credential_busy" });
  closeout.recoverHostCloseout(host.alias, id, { ...evidence(), resolution: "not_changed" });
  store.createRemediationTransaction(txn);
  assert.throws(() => store.claimHostCloseout(claimInput()), { code: "host_operation_active" });
});

test("an active enrollment prevents closeout before the SSH helper starts", async () => {
  const setup = credentials.beginHostCredential(host);
  try {
    await assert.rejects(closeout.decommissionHost(host.alias), { code: "credential_busy" });
    assert.equal(countInvocations(), 0);
    assert.equal(store.getHostCloseout(id).status, "not_changed");
  } finally { setup.release(); }
});

test("concurrent closeout workers get only one durable claim and a valid audit chain", async () => {
  const code = `try { store.claimHostCloseout(${JSON.stringify(claimInput())}); process.stdout.write("claimed"); await new Promise(resolve => setTimeout(resolve, 150)); }
    catch (error) { process.stdout.write(error.code); }`;
  const results = await Promise.all([child(code), child(code)]);
  const values = results.map(value => value.stdout);
  assert.equal(values.filter(value => value === "claimed").length, 1);
  assert.equal(values.filter(value => ["operation_owner_live", "closeout_recovery_required"].includes(value)).length, 1);
  assert.equal(store.verifyAuditChain().valid, true);
});
