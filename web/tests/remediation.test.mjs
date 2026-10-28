import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, beforeEach, afterEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

// Exercise real orchestration and SQLite state while replacing only remote I/O.
const compiled = compileServerModules(["remediation", "state-store", "astra-oval-config"]);
writeFileSync(path.join(compiled.directory, "ansible-control.mjs"), `
export const control = { runs: [], failAction: null, failOutcome: "completed", failPost: false, missingReport: false, address: "192.0.2.20", report: {partial:false,available:true} };
export const isSafeLimit = value => /^[A-Za-z0-9_-]+$/.test(value);
export const inventoryHostExists = value => value === "host-one";
export const inventoryHostConnection = () => ({address: control.address, port: 2222, user: "audit"});
export const inventoryHostAddress = () => control.address;
export const validateExtraVars = () => ({ok: true});
export const appendIncident = () => {};
export const reportIdForRun = () => "report";
export async function runAnsiblePlaybook(options) {
  control.runs.push(options.action);
  if (control.failAction === options.action || (control.failPost && options.action === "agentlessAudit" && control.runs.length > 1)) throw Object.assign(new Error("remote operation failed"), {remoteOutcome:control.failOutcome});
  return {stdout:"verified",stderr:"",command:options.action,reportRunId:"run"};
}
`);
writeFileSync(path.join(compiled.directory, "ansible-reports.mjs"), `
import {control} from "./ansible-control.mjs";
export const readAnsibleReport = () => control.missingReport ? null : control.report;
`);
const remediation = await import(compiled.url("remediation"));
const store = await import(compiled.url("state-store"));
const { control } = await import(compiled.url("ansible-control"));
const previousDirectory = process.env.HCP_STATE_DIR;
const previousKey = process.env.HCP_AUDIT_HMAC_KEY;
let directory;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-remediation-test-"));
  process.env.HCP_STATE_DIR = directory;
  process.env.HCP_AUDIT_HMAC_KEY = "remediation-test-key";
  Object.assign(control, {runs:[],failAction:null,failOutcome:"completed",failPost:false,missingReport:false,address:"192.0.2.20",report:{partial:false,available:true}});
});
afterEach(() => rmSync(directory, {recursive:true,force:true}));
after(() => {
  if (previousDirectory === undefined) delete process.env.HCP_STATE_DIR; else process.env.HCP_STATE_DIR = previousDirectory;
  if (previousKey === undefined) delete process.env.HCP_AUDIT_HMAC_KEY; else process.env.HCP_AUDIT_HMAC_KEY = previousKey;
  rmSync(compiled.directory, {recursive:true,force:true});
});
const request = {action:"closePort",profileId:"basic_linux",hostAlias:"host-one",extraVars:{target_port:"8080",target_protocol:"tcp"},reason:"test authorised remediation"};

function verifiedButPartlyLimitedAudit(incompleteChecks = ["ssh_effective_config"]) {
  return {
    partial: true,
    available: true,
    raw: {
      scanner: { partial: true, incompleteChecks },
      findings: [
        { id: "firewall_active", status: "passed" },
        { id: "dangerous_ports_absent", status: "passed" },
      ],
    },
  };
}

test("missing pre-audit prevents firewall backup and modification", async () => {
  control.missingReport = true;
  await assert.rejects(remediation.applyRemediation(request), /исходный отчёт не создан/);
  assert.deepEqual(control.runs, ["agentlessAudit"]);
  assert.equal(store.listRemediationTransactions()[0].backupRef, null);
});

test("unrelated audit limitations do not block a verified firewall transaction", async () => {
  control.report = verifiedButPartlyLimitedAudit();
  const result = await remediation.applyRemediation(request);
  assert.equal(result.transaction.status, "applied");
  assert.match(result.preAuditWarnings.join(" "), /эффективная конфигурация SSH/);
  assert.match(result.postAuditWarnings.join(" "), /эффективная конфигурация SSH/);
  assert.deepEqual(control.runs, ["agentlessAudit", "backupRemediation", "closePort", "agentlessAudit"]);
});

test("missing firewall or port evidence still prevents the backup and modification", async () => {
  control.report = verifiedButPartlyLimitedAudit(["firewall_active"]);
  control.report.raw.findings[0].status = "manual";
  await assert.rejects(remediation.applyRemediation(request), /не подтверждено активное состояние поддерживаемого firewall/);
  assert.deepEqual(control.runs, ["agentlessAudit"]);
  assert.equal(store.listRemediationTransactions()[0].backupRef, null);
});

test("a detected nftables backend stays audit-only until its rollback model is implemented", async () => {
  control.report = verifiedButPartlyLimitedAudit();
  control.report.partial = false;
  control.report.raw.scanner.incompleteChecks = [];
  control.report.raw.findings[0].evidence = "backend=nftables; nftables=policy drop";
  await assert.rejects(remediation.applyRemediation(request), /обнаружен nftables/);
  assert.deepEqual(control.runs, ["agentlessAudit"]);
});

test("a partly failed change retains its backup and can be rolled back", async () => {
  control.failAction = "closePort";
  await assert.rejects(remediation.applyRemediation(request), /remote operation failed/);
  const transaction = store.listRemediationTransactions()[0];
  assert.deepEqual(control.runs, ["agentlessAudit", "backupRemediation", "closePort"]);
  assert.equal(transaction.status, "failed");
  assert.match(transaction.backupRef, /firewall-state.tar.gz$/);
  control.failAction = null;
  const restored = await remediation.rollbackRemediation(transaction.id, "host-one");
  assert.equal(restored.transaction.status, "rolled_back");
});

test("audit and backup transport errors before mutation do not require firewall recovery", async () => {
  for (const action of ["agentlessAudit", "backupRemediation"]) {
    control.failAction = action;
    control.failOutcome = "unknown";
    await assert.rejects(remediation.applyRemediation(request), /remote operation failed/);
    const transaction = store.listRemediationTransactions()[0];
    assert.equal(transaction.status, "failed");
    assert.equal(transaction.recoveryRequired, false);
    assert.equal(store.hasActiveRemediationForHost("host-one"), false);
    assert.equal(transaction.backupRef, null);
  }
  control.failAction = null;
  assert.equal((await remediation.applyRemediation(request)).transaction.status, "applied");
});

test("unknown rollback outcome consumes the previous recovery and blocks a direct retry", async () => {
  const applied = await remediation.applyRemediation(request);
  store.updateRemediationTransaction(applied.transaction.id, { status: "interrupted" });
  const evidence = {
    confirmedHost: "host-one", confirmedOperation: applied.transaction.id,
    expectedRecoveryVersion: store.getRemediationTransaction(applied.transaction.id).recoveryVersion,
    processesStopped: true, outcomeVerified: true, inspectionNote: "Independent console inspection of the fixture completed.",
    evidenceReference: "fixture-incident-123", resolution: "prepare_rollback", backupVerified: true,
  };
  const prepared = store.reconcileRemediationTransaction(applied.transaction.id, evidence);
  const previousAttestation = { ...evidence, expectedRecoveryVersion: prepared.recoveryVersion };
  control.failAction = "rollbackRemediation";
  control.failOutcome = "unknown";
  await assert.rejects(remediation.rollbackRemediation(prepared.id, "host-one"), /Результат удалённого отката неизвестен/);
  const interrupted = store.getRemediationTransaction(prepared.id);
  assert.equal(interrupted.status, "interrupted");
  assert.equal(interrupted.recoveryRequired, true);
  assert.notEqual(interrupted.recoveryVersion, prepared.recoveryVersion);
  assert.equal(store.hasActiveRemediationForHost("host-one"), true);
  await assert.rejects(remediation.rollbackRemediation(prepared.id, "host-one"), { code: "rollback_not_available" });
  await assert.rejects(remediation.applyRemediation(request), { code: "transaction_in_progress" });
  assert.throws(() => store.reconcileRemediationTransaction(prepared.id, previousAttestation), { code: "recovery_version_stale" });
  store.reconcileRemediationTransaction(prepared.id, { ...evidence, expectedRecoveryVersion: interrupted.recoveryVersion });
  control.failAction = null;
  assert.equal((await remediation.rollbackRemediation(prepared.id, "host-one")).transaction.status, "rolled_back");
});

test("post-audit failure preserves the applied state and exposes its error", async () => {
  control.failPost = true;
  const result = await remediation.applyRemediation(request);
  assert.equal(result.transaction.status, "applied");
  assert.match(result.postAuditError, /remote operation failed/);
});

test("changed connection identity and management SSH port block modifications", async () => {
  await assert.rejects(remediation.applyRemediation({...request,extraVars:{target_port:"2222",target_protocol:"tcp"}}), {code:"protected_ssh_port"});
  assert.deepEqual(control.runs, []);
  const result = await remediation.applyRemediation(request);
  control.address = "192.0.2.99";
  await assert.rejects(remediation.rollbackRemediation(result.transaction.id, "host-one"), {code:"host_connection_changed"});
  assert.equal(control.runs.at(-1), "agentlessAudit");
});

test("failed reload stays rollback_failed and remains retryable", async () => {
  const result = await remediation.applyRemediation(request);
  control.failAction = "rollbackRemediation";
  await assert.rejects(remediation.rollbackRemediation(result.transaction.id, "host-one"), /remote operation failed/);
  assert.equal(store.getRemediationTransaction(result.transaction.id).status, "rollback_failed");
  control.failAction = null;
  assert.equal((await remediation.rollbackRemediation(result.transaction.id, "host-one")).transaction.status, "rolled_back");
});

test("recovered rollback retains its host lock on failure and preserves connection guards", async () => {
  const result = await remediation.applyRemediation(request);
  store.updateRemediationTransaction(result.transaction.id, { status: "recovery_ready" });
  control.address = "192.0.2.99";
  await assert.rejects(remediation.rollbackRemediation(result.transaction.id, "host-one"), { code: "host_connection_changed" });
  assert.equal(store.getRemediationTransaction(result.transaction.id).status, "recovery_ready");
  control.address = "192.0.2.20";
  control.failAction = "rollbackRemediation";
  await assert.rejects(remediation.rollbackRemediation(result.transaction.id, "host-one"), /remote operation failed/);
  assert.equal(store.getRemediationTransaction(result.transaction.id).status, "recovery_ready");
  assert.equal(store.hasActiveRemediationForHost("host-one"), true);
  control.failAction = null;
  assert.equal((await remediation.rollbackRemediation(result.transaction.id, "host-one")).transaction.status, "rolled_back");
  assert.equal(store.hasActiveRemediationForHost("host-one"), false);
});

test("failed operation before backup can be cancelled without contacting the host", async () => {
  control.missingReport = true;
  await assert.rejects(remediation.applyRemediation(request));
  const transaction = store.listRemediationTransactions()[0];
  const runs = [...control.runs];
  assert.throws(() => store.cancelRemediationTransaction(transaction.id, "other-host"), {code:"host_confirmation_required"});
  const cancelled = store.cancelRemediationTransaction(transaction.id, "host-one");
  assert.equal(cancelled.status, "cancelled");
  assert.equal(cancelled.error, transaction.error);
  assert.deepEqual(control.runs, runs);
  assert.equal(store.verifyAuditChain().valid, true);
  assert.equal(store.cancelRemediationTransaction(transaction.id, "host-one").status, "cancelled");
});

test("active operations and failures with a backup cannot be cancelled", async () => {
  store.createRemediationTransaction({id:"active",hostAlias:"host-one",action:"closePort",profileId:"basic_linux",reason:"test",parameters:{}});
  assert.throws(() => store.cancelRemediationTransaction("active", "host-one"), {code:"cancel_not_available"});
  store.updateRemediationTransaction("active", {status:"failed",backupRef:"/var/lib/hcp-backups/active/firewall-state.tar.gz"});
  assert.throws(() => store.cancelRemediationTransaction("active", "host-one"), {code:"cancel_not_available"});
  assert.equal(store.getRemediationTransaction("active").status, "failed");
});


test("UFW lock refusal is diagnosed before the nftables fallback and never starts backup", async () => {
  control.report = verifiedButPartlyLimitedAudit();
  control.report.raw.findings[0].evidence = "backend=nftables; ufw=PermissionError: Permission denied: '/run/ufw.lock'; nftables=rules";
  await assert.rejects(remediation.applyRemediation(request), /UFW.*ufw.lock/);
  assert.deepEqual(control.runs, ["agentlessAudit"]);
  assert.equal(store.listRemediationTransactions()[0].backupRef, null);
});
