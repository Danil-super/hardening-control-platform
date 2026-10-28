import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, afterEach, beforeEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

// Real executor, remediation orchestration and SQLite. Only the remote CLI
// and inventory/report inputs are replaced; no SSH or firewall is contacted.
const compiled = compileServerModules(["remediation", "state-store"]);
writeFileSync(path.join(compiled.directory, "real-ansible-control.mjs"), readFileSync(path.join(compiled.directory, "ansible-control.mjs")));
writeFileSync(path.join(compiled.directory, "ansible-control.mjs"), `
import {executeAnsiblePlaybook} from "./real-ansible-control.mjs";
export const control = { action: "closePort", mode: "success", directory: "", calls: [] };
export const isSafeLimit = () => true, inventoryHostExists = () => true;
export const inventoryHostConnection = () => ({address:"192.0.2.20",port:2222,user:"fixture"});
export const inventoryHostAddress = () => "192.0.2.20";
export const validateExtraVars = () => ({ok:true});
export const appendIncident = () => {};
export const reportIdForRun = () => "fixture-report";
export async function runAnsiblePlaybook(options) {
  control.calls.push(options);
  if (["closePort", "rollbackRemediation", "backupRemediation"].includes(options.action)) {
    return executeAnsiblePlaybook({args:[options.action, options.action === control.action ? control.mode : "success", control.directory], timeout:500});
  }
  return {command:options.action,stdout:"",stderr:"",reportRunId:"fixture-run"};
}
`);
writeFileSync(path.join(compiled.directory, "ansible-reports.mjs"), `
export const getReportsDir = () => "/unused-fixture-reports";
export const readAnsibleReport = () => ({partial:false,available:true,raw:{scanner:{incompleteChecks:[]},findings:[{id:"firewall_active",status:"passed",evidence:"backend=ufw; fixture=controlled"},{id:"dangerous_ports_absent",status:"passed"}]}});
`);
const remediation = await import(compiled.url("remediation"));
const store = await import(compiled.url("state-store"));
const { control } = await import(compiled.url("ansible-control"));
const savedEnvironment = Object.fromEntries(["PATH", "HCP_STATE_DIR", "HCP_AUDIT_HMAC_KEY"].map((name) => [name, process.env[name]]));
let directory;

async function waitForFile(file) {
  const deadline = Date.now() + 5000;
  while (!existsSync(file) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(existsSync(file), true, `fixture did not finish: ${file}`);
}

beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-remediation-execution-"));
  mkdirSync(path.join(directory, "bin"));
  process.env.PATH = path.join(directory, "bin");
  process.env.HCP_STATE_DIR = path.join(directory, "state");
  process.env.HCP_AUDIT_HMAC_KEY = "remediation-execution-test-key";
  Object.assign(control, { action:"closePort", mode:"success", directory, calls:[] });
  writeFileSync(path.join(directory, "target"), "baseline");
  writeFileSync(path.join(directory, "bin", "ansible-playbook"), `#!${process.execPath}
const fs = require("node:fs"), path = require("node:path"), {spawn} = require("node:child_process");
const [action, mode, directory] = process.argv.slice(2);
const target = path.join(directory, "target");
function fail(payload, code=2) {
  console.log("fatal: [fixture-host]: " + (code===4 ? "UNREACHABLE!" : "FAILED!") + " => " + JSON.stringify(payload));
  console.log("\\nPLAY RECAP *********************************************************************");
  console.log("fixture-host : ok=1 changed=0 unreachable=" + (code===4 ? 1 : 0) + " failed=" + (code===4 ? 0 : 1) + " skipped=0 rescued=0 ignored=0");
  process.exit(code);
}
if (mode === "timeout") {
  // Model the remote task surviving the loss of its local Ansible/SSH owner.
  const code = 'const fs=require("node:fs"),path=require("node:path");const [directory,action]=process.argv.slice(1);const deadline=Date.now()+6000;const timer=setInterval(()=>{if(fs.existsSync(path.join(directory,"release"))){fs.writeFileSync(path.join(directory,"target"),"late-"+action);fs.writeFileSync(path.join(directory,"done"),"done");clearInterval(timer);}else if(Date.now()>deadline){clearInterval(timer);}},20);';
  const child = spawn(process.execPath, ["-e", code, directory, action], {detached:true,stdio:"ignore"});
  child.unref();
  fs.writeFileSync(path.join(directory, "launched"), String(child.pid));
  setInterval(() => {}, 1000);
} else if (mode === "overflow") {
  process.stdout.write("x".repeat(8 * 1024 * 1024 + 65536));
  setInterval(() => {}, 1000);
} else if (mode === "unreachable") {
  fail({msg:"Failed to connect to the host via ssh: Connection reset by peer",unreachable:true},4);
} else if (mode === "native-unknown") {
  fail({stdout:JSON.stringify({ok:false,error:"backend completion unconfirmed",outcomeUnknown:true}),rc:1});
} else if (mode === "completed") {
  fs.writeFileSync(target, "partial-change");
  fail({stdout:JSON.stringify({ok:false,error:"fixture rule verification failed",outcomeUnknown:false}),rc:1});
} else {
  if (action === "backupRemediation") fs.writeFileSync(path.join(directory, "backup-lease"), "lease");
  else fs.writeFileSync(target, action === "rollbackRemediation" ? "restored" : "applied");
}
`, { mode:0o700 });
});
afterEach(async () => {
  if (existsSync(path.join(directory, "launched"))) {
    writeFileSync(path.join(directory, "release"), "release");
    await waitForFile(path.join(directory, "done"));
  }
  rmSync(directory, {recursive:true,force:true});
});
after(() => {
  for (const [name, value] of Object.entries(savedEnvironment)) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
  rmSync(compiled.directory, {recursive:true,force:true});
});
const request = {action:"closePort",profileId:"basic_linux",hostAlias:"fixture-host",extraVars:{target_port:"8080",target_protocol:"tcp"},reason:"controlled executor regression"};

test("apply carries the same target transaction lease as its backup and ordinary rollback has no recovery attestation", async () => {
  const { transaction } = await remediation.applyRemediation(request);
  const backup = control.calls.find(item => item.action === "backupRemediation");
  const apply = control.calls.find(item => item.action === "closePort");
  assert.equal(backup.extraVars.transaction_id, transaction.id);
  assert.equal(apply.extraVars.transaction_id, transaction.id);
  await remediation.rollbackRemediation(transaction.id, request.hostAlias);
  const rollback = control.calls.find(item => item.action === "rollbackRemediation");
  assert.equal(rollback.extraVars.rollback_recovery_verified, false);
});

test("an unknown backup outcome preserves its target lease until a separately attested rollback", async () => {
  Object.assign(control, { action:"backupRemediation", mode:"unreachable" });
  await assert.rejects(remediation.applyRemediation(request), error => error.remoteOutcome === "unknown");
  const transaction = store.listRemediationTransactions()[0];
  assert.equal(transaction.status, "interrupted");
  assert.equal(transaction.backupRef, null, "the response was lost before the controller checkpoint");
  assert.equal(store.hasActiveRemediationForHost(request.hostAlias), true);
  assert.equal(control.calls.some(item => item.action === "closePort"), false);
  await assert.rejects(remediation.applyRemediation(request), {code:"transaction_in_progress"});
  store.reconcileRemediationTransaction(transaction.id, {
    confirmedHost:request.hostAlias, confirmedOperation:transaction.id,
    expectedRecoveryVersion:transaction.recoveryVersion, processesStopped:true, outcomeVerified:true,
    inspectionNote:"Independent console confirmed the archive and all old processes have stopped.",
    evidenceReference:"incident:backup-lease-recovery", resolution:"prepare_rollback", backupVerified:true,
  });
  await remediation.rollbackRemediation(transaction.id, request.hostAlias);
  assert.equal(control.calls.find(item => item.action === "rollbackRemediation").extraVars.rollback_recovery_verified, true);
  assert.equal(store.getRemediationTransaction(transaction.id).status, "rolled_back");
});

for (const action of ["closePort", "rollbackRemediation"]) {
  test(`${action} timeout keeps the host locked while the original remote task can still act`, async () => {
    let transaction;
    if (action === "rollbackRemediation") transaction = (await remediation.applyRemediation(request)).transaction;
    Object.assign(control, {action,mode:"timeout"});
    const promise = action === "closePort" ? remediation.applyRemediation(request) : remediation.rollbackRemediation(transaction.id, "fixture-host");
    await assert.rejects(promise, (error) => error.killed === true && error.remoteOutcome === "unknown");
    transaction = store.listRemediationTransactions()[0];
    assert.equal(transaction.status, "interrupted");
    assert.equal(transaction.recoveryRequired, true);
    assert.equal(store.hasActiveRemediationForHost("fixture-host"), true);
    assert.equal(readFileSync(path.join(directory, "target"), "utf8"), action === "closePort" ? "baseline" : "applied");
    await assert.rejects(remediation.rollbackRemediation(transaction.id, "fixture-host"), {code:"rollback_not_available"});
    await assert.rejects(remediation.applyRemediation(request), {code:"transaction_in_progress"});
    writeFileSync(path.join(directory, "release"), "release");
    await waitForFile(path.join(directory, "done"));
    assert.equal(readFileSync(path.join(directory, "target"), "utf8"), `late-${action}`);
    assert.equal(store.getRemediationTransaction(transaction.id).status, "interrupted");
    assert.equal(store.hasActiveRemediationForHost("fixture-host"), true);
  });
}

for (const mode of ["overflow", "unreachable", "native-unknown"]) {
  test(`${mode} retains the mutation lock instead of treating local exit as remote completion`, async () => {
    control.mode = mode;
    await assert.rejects(remediation.applyRemediation(request), (error) => error.remoteOutcome === "unknown");
    const transaction = store.listRemediationTransactions()[0];
    assert.equal(transaction.status, "interrupted");
    assert.equal(transaction.recoveryRequired, true);
    assert.equal(store.hasActiveRemediationForHost("fixture-host"), true);
  });
}

test("a completed native failure retains its backup and permits ordinary rollback", async () => {
  control.mode = "completed";
  await assert.rejects(remediation.applyRemediation(request), (error) => error.remoteOutcome === "completed");
  const transaction = store.listRemediationTransactions()[0];
  assert.equal(transaction.status, "failed");
  assert.equal(store.hasActiveRemediationForHost("fixture-host"), false);
  assert.equal(readFileSync(path.join(directory, "target"), "utf8"), "partial-change");
  assert.equal((await remediation.rollbackRemediation(transaction.id, "fixture-host")).transaction.status, "rolled_back");
  assert.equal(readFileSync(path.join(directory, "target"), "utf8"), "restored");
});

test("failure to spawn the CLI is known not to have started and can be retried", async () => {
  process.env.PATH = path.join(directory, "no-executable");
  await assert.rejects(remediation.applyRemediation(request), (error) => error.code === "ENOENT" && error.remoteOutcome === "not_started");
  assert.equal(store.listRemediationTransactions()[0].status, "failed");
  assert.equal(store.hasActiveRemediationForHost("fixture-host"), false);
  assert.equal(readFileSync(path.join(directory, "target"), "utf8"), "baseline");
  process.env.PATH = path.join(directory, "bin");
  assert.equal((await remediation.applyRemediation(request)).transaction.status, "applied");
});
