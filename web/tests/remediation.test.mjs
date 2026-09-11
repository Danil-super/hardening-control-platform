import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, beforeEach, afterEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

// Exercise real orchestration and SQLite state while replacing only remote I/O.
const compiled = compileServerModules(["remediation", "state-store", "astra-oval-config"]);
writeFileSync(path.join(compiled.directory, "ansible-control.mjs"), `
export const control = { runs: [], failAction: null, failPost: false, missingReport: false, address: "192.0.2.20" };
export const isSafeLimit = value => /^[A-Za-z0-9_-]+$/.test(value);
export const inventoryHostExists = value => value === "host-one";
export const inventoryHostConnection = () => ({address: control.address, port: 2222, user: "audit"});
export const inventoryHostAddress = () => control.address;
export const validateExtraVars = () => ({ok: true});
export const appendIncident = () => {};
export const reportIdForRun = () => "report";
export async function runAnsiblePlaybook(options) {
  control.runs.push(options.action);
  if (control.failAction === options.action || (control.failPost && options.action === "agentlessAudit" && control.runs.length > 1)) throw new Error("remote operation failed");
  return {stdout:"verified",stderr:"",command:options.action,reportRunId:"run"};
}
`);
writeFileSync(path.join(compiled.directory, "ansible-reports.mjs"), `
import {control} from "./ansible-control.mjs";
export const readAnsibleReport = () => control.missingReport ? null : {partial:false,available:true};
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
  Object.assign(control, {runs:[],failAction:null,failPost:false,missingReport:false,address:"192.0.2.20"});
});
afterEach(() => rmSync(directory, {recursive:true,force:true}));
after(() => {
  if (previousDirectory === undefined) delete process.env.HCP_STATE_DIR; else process.env.HCP_STATE_DIR = previousDirectory;
  if (previousKey === undefined) delete process.env.HCP_AUDIT_HMAC_KEY; else process.env.HCP_AUDIT_HMAC_KEY = previousKey;
  rmSync(compiled.directory, {recursive:true,force:true});
});
const request = {action:"closePort",profileId:"basic_linux",hostAlias:"host-one",extraVars:{target_port:"8080",target_protocol:"tcp"},reason:"test authorised remediation"};

test("missing pre-audit prevents firewall backup and modification", async () => {
  control.missingReport = true;
  await assert.rejects(remediation.applyRemediation(request), /аудит отсутствует/);
  assert.deepEqual(control.runs, ["agentlessAudit"]);
  assert.equal(store.listRemediationTransactions()[0].backupRef, null);
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
