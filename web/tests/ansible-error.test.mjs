import assert from "node:assert/strict";
import test, { after } from "node:test";
import { rmSync } from "node:fs";
import { compileServerModules } from "./_typescript-loader.mjs";
const compiled = compileServerModules(["ansible-error"]);
const { ansibleFailureMessage, classifyAnsibleExecutionError } = await import(compiled.url("ansible-error"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test("UFW lock refusal explains the actual access problem instead of the runner command", () => {
  const failure = { message: "Command failed: ansible-playbook --extra-vars @/tmp/secret/vars.json", stdout: 'fatal: [host]: FAILED! => ' + JSON.stringify({ stdout: JSON.stringify({ ok: false, error: "ufw status: PermissionError: [Errno 13] Permission denied: '/run/ufw.lock'" }) }) };
  const message = ansibleFailureMessage(failure);
  assert.match(message, /UFW.*\/run\/ufw.lock/);
  assert.match(message, /целостности/);
  assert.doesNotMatch(message, /vars.json|Command failed/);
});

test("Ansible validation and transport failures retain actionable details", () => {
  assert.equal(ansibleFailureMessage({ stdout: 'fatal: [host]: FAILED! => {"msg":"port is protected"}' }), "port is protected");
  assert.equal(ansibleFailureMessage({ stderr: 'ERROR! Missing sudo password' }), "ERROR! Missing sudo password");
  assert.match(ansibleFailureMessage(new Error("network timeout")), /network timeout/);
});

test("a recap cannot turn truncated or unfamiliar native failure output into proof of completion", () => {
  const recap = "\nPLAY RECAP ********************************************************\nhost : ok=1 changed=0 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0\n";
  for (const stdout of [recap, 'fatal: [host]: FAILED! => {"stdout":' + recap,
    'fatal: [host]: FAILED! => ' + JSON.stringify({msg:"The command action failed to execute in the expected time frame (1) and was terminated"}) + recap,
    'fatal: [host]: FAILED! => ' + JSON.stringify({stdout:JSON.stringify({ok:false,error:"no exit evidence"})}) + recap,
    'fatal: [host]: FAILED! => ' + JSON.stringify({stdout:"",rc:-15}) + recap,
    'fatal: [host]: FAILED! => ' + JSON.stringify({stdout:"",rc:1}) + recap,
    'fatal: [host]: FAILED! => ' + JSON.stringify({stdout:"not a completed helper response",rc:1}) + recap]) {
    assert.equal(classifyAnsibleExecutionError({code:2,stdout}, true), "unknown");
  }
  const completed = 'fatal: [host]: FAILED! => ' + JSON.stringify({stdout:JSON.stringify({ok:false,error:"verification failed"}),rc:1}) + recap;
  assert.equal(classifyAnsibleExecutionError({code:2,stdout:completed}, true), "completed");
  assert.equal(classifyAnsibleExecutionError({code:2,stdout:completed.replace("unreachable=0", "unreachable=1")}, true), "unknown");
  assert.equal(classifyAnsibleExecutionError({code:2,stdout:completed,signal:"SIGKILL"}, true), "unknown");
  assert.equal(classifyAnsibleExecutionError({code:"ENOENT"}, false), "not_started");
});
