import assert from "node:assert/strict";
import test, { after } from "node:test";
import { rmSync } from "node:fs";
import { compileServerModules } from "./_typescript-loader.mjs";
const compiled = compileServerModules(["ansible-error"]);
const { ansibleFailureMessage } = await import(compiled.url("ansible-error"));
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
