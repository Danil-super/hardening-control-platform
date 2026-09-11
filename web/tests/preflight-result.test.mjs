import assert from "node:assert/strict";
import { after, test } from "node:test";
import { rmSync } from "node:fs";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["preflight-result"]);
const { summarizePreflight, explainConnectionFailure } = await import(compiled.url("preflight-result"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));
const pass = { ok: true, stdout: "", stderr: "" };
const baseline = () => ({ ssh: pass, setup: pass, sudo: pass, become: true, os: "Astra fixture", pythonMessage: "Python fixture" });

test("unknown host key is one SSH failure with dependent checks skipped", () => {
  const result = summarizePreflight({ ...baseline(), ssh: { ok: false, stdout: 'No ED25519 host key is known for 192.0.2.10 and you have requested strict checking. Host key verification failed.', stderr: "" } });
  assert.equal(result.ok, false);
  assert.equal(result.checks.ssh.state, "failed");
  assert.match(result.message, /Подтвердить сервер/);
  for (const name of ["python", "sudo"]) assert.equal(result.checks[name].state, "skipped");
});

test("a real missing sudo password blocks privileged registration while retaining passed SSH and Python", () => {
  const result = summarizePreflight({ ...baseline(), sudo: { ok: false, stdout: '{"msg":"Missing sudo password"}', stderr: "" } });
  assert.equal(result.ok, false);
  assert.equal(result.checks.ssh.state, "passed");
  assert.equal(result.checks.python.state, "passed");
  assert.equal(result.checks.sudo.state, "failed");
  assert.match(result.message, /sudo требует пароль/);
  assert.match(result.checks.sudo.details, /Missing sudo password/);
});

test("disabled sudo permits registration without claiming that elevation was verified", () => {
  const result = summarizePreflight({ ...baseline(), become: false, sudo: { ok: false, stdout: "", stderr: "" } });
  assert.equal(result.ok, true);
  assert.equal(result.checks.sudo.state, "disabled");
  assert.match(result.message, /без sudo/);
});

test("Python failure skips elevation and OS detection instead of reporting extra failures", () => {
  const result = summarizePreflight({ ...baseline(), setup: { ok: false, stderr: "unsupported Python", stdout: "" }, os: null });
  assert.equal(result.ok, false);
  assert.equal(result.checks.python.state, "failed");
  assert.equal(result.checks.sudo.state, "skipped");
  assert.equal(result.checks.os.state, "skipped");
});

test("failure explanations distinguish changed keys, login keys, missing sudo and denied privileges", () => {
  assert.match(explainConnectionFailure("ssh", "REMOTE HOST IDENTIFICATION HAS CHANGED!"), /Ключ сервера изменился/);
  assert.match(explainConnectionFailure("ssh", "Permission denied (publickey)."), /authorized_keys/);
  assert.match(explainConnectionFailure("sudo", "/bin/sh: 1: sudo: not found"), /sudo не найден/);
  assert.match(explainConnectionFailure("sudo", "user is not in the sudoers file"), /не разрешён/);
});
