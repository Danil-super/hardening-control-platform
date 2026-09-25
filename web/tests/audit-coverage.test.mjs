import assert from "node:assert/strict";
import { after, test } from "node:test";
import { rmSync } from "node:fs";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["audit-coverage"]);
const { describeIncompleteAuditChecks } = await import(compiled.url("audit-coverage"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test("incomplete agentless checks explain the collection gap and a safe next step", () => {
  const checks = describeIncompleteAuditChecks(["ssh_effective_config", "open_ports", "ssh_effective_config"]);
  assert.equal(checks.length, 2);
  assert.equal(checks[0].id, "ssh_effective_config");
  assert.match(checks[0].title, /Эффективная конфигурация SSH/);
  assert.match(checks[0].nextStep, /sshd -t/);
  assert.equal(checks[1].id, "open_ports");
  assert.match(checks[1].nextStep, /ss/);
});

test("dynamic and future incomplete checks remain visible instead of becoming a generic warning", () => {
  const checks = describeIncompleteAuditChecks(["service_auditd", "future_probe", null]);
  assert.equal(checks.length, 2);
  assert.match(checks[0].title, /auditd/);
  assert.match(checks[1].title, /future probe/);
});
