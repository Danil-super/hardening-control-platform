import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["host-readiness"]);
const { assessHostReadiness } = await import(compiled.url("host-readiness"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));
const baseline = () => ({ schemaVersion: 1, osRelease: { ID: "ubuntu", VERSION_ID: "24.04" }, astraVersion: null,
  kernel: "6.8", pythonVersion: "3.12.3", effectiveUid: 0, initSystem: "systemd",
  tools: { "dpkg-query": "/usr/bin/dpkg-query", ss: "/usr/bin/ss", sshd: "/usr/sbin/sshd", systemctl: "/usr/bin/systemctl", oscap: "/usr/bin/oscap" },
  firewall: { ufw: "active", firewalld: "missing", netfilterPersistent: "inactive" }, errors: [] });
const state = (result, id) => result.checks.find((check) => check.id === id).state;

test("Astra derived from Debian never inherits verified CVE/SCAP prerequisites", () => {
  const probe = baseline();
  probe.osRelease = { ID: "astra", ID_LIKE: "debian", NAME: "Astra Linux", VERSION_ID: "1.7_x86-64" };
  probe.astraVersion = "1.7.6.15";
  const result = assessHostReadiness(probe);
  assert.equal(state(result, "packages"), "ready");
  assert.equal(state(result, "cve"), "unsupported");
  assert.equal(state(result, "openscap"), "needs_setup");
  assert.equal(result.astraVersion, "1.7.6.15");
  probe.osRelease.ID = "debian";
  assert.equal(state(assessHostReadiness(probe), "cve"), "unsupported");
});

test("unknown firewall, competing managers and containers do not get readiness", () => {
  const probe = baseline();
  assert.equal(state(assessHostReadiness(probe), "firewall"), "ready");
  probe.firewall.firewalld = "unknown";
  assert.equal(state(assessHostReadiness(probe), "firewall"), "unknown");
  probe.firewall.firewalld = "active";
  assert.equal(state(assessHostReadiness(probe), "firewall"), "needs_setup");
  probe.firewall.firewalld = "missing";
  probe.firewall.netfilterPersistent = "active";
  assert.equal(state(assessHostReadiness(probe), "firewall"), "needs_setup");
  probe.initSystem = "sshd";
  assert.equal(state(assessHostReadiness(probe), "baseline"), "needs_setup");
  probe.initSystem = "systemd";
  probe.effectiveUid = 1000;
  assert.equal(state(assessHostReadiness(probe), "baseline"), "needs_setup");
});

test("missing or malformed probe evidence cannot appear ready", () => {
  for (const data of [null, {}, { ...baseline(), schemaVersion: 2 }, { ...baseline(), tools: { oscap: true } }]) {
    assert.throws(() => assessHostReadiness(data));
  }
  const probe = baseline();
  delete probe.firewall.ufw;
  assert.equal(state(assessHostReadiness(probe), "firewall"), "unknown");
  delete probe.tools["dpkg-query"];
  assert.equal(state(assessHostReadiness(probe), "packages"), "needs_setup");
});
