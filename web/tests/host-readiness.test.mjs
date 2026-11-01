import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["host-readiness"]);
const { assessHostReadiness, assessTargetPython } = await import(compiled.url("host-readiness"));
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
  assert.equal(state(result, "cve"), "needs_setup");
  assert.equal(state(result, "openscap"), "needs_setup");
  assert.equal(result.astraVersion, "1.7.6.15");
  probe.osRelease.ID = "debian";
  assert.equal(state(assessHostReadiness(probe), "cve"), "needs_setup");
});

test("Astra releases preserve exact identity and share capability-based checks", () => {
  for (const version of ["1.6.7.15", "1.7.6.15", "1.8.1", "future-release"]) {
    const probe = baseline();
    probe.osRelease = { ID: "astra", ID_LIKE: "debian", VERSION_ID: version };
    probe.astraVersion = version;
    const result = assessHostReadiness(probe);
    assert.equal(result.astraVersion, version);
    assert.equal(state(result, "packages"), "ready");
    assert.equal(state(result, "cve"), "needs_setup");
    assert.equal(state(result, "openscap"), "needs_setup");
  }
});

test("target Python is checked against the installed controller before modules run", () => {
  assert.equal(assessTargetPython("3.5.10", "2.14.18").compatible, true);
  assert.equal(assessTargetPython("3.7.3", "2.14.18").compatible, true);
  assert.equal(assessTargetPython("3.11.2", "2.14.18").compatible, true);
  assert.equal(assessTargetPython("3.12.3", "2.14.18").compatible, false);
  assert.equal(assessTargetPython("3.7.3", "2.20.0").compatible, false);
  assert.equal(assessTargetPython("3.11.2", "2.20.0").compatible, true);
  for (const version of [null, "unknown", "2.7.18", "3.4.10"]) {
    assert.equal(assessTargetPython(version, "2.14.18").compatible, false);
  }
  assert.equal(assessTargetPython("3.11.2", "2.99.0").compatible, null);
  assert.equal(assessTargetPython("3.11.2", null).compatible, null);
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

test("OpenRC and APK readiness are independent of systemd and firewall mutation", () => {
  const probe = baseline();
  probe.osRelease = { ID: "alpine", VERSION_ID: "3.22.2" };
  probe.initSystem = "init"; probe.serviceManager = "openrc";
  probe.tools = { apk: "/sbin/apk", ss: "/bin/ss", sshd: "/usr/sbin/sshd", "rc-service": "/sbin/rc-service", "rc-status": "/sbin/rc-status" };
  const result = assessHostReadiness(probe);
  assert.equal(result.platform.trivyFamily, "alpine");
  assert.equal(state(result, "baseline"), "ready"); assert.equal(state(result, "packages"), "ready");
  assert.equal(state(result, "cve"), "ready"); assert.equal(state(result, "firewall"), "needs_setup");
  probe.initSystem = "sshd";
  assert.equal(state(assessHostReadiness(probe), "baseline"), "needs_setup");
});

test("native package manager and vendor source cannot be substituted by installed foreign tools", () => {
  const probe = baseline();
  probe.osRelease = { ID: "almalinux", VERSION_ID: "9.6", ID_LIKE: "rhel centos fedora" };
  assert.equal(state(assessHostReadiness(probe), "packages"), "needs_setup");
  probe.tools.rpm = "/usr/bin/rpm";
  assert.equal(state(assessHostReadiness(probe), "packages"), "ready");
  assert.equal(state(assessHostReadiness(probe), "cve"), "ready");
  for (const os of [{ ID: "redos", ID_LIKE: "rhel" }, { ID: "custom", ID_LIKE: "rhel" }, { ID: "centos", NAME: "CentOS Stream" }]) {
    probe.osRelease = os;
    assert.equal(state(assessHostReadiness(probe), "packages"), "ready");
    assert.equal(state(assessHostReadiness(probe), "cve"), "unsupported");
  }
  probe.osRelease = { ID: "arch" };
  assert.equal(state(assessHostReadiness(probe), "packages"), "unsupported");
  assert.equal(state(assessHostReadiness(probe), "cve"), "unsupported");
});

test("SysV limited status coverage and malformed optional evidence never become complete", () => {
  const probe = baseline(); probe.initSystem = "init"; probe.serviceManager = "sysv";
  const result = assessHostReadiness(probe);
  assert.equal(state(result, "baseline"), "needs_setup");
  assert.match(result.checks.find((check) => check.id === "baseline").detail, /LSB/);
  for (const update of [{ serviceManager: "runit" }, { architecture: 1 }, { securityModules: [] }, { firewall: [] }, { tools: [] }]) {
    assert.throws(() => assessHostReadiness({ ...probe, ...update }));
  }
});
