import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, afterEach, beforeEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ansible-runtime", "target-python"]);
const { selectAnsibleRuntime, hasModernAnsibleRuntime } = await import(compiled.url("ansible-runtime"));
const { targetPythonInterpreter, targetPythonProbeCommand, parseTargetPythonVersion } = await import(compiled.url("target-python"));
const environment = { ...process.env };
let directory;

function executable(id, version, status = 0) {
  const bin = path.join(directory, id);
  mkdirSync(bin, { recursive: true });
  writeFileSync(path.join(bin, "ansible"), `#!${process.execPath}
const fs = require('node:fs');
fs.appendFileSync(${JSON.stringify(path.join(directory, "calls"))}, JSON.stringify({runtime:${JSON.stringify(id)},args:process.argv.slice(2)})+'\\n');
if (process.argv[2] !== '--version') throw new Error('No module may run during runtime selection');
console.log(${JSON.stringify(version)});
process.exitCode=${status};
`, { mode: 0o700 });
  return bin;
}

beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-runtime-test-"));
  writeFileSync(path.join(directory, "calls"), "");
  process.env.PATH = executable("legacy", "ansible [core 2.14.18]") + path.delimiter + environment.PATH;
  process.env.HCP_ANSIBLE_MODERN_BIN_DIR = executable("modern", "ansible [core 2.21.5]");
});
afterEach(() => {
  for (const key of ["PATH", "HCP_ANSIBLE_MODERN_BIN_DIR"]) {
    if (environment[key] === undefined) delete process.env[key]; else process.env[key] = environment[key];
  }
  rmSync(directory, { recursive: true, force: true });
});
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test("every supported minor version selects a proven installed runtime, preferring modern", async () => {
  assert.equal(hasModernAnsibleRuntime(), true);
  for (let minor = 5; minor <= 14; minor++) {
    const runtime = await selectAnsibleRuntime([{ alias: "host", pythonVersion: `3.${minor}.0` }]);
    assert.equal(runtime.id, minor < 9 ? "legacy" : "modern");
    assert.equal(runtime.coreVersion, minor < 9 ? "2.14.18" : "2.21.5");
    assert.equal(runtime.playbook, minor < 9 ? "ansible-playbook" : path.join(directory, "modern/ansible-playbook"));
  }
  const calls = readFileSync(path.join(directory, "calls"), "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(calls.length, 20);
  assert.ok(calls.every((call) => call.args.length === 1 && call.args[0] === "--version"));
});

test("a group gets one compatible runtime and an incompatible mixed group never dispatches modules", async () => {
  const targets = (...versions) => versions.map((pythonVersion, index) => ({ alias: `node-${index}`, pythonVersion }));
  assert.equal((await selectAnsibleRuntime(targets("3.5.10", "3.11.9"))).id, "legacy");
  assert.equal((await selectAnsibleRuntime(targets("3.9.21", "3.14.0"))).id, "modern");
  await assert.rejects(selectAnsibleRuntime(targets("3.8.20", "3.12.10")), (error) => {
    assert.equal(error.code, "ansible_runtime_incompatible");
    assert.match(error.message, /node-0: Python 3\.8\.20/);
    assert.match(error.message, /node-1: Python 3\.12\.10/);
    assert.match(error.message, /Разделите несовместимые версии/);
    return true;
  });
});

test("selection uses the actual core version and refuses malformed, unknown or failed probes", async () => {
  executable("modern", "ansible [core 2.17.14]");
  assert.equal((await selectAnsibleRuntime([{ alias: "host", pythonVersion: "3.12.9" }])).coreVersion, "2.17.14");
  for (const output of ["ansible [core 2.99.0]", "unrecognized version", "ansible [core 2.21.5.dev0]"]) {
    executable("modern", output);
    await assert.rejects(selectAnsibleRuntime([{ alias: "host", pythonVersion: "3.14.0" }]), { code: "ansible_runtime_incompatible" });
  }
  executable("modern", "ansible [core 2.21.5]", 1);
  assert.equal((await selectAnsibleRuntime([{ alias: "host", pythonVersion: "3.11.9" }])).id, "legacy");
  await assert.rejects(selectAnsibleRuntime([{ alias: "host", pythonVersion: "3.14.0" }]), { code: "ansible_runtime_incompatible" });
});

test("missing versions, future Python and absent modern installation cannot produce compatibility", async () => {
  for (const pythonVersion of [null, "", "2.7.18", "3.4.10", "3.15.0", "3.14.0\nspoof"]) {
    await assert.rejects(selectAnsibleRuntime([{ alias: "host", pythonVersion }]), { code: "ansible_runtime_incompatible" });
  }
  delete process.env.HCP_ANSIBLE_MODERN_BIN_DIR;
  assert.equal(hasModernAnsibleRuntime(), false);
  assert.equal((await selectAnsibleRuntime([{ alias: "host", pythonVersion: "3.5.10" }])).id, "legacy");
  await assert.rejects(selectAnsibleRuntime([{ alias: "host", pythonVersion: "3.14.0" }]), { code: "ansible_runtime_incompatible" });
  process.env.HCP_ANSIBLE_MODERN_BIN_DIR = "relative/bin";
  await assert.rejects(selectAnsibleRuntime([{ alias: "host", pythonVersion: "3.11.2" }]), /абсолютным путём/);
});

test("the Python probe executes the explicit interpreter through POSIX sh and rejects ambiguity", () => {
  const python = execFileSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).trim();
  const stdout = execFileSync("/bin/sh", ["-c", targetPythonProbeCommand(python)], { encoding: "utf8" });
  assert.match(parseTargetPythonVersion(stdout), /^3\.\d+\.\d+$/);
  assert.equal(targetPythonInterpreter(), "/usr/bin/python3");
  for (const value of ["auto", "python3", "/usr/bin/python3;id", "/usr/bin/python3\n", "/tmp/$(id)", null, 3]) assert.throws(() => targetPythonInterpreter(value), /абсолютный путь/);
  for (const value of ["", "HCP_PYTHON=3.14.0rc1", "HCP_PYTHON=3.14.0\nHCP_PYTHON=3.14.0", "HCP_PYTHON=3.14.0\nHCP_PYTHON=invalid"]) assert.equal(parseTargetPythonVersion(value), null);
});

test("native Ansible remains detectable under its required UTF-8 controller locale", async (context) => {
  process.env.PATH = environment.PATH;
  delete process.env.HCP_ANSIBLE_MODERN_BIN_DIR;
  let stdout;
  try {
    stdout = execFileSync("ansible", ["--version"], { encoding: "utf8", timeout: 15000,
      env: { ...process.env, LC_ALL: "C.UTF-8" } });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    context.skip("Requires a real Ansible CLI, installed in CI."); return;
  }
  const coreVersion = stdout.match(/^ansible\s+\[core\s+(\d+\.\d+\.\d+)\]/m)?.[1];
  assert.ok(coreVersion, stdout);
  const runtime = await selectAnsibleRuntime([{ alias: "native-cli-contract", pythonVersion: "3.11.2" }]);
  assert.equal(runtime.id, "legacy");
  assert.equal(runtime.coreVersion, coreVersion);
});
