import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import test, { afterEach, beforeEach } from "node:test";
import ts from "typescript";

const webDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const nativeRequire = createRequire(import.meta.url);
const environment = { ...process.env };
const originalCwd = process.cwd();
let nativeAnsible = true;
try { execFileSync("ansible-inventory", ["--version"], { stdio: "pipe", timeout: 15000 }); }
catch (error) { if (error.code !== "ENOENT") throw error; nativeAnsible = false; }
const native = { skip: nativeAnsible ? false : "Requires native ansible-inventory for effective host/group variables." };
let directory, targetVersion, probes, handler;

/** Execute the production handler and helpers; only remote observations and
 * external Ansible stages are fixture boundaries. Inventory resolution is real.
 */
function loadHandler() {
  const modules = new Map();
  function load(relative) {
    if (modules.has(relative)) return modules.get(relative).exports;
    const filename = path.join(webDirectory, relative);
    const code = ts.transpileModule(readFileSync(filename, "utf8"), {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
    }).outputText;
    const module = { exports: {} }; modules.set(relative, module);
    const resolve = (name) => {
      if (name === "next/server") return { NextResponse: { json: (body, init) => Response.json(body, init) } };
      if (name === "@/lib/ansible-control") return { getRepoRoot: () => directory };
      if (name === "@/lib/state-store") return { recordAssetObservation: () => ({ version: 1, status: "verified", alias: "host", assetId: "fixture", generation: 1 }) };
      if (name === "@/lib/host-credentials") return { connectionPrivateKey: () => process.env.HCP_SSH_PRIVATE_KEY_PATH,
        hostCredentialSudoMode: () => null, isHostCredentialSudoReady: () => true, HostCredentialError: class extends Error {} };
      if (name === "@/lib/ssh-bootstrap") return { credentialTransportAllowed: () => true };
      if (name === "@/lib/ssh-access") return { ...load("lib/ssh-access.ts"), probeTrustedAssetIdentity: async (input) => {
        probes.push(input); return { machineIdSha256: "1".repeat(64), sshHostKeyFingerprint: "SHA256:" + "A".repeat(43), observedAt: new Date().toISOString(),
          ...(input.pythonInterpreter ? { pythonVersion: targetVersion, pythonInterpreter: input.pythonInterpreter } : {}) };
      } };
      if (name.startsWith("@/lib/")) return load(`lib/${name.slice(6)}.ts`);
      return nativeRequire(name);
    };
    vm.runInThisContext(`(function(require,module,exports){${code}\n})`, { filename })(resolve, module, module.exports);
    return module.exports;
  }
  return load("app/api/ansible/hosts/preflight/route.ts").POST;
}

beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-preflight-runtime-test-"));
  for (const name of ["web", "ansible/group_vars", "ansible/scripts", "legacy", "modern"]) mkdirSync(path.join(directory, name), { recursive: true });
  copyFileSync(path.join(webDirectory, "../ansible/scripts/hcp-host-readiness.py"), path.join(directory, "ansible/scripts/hcp-host-readiness.py"));
  writeFileSync(path.join(directory, "calls"), "");
  writeFileSync(path.join(directory, "ansible/inventory.ini"), "[linux_hosts]\nhost ansible_host=192.0.2.10 ansible_user=root\n");
  writeFileSync(path.join(directory, "ansible/group_vars/linux_hosts.yml"), "ansible_python_interpreter: /opt/python3.14/bin/python3\n");
  for (const [id, version] of [["legacy", "2.14.18"], ["modern", "2.21.5"]]) writeFileSync(path.join(directory, id, "ansible"), `#!${process.execPath}
const fs=require('node:fs'),path=require('node:path'),args=process.argv.slice(2);
if(args.includes('--version')){console.log('ansible [core ${version}]');process.exit(0);}
const tree=args[args.indexOf('--tree')+1],alias=args[args.indexOf('--tree')+2],stage=path.basename(tree);
const inventory=JSON.parse(fs.readFileSync(args[args.indexOf('-i')+1],'utf8')),host=inventory.all.hosts[alias];
fs.appendFileSync(${JSON.stringify(path.join(directory, "calls"))},JSON.stringify({id:'${id}',stage,args,host})+'\\n');
let data={changed:false,stdout:''};
if(stage==='python-version')data.stdout='HCP_PYTHON=3.11.2\\n';
if(stage==='setup')data.ansible_facts={ansible_distribution:'Rocky',ansible_distribution_version:'9',ansible_python:{executable:host.ansible_python_interpreter}};
if(stage==='sudo')data.stdout='0\\n';
if(stage==='readiness')data.stdout=JSON.stringify({schemaVersion:1,osRelease:{ID:'rocky',PRETTY_NAME:'Rocky fixture'},astraVersion:null,kernel:'fixture',pythonVersion:'3.14.0',effectiveUid:0,initSystem:'systemd',serviceManager:'systemd',tools:{rpm:'/usr/bin/rpm',ss:'/usr/bin/ss',sshd:'/usr/sbin/sshd',systemctl:'/usr/bin/systemctl'},firewall:{ufw:'missing',firewalld:'active',netfilterPersistent:'missing'},errors:[]});
fs.mkdirSync(tree,{recursive:true});fs.writeFileSync(path.join(tree,alias),JSON.stringify(data));
console.log(JSON.stringify(data));
`, { mode: 0o700 });
  process.chdir(path.join(directory, "web"));
  process.env.PATH = path.join(directory, "legacy") + path.delimiter + environment.PATH;
  process.env.HCP_ANSIBLE_MODERN_BIN_DIR = path.join(directory, "modern");
  process.env.HCP_SSH_PRIVATE_KEY_PATH = path.join(directory, "fixture-key");
  writeFileSync(process.env.HCP_SSH_PRIVATE_KEY_PATH, "fixture; no SSH uses this file", { mode: 0o600 });
  targetVersion = "3.14.0"; probes = []; handler = loadHandler();
});
afterEach(() => {
  process.chdir(originalCwd);
  for (const key of ["PATH", "HCP_ANSIBLE_MODERN_BIN_DIR", "HCP_SSH_PRIVATE_KEY_PATH"]) {
    if (environment[key] === undefined) delete process.env[key]; else process.env[key] = environment[key];
  }
  rmSync(directory, { recursive: true, force: true });
});

const input = () => ({ alias: "host", address: "192.0.2.10", user: "root", port: 22, become: true });
const request = (body = input()) => handler(new Request("http://127.0.0.1/api/ansible/hosts/preflight", { method: "POST", body: JSON.stringify(body) }));
const calls = () => readFileSync(path.join(directory, "calls"), "utf8").trim().split("\n").filter(Boolean).map(JSON.parse);

test("preflight honors effective inventory Python for identity, modules and the readiness collector", native, async () => {
  const response = await request(); const result = await response.json();
  assert.equal(response.status, 200); assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.facts.configuredPython, "/opt/python3.14/bin/python3");
  assert.equal(result.facts.ansibleCoreVersion, "2.21.5");
  assert.equal(result.facts.ansibleRuntime, "modern");
  assert.equal(probes.length, 1); assert.equal(probes[0].pythonInterpreter, result.facts.configuredPython);
  assert.deepEqual(calls().map((call) => [call.stage, call.id]), [["ssh", "legacy"], ["setup", "modern"], ["sudo", "modern"], ["readiness", "modern"]]);
  assert.ok(calls().every((call) => call.host.ansible_python_interpreter === result.facts.configuredPython));
  const readiness = calls().find((call) => call.stage === "readiness");
  assert.equal(JSON.parse(readiness.args[readiness.args.indexOf("-a") + 1]).argv[0], result.facts.configuredPython);
});

test("older Python selects legacy, while unknown Python stops before module transfer", native, async () => {
  targetVersion = "3.7.3";
  const legacy = await (await request()).json();
  assert.equal(legacy.ok, true); assert.equal(legacy.facts.ansibleRuntime, "legacy");
  assert.ok(calls().every((call) => call.id === "legacy"));
  writeFileSync(path.join(directory, "calls"), ""); targetVersion = null;
  const missing = await (await request()).json();
  assert.equal(missing.ok, false); assert.equal(missing.checks.python.state, "failed");
  assert.equal(missing.checks.sudo.state, "skipped"); assert.match(missing.message, /Python не определён/);
  assert.deepEqual(calls().map((call) => call.stage), ["ssh"]);
});

test("saved connection mismatches are rejected for root and when elevation is disabled", native, async () => {
  for (const become of [true, false]) {
    const response = await request({ ...input(), address: "192.0.2.99", become });
    assert.equal(response.status, 409); assert.equal((await response.json()).error, "inventory_connection_mismatch");
  }
  assert.deepEqual(calls(), []); assert.equal(probes.length, 0);
  writeFileSync(path.join(directory, "ansible/group_vars/linux_hosts.yml"), "ansible_python_interpreter: auto\n");
  const invalid = await request(); assert.equal(invalid.status, 409);
  assert.match((await invalid.json()).message, /абсолютный путь/); assert.deepEqual(calls(), []);
});

test("unsaved hosts use the default interpreter and legacy deployments preserve the original probe protocol", native, async () => {
  const unsaved = await (await request({ ...input(), alias: "new-host" })).json();
  assert.equal(unsaved.facts.configuredPython, "/usr/bin/python3");
  assert.equal(probes[0].pythonInterpreter, "/usr/bin/python3");
  delete process.env.HCP_ANSIBLE_MODERN_BIN_DIR; probes = []; writeFileSync(path.join(directory, "calls"), "");
  const legacy = await (await request()).json();
  assert.equal(legacy.ok, true); assert.equal(legacy.facts.ansibleRuntime, "legacy");
  assert.equal(probes[0].pythonInterpreter, undefined);
  const python = calls().find((call) => call.stage === "python-version");
  assert.match(python.args[python.args.indexOf("-a") + 1], /'\/opt\/python3\.14\/bin\/python3' -c/);
});
