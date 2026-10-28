import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test, { after, afterEach, beforeEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const webDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const originalCwd = process.cwd();
const environmentKeys = ["PATH", "TMPDIR", "HCP_STATE_DIR", "HCP_REPORTS_DIR", "HCP_AUDIT_HMAC_KEY", "HCP_SSH_PRIVATE_KEY_PATH", "HCP_KNOWN_HOSTS_PATH", "HCP_ASSET_EXECUTION_RECORD", "HCP_ASSET_CHILD_FAIL"];
const originalEnvironment = Object.fromEntries(environmentKeys.map((key) => [key, process.env[key]]));
let hasNativeAnsible;
try { execFileSync("ansible-inventory", ["--version"], { stdio: "pipe", timeout: 15000 }); hasNativeAnsible = true; }
catch (error) { if (error.code !== "ENOENT") throw error; hasNativeAnsible = false; }
const native = { skip: hasNativeAnsible ? false : "Requires the real ansible-inventory executable (installed in CI)." };

const compiled = compileServerModules(["asset-execution", "ansible-control", "host-credentials", "audit-correlation"]);
// The network observation is the only replaced server module boundary. Native
// inventory resolution, immutable bindings, SQLite locks and report publication
// execute their production implementations.
copyFileSync(path.join(compiled.directory, "ssh-access.mjs"), path.join(compiled.directory, "actual-ssh-access.mjs"));
writeFileSync(path.join(compiled.directory, "ssh-access.mjs"), [
  'export * from "./actual-ssh-access.mjs";',
  'let observe;',
  'export function installObservation(callback) { observe = callback; }',
  'export async function probeTrustedAssetIdentity(connection) {',
  '  if (!observe) throw new Error("Unexpected SSH identity observation");',
  '  return observe(connection);',
  '}',
].join("\n"));
const { installObservation } = await import(compiled.url("ssh-access"));
const { prepareAssetExecution } = await import(compiled.url("asset-execution"));
const { freezeInventoryTargets, connectionFromInventoryVariables, explicitInventoryConnectionId } = await import(compiled.url("inventory"));
const { runAnsiblePlaybook } = await import(compiled.url("ansible-control"));
const credentials = await import(compiled.url("host-credentials"));
const identity = await import(compiled.url("asset-binding"));
const store = await import(compiled.url("state-store"));
const reports = await import(compiled.url("ansible-reports"));
const { buildHostCorrelation } = await import(compiled.url("audit-correlation"));
let directory;
let inventoryPath;

function writeInventory(lines) {
  writeFileSync(inventoryPath, "[linux_hosts]\n" + lines.join("\n") + "\n");
}
function observed(connection, key = "A") {
  const endpoint = connection.port === 22 ? connection.address : "[" + connection.address + "]:" + connection.port;
  return { machineIdSha256: identity.machineIdentityHash("1234567890abcdef1234567890abcdef"),
    sshHostKeyFingerprint: "SHA256:" + key.repeat(43), observedAt: new Date().toISOString(),
    hostKeyLine: endpoint + " ssh-ed25519 " + key.repeat(64), hostKeyAlgorithms: "ssh-ed25519" };
}
function deferred() {
  let resolve;
  const promise = new Promise((accept) => { resolve = accept; });
  return { promise, resolve };
}

beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-asset-execution-test-"));
  for (const name of ["web", "ansible/group_vars", "ansible/playbooks", "reports", "state", "bin", "tmp"]) mkdirSync(path.join(directory, name), { recursive: true });
  copyFileSync(path.join(webDirectory, "../ansible/group_vars/linux_hosts.yml"), path.join(directory, "ansible/group_vars/linux_hosts.yml"));
  inventoryPath = path.join(directory, "ansible/inventory.ini");
  writeInventory(["fixture-one ansible_host=192.0.2.10 ansible_user=audit ansible_port=2222"]);
  process.chdir(path.join(directory, "web"));
  process.env.PATH = path.join(directory, "bin") + path.delimiter + originalEnvironment.PATH;
  process.env.TMPDIR = path.join(directory, "tmp");
  process.env.HCP_STATE_DIR = path.join(directory, "state");
  process.env.HCP_REPORTS_DIR = path.join(directory, "reports");
  process.env.HCP_AUDIT_HMAC_KEY = "asset-execution-regression-fixture";
  process.env.HCP_SSH_PRIVATE_KEY_PATH = path.join(directory, "shared key");
  process.env.HCP_KNOWN_HOSTS_PATH = path.join(directory, "live known_hosts");
  process.env.HCP_ASSET_EXECUTION_RECORD = path.join(directory, "execution.json");
  delete process.env.HCP_ASSET_CHILD_FAIL;
  writeFileSync(process.env.HCP_SSH_PRIVATE_KEY_PATH, "fixture key; no SSH process uses it\n", { mode: 0o600 });
  writeFileSync(process.env.HCP_KNOWN_HOSTS_PATH, "mutable trust fixture\n", { mode: 0o600 });
  installObservation(undefined);
});
afterEach(() => {
  process.chdir(originalCwd);
  for (const [key, value] of Object.entries(originalEnvironment)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  rmSync(directory, { recursive: true, force: true });
});
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test("native inventory resolves the repository's default key template without evaluating arbitrary Jinja", native, () => {
  const frozen = freezeInventoryTargets("fixture-one");
  try {
    const target = frozen.targets[0];
    assert.match(target.variables.ansible_ssh_private_key_file, /lookup\('env', 'HCP_STATE_DIR'\)/,
      "the real Ansible CLI leaves the standard group_vars expression unresolved");
    assert.equal(target.connection.privateKeyPath, process.env.HCP_SSH_PRIVATE_KEY_PATH);
    assert.equal(target.connection.address, "192.0.2.10");
    assert.equal(target.connection.port, 2222);
    assert.equal(statSync(frozen.directory).mode & 0o777, 0o700);
    assert.equal(connectionFromInventoryVariables("fixture-one", { ...target.variables, ansible_ssh_private_key_file: "~/.ssh/audit-key" }).privateKeyPath,
      path.join(homedir(), ".ssh/audit-key"));
    assert.throws(() => connectionFromInventoryVariables("fixture-one", { ...target.variables,
      ansible_ssh_private_key_file: "{{ lookup('pipe', 'unexpected-command') }}" }), /шаблон приватного SSH-ключа/);
  } finally { rmSync(frozen.directory, { recursive: true, force: true }); }
});

test("the standard group_vars template preserves a verified per-host credential in the frozen run", native, async () => {
  const connection = { alias: "fixture-one", address: "192.0.2.10", port: 2222, user: "audit" };
  const enrollment = credentials.beginHostCredential(connection);
  try {
    writeFileSync(enrollment.keyPath, "fixture private key\n", { mode: 0o600 });
    credentials.markHostCredentialVerified(enrollment.credential.id, connection, "ssh-ed25519 " + "A".repeat(64), "SHA256:" + "A".repeat(43));
  } finally { enrollment.release(); }
  writeInventory(["fixture-one ansible_host=192.0.2.10 ansible_user=audit ansible_port=2222 hcp_ssh_credential_id=" + enrollment.credential.id]);
  let probe;
  installObservation((value) => { probe = value; return observed(value); });
  const execution = await prepareAssetExecution("fixture-one", { authenticate: true });
  try {
    const host = JSON.parse(readFileSync(execution.inventoryPath, "utf8")).all.hosts["fixture-one"];
    assert.equal(probe.privateKeyPath, enrollment.keyPath);
    assert.equal(host.ansible_ssh_private_key_file, enrollment.keyPath);
    assert.notEqual(host.ansible_ssh_private_key_file, process.env.HCP_SSH_PRIVATE_KEY_PATH);
    assert.equal(execution.bindings.get("fixture-one").status, "verified");
  } finally { execution.release(); }
});

function installRecordingAnsibleChild() {
  // This child is deliberately not a scanner. It records the actual invocation,
  // resolves the supplied frozen inventory with native Ansible, and writes a
  // controlled report so the test can exercise the production publication path.
  writeFileSync(path.join(directory, "bin/ansible-playbook"), [
    "#!/usr/bin/env python3",
    "import json, os, pathlib, shlex, subprocess, sys",
    "args = sys.argv[1:]",
    "inventory = args[args.index('-i') + 1]",
    "variables = {}",
    "def literal(value):",
    "    if isinstance(value, dict) and set(value) == {'__ansible_unsafe'}: return value['__ansible_unsafe']",
    "    return value",
    "for i, arg in enumerate(args):",
    "    if arg in ('-e', '--extra-vars'):",
    "        value = args[i + 1]",
    "        extra = json.load(open(value[1:])) if value.startswith('@') else json.loads(value)",
    "        variables.update({key: literal(item) for key, item in extra.items()})",
    "resolved = json.loads(subprocess.check_output(['ansible-inventory', '-i', inventory, '--list', '--playbook-dir', os.path.join(os.getcwd(), 'ansible', 'playbooks')]))",
    "hosts = resolved['_meta']['hostvars']",
    "ssh_args = shlex.split(variables['ansible_ssh_args'])",
    "known_hosts = next(item.split('=', 1)[1] for item in ssh_args if item.startswith('UserKnownHostsFile='))",
    "record = {'args': args, 'hosts': hosts, 'inventoryPath': inventory, 'inventoryMode': os.stat(inventory).st_mode & 0o777, 'trustPath': known_hosts, 'trust': open(known_hosts).read(), 'sshArgs': ssh_args, 'extraVars': variables}",
    "json.dump(record, open(os.environ['HCP_ASSET_EXECUTION_RECORD'], 'w'))",
    "destination = pathlib.Path(variables['hcp_reports_dir'])",
    "for alias, host in hosts.items():",
    "    report = {'inventoryHost': alias, 'hostname': alias, 'mode': 'agentless', 'profileId': variables['audit_profile'], 'createdAt': '2026-10-28T12:00:00Z', 'scanner': {'available': True, 'partial': os.environ.get('HCP_ASSET_CHILD_FAIL') == 'true'}, 'findings': [], 'executedAddress': host['ansible_host'], 'assetBinding': {'status': 'untrusted-child-claim'}}",
    "    if os.environ.get('HCP_ASSET_CHILD_FAIL') == 'true': report['scanner']['error'] = 'Controlled scanner failure after a diagnostic report'",
    "    report_path = destination / (alias + '-' + variables['audit_profile'] + '-' + variables['report_run_id'] + '.json')",
    "    report_path.write_text(json.dumps(report))",
    "if os.environ.get('HCP_ASSET_CHILD_FAIL') == 'true': sys.exit(2)",
    "print('Controlled Ansible boundary completed')",
  ].join("\n") + "\n", { mode: 0o700 });
}

for (const fails of [false, true]) test("live inventory and trust edits during identity capture cannot change executed or published targets" + (fails ? "; failed child retains its diagnostic reports" : ""), native, async () => {
  writeInventory([
    "fixture-one ansible_host=192.0.2.10 ansible_user=audit ansible_port=2222",
    "fixture-two ansible_host=192.0.2.11 ansible_user=audit ansible_port=2222",
  ]);
  installRecordingAnsibleChild();
  process.env.HCP_ASSET_CHILD_FAIL = String(fails);
  const entered = deferred(); const resume = deferred(); const probes = [];
  installObservation(async (connection) => {
    probes.push(connection);
    if (probes.length === 1) { entered.resolve(); await resume.promise; }
    return observed(connection);
  });
  const running = runAnsiblePlaybook({ action: "agentlessAudit", profileId: "basic_linux", limit: "linux_hosts" });
  // Attach rejection handling before releasing the deliberately failing child.
  const completed = running.then((value) => ({ value }), (error) => ({ error }));
  await entered.promise;
  writeInventory(["replacement ansible_host=192.0.2.99 ansible_user=other ansible_port=2200"]);
  writeFileSync(process.env.HCP_KNOWN_HOSTS_PATH, "[192.0.2.99]:2200 ssh-ed25519 " + "B".repeat(64) + "\n");
  resume.resolve();
  const result = await completed;
  if (fails) assert.ok(result.error, "fixture Ansible child exits nonzero");
  else assert.equal(result.error, undefined);
  assert.deepEqual(probes.map((value) => value.address), ["192.0.2.10", "192.0.2.11"], "all targets were resolved before the first network await");
  const execution = JSON.parse(readFileSync(process.env.HCP_ASSET_EXECUTION_RECORD, "utf8"));
  assert.notEqual(execution.inventoryPath, inventoryPath);
  assert.equal(execution.inventoryMode, 0o600);
  assert.deepEqual(Object.keys(execution.hosts).sort(), ["fixture-one", "fixture-two"]);
  assert.equal(execution.hosts["fixture-one"].ansible_host, "192.0.2.10");
  assert.equal(execution.hosts["fixture-two"].ansible_host, "192.0.2.11");
  assert.equal(execution.hosts["fixture-one"].ansible_port, 2222);
  assert.equal(execution.hosts["fixture-one"].ansible_ssh_private_key_file, process.env.HCP_SSH_PRIVATE_KEY_PATH);
  assert.notEqual(execution.trustPath, process.env.HCP_KNOWN_HOSTS_PATH);
  assert.equal(execution.trust, probes.map((connection) => observed(connection).hostKeyLine).join("\n") + "\n");
  for (const option of ["StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "UpdateHostKeys=no", "HostKeyAlgorithms=ssh-ed25519"]) assert.ok(execution.sshArgs.includes(option));
  assert.equal(execution.extraVars.ansible_ssh_common_args, "");
  assert.equal(execution.extraVars.ansible_host_key_checking, true);
  const saved = readdirSync(process.env.HCP_REPORTS_DIR).filter((file) => file.endsWith(".json"));
  assert.equal(saved.length, 2, "removing an alias during capture cannot discard its completed report");
  for (const file of saved) {
    const report = JSON.parse(readFileSync(path.join(process.env.HCP_REPORTS_DIR, file), "utf8"));
    const expectedConnection = probes.find((connection) => connection.address === report.executedAddress);
    assert.ok(expectedConnection);
    assert.equal(report.assetBinding.status, "verified", "publication replaces untrusted report-provided identity");
    assert.equal(report.assetBinding.assetId, identity.assetIdForObservation(observed(expectedConnection)));
    assert.equal(report.assetBinding.connectionId, identity.assetConnectionId(expectedConnection));
    assert.equal(report.assetBinding.alias, report.inventoryHost);
    assert.equal(report.scanner.partial, fails);
    if (fails) assert.match(report.scanner.error, /Controlled scanner failure/);
    assert.equal(reports.readAnsibleReport(file.slice(0, -5)).assetBindingInvalid, false);
  }
  assert.equal(existsSync(execution.inventoryPath), false);
  assert.equal(existsSync(execution.trustPath), false);
  assert.equal(existsSync(execution.extraVars.hcp_reports_dir), false);
  const binding = store.currentAssetBinding("fixture-one");
  const lease = store.acquireAssetExecution([{ alias: binding.alias, binding }]);
  store.releaseAssetExecution(lease);
});

test("two aliases observing conflicting keys at one endpoint stop before child execution", native, async () => {
  writeInventory([
    "fixture-one ansible_host=192.0.2.10 ansible_user=audit ansible_port=2222",
    "fixture-two ansible_host=192.0.2.10 ansible_user=audit ansible_port=2222",
  ]);
  installRecordingAnsibleChild();
  let count = 0;
  installObservation((connection) => observed(connection, ++count === 1 ? "A" : "B"));
  await assert.rejects(runAnsiblePlaybook({ action: "agentlessAudit", profileId: "basic_linux", limit: "linux_hosts" }), (error) => {
    assert.match(error.message, /endpoint сменил ключ/); assert.equal(error.remoteOutcome, "not_started"); return true;
  });
  assert.equal(count, 2);
  assert.equal(existsSync(process.env.HCP_ASSET_EXECUTION_RECORD), false);
  assert.deepEqual(readdirSync(process.env.HCP_REPORTS_DIR), []);
  assert.deepEqual(readdirSync(process.env.TMPDIR).filter((name) => name.startsWith("hcp-execution-inventory-")), []);
  const binding = store.currentAssetBinding("fixture-one");
  const lease = store.acquireAssetExecution([{ alias: binding.alias, binding }]);
  store.releaseAssetExecution(lease);
});

test("a default-port inventory change excludes the old machine and endpoint without authenticating the new network report", native, () => {
  const alias = "fixture-one";
  const original = { address: "192.0.2.10", user: "audit", port: 22 };
  const replacement = { ...original, address: "192.0.2.99" };
  writeInventory([alias + " ansible_host=" + original.address + " ansible_user=audit"]);
  const binding = store.recordAssetObservation({ alias, observation: observed(original), connectionId: identity.assetConnectionId(original) });
  function saveReport(id, assetBinding, mode) {
    writeFileSync(path.join(process.env.HCP_REPORTS_DIR, id + ".json"), JSON.stringify({ inventoryHost: alias, hostname: alias,
      createdAt: new Date().toISOString(), mode, profileId: "basic_linux", assetBinding, scanner: { available: true, partial: false },
      findings: [{ id: "fixture-issue", profileId: "basic_linux", source: mode === "ssh-audit" ? "ssh_audit" : "agentless", title: "Fixture issue", description: "Controlled observation", recommendation: "Review", category: "Fixture", risk: "high", status: "failed", remediationAvailable: false }] }));
  }
  const networkBinding = (connection) => ({ version: 1, status: "unknown", alias, reason: "unauthenticated_network_scan",
    connectionId: identity.assetConnectionId(connection), aliasGeneration: binding.generation, observedAt: new Date().toISOString() });
  saveReport("old-machine", binding, "agentless");
  saveReport("old-network", networkBinding(original), "ssh-audit");
  assert.equal(explicitInventoryConnectionId(alias), identity.assetConnectionId(original), "native Ansible supplies the omitted default port");
  assert.deepEqual(buildHostCorrelation(alias).findings.flatMap((finding) => finding.sources.map((source) => source.reportId)).sort(), ["old-machine", "old-network"]);

  writeInventory([alias + " ansible_host=" + replacement.address + " ansible_user=audit"]);
  saveReport("new-network", networkBinding(replacement), "ssh-audit");
  assert.equal(explicitInventoryConnectionId(alias), identity.assetConnectionId(replacement));
  const correlation = buildHostCorrelation(alias);
  assert.deepEqual(correlation.findings.flatMap((finding) => finding.sources.map((source) => source.reportId)), ["new-network"]);
  for (const id of ["old-machine", "old-network"]) {
    const coverage = correlation.coverage.find((entry) => entry.reportId === id);
    assert.equal(coverage.current, false);
    assert.equal(coverage.auditEvidence, false);
    assert.ok(coverage.coverageIssues.includes("asset_connection_changed"));
  }
  const currentNetwork = correlation.coverage.find((entry) => entry.reportId === "new-network");
  assert.equal(currentNetwork.current, true);
  assert.ok(currentNetwork.coverageIssues.includes("asset_identity_unverified"));
  const networkReport = reports.readAnsibleReport("new-network");
  assert.equal(networkReport.assetBinding.status, "unknown");
  assert.equal(identity.sameAssetEvidence(binding, networkReport.assetBinding), false);
  assert.equal(store.currentAssetBinding(alias).connectionId, identity.assetConnectionId(original), "network scanning never silently rebinds the authenticated machine");

  writeInventory([alias + " ansible_host=192.0.2.99 ansible_user=audit ansible_port=not-a-port"]);
  assert.equal(explicitInventoryConnectionId(alias), "unresolved");
  assert.equal(buildHostCorrelation(alias).findings.length, 0, "unresolved live configuration cannot reuse the old identity as evidence");
});

test("current evidence uses effective host_vars rather than a shadowed inline endpoint", native, () => {
  const alias = "fixture-one";
  writeInventory([alias + " ansible_host=192.0.2.10 ansible_user=audit ansible_port=22"]);
  mkdirSync(path.join(directory, "ansible/host_vars"));
  writeFileSync(path.join(directory, "ansible/host_vars/fixture-one.yml"), "ansible_host: 192.0.2.99\n");
  const frozen = freezeInventoryTargets(alias);
  try {
    const effective = frozen.targets[0].connection;
    assert.equal(effective.address, "192.0.2.99", "the real Ansible resolver applies host_vars precedence");
    assert.equal(explicitInventoryConnectionId(alias), identity.assetConnectionId(effective), "displayed current endpoint must agree with actual execution");
  } finally { rmSync(frozen.directory, { recursive: true, force: true }); }
});
