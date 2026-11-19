import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import vm from "node:vm";
import test from "node:test";
import ts from "typescript";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const nativeRequire = createRequire(import.meta.url);

// Execute real handlers; replace only process/network boundaries to prove
// rejected requests cannot reach Ansible, network scans or inventory writes.
function load(relativePath, replacements = {}) {
  const filename = path.join(webDir, relativePath);
  const code = ts.transpileModule(readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
  }).outputText;
  const module = { exports: {} };
  const next = { NextResponse: { json: (body, init = {}) => Response.json(body, init) } };
  const resolve = (name) => name in replacements ? replacements[name] : name === "next/server" ? next
    : ["@/lib/ansible-literal-vars", "@/lib/audit-tool-labels"].includes(name) ? load(`${name.slice(2)}.ts`) : nativeRequire(name);
  vm.runInThisContext(`(function(require, module, exports) { ${code}\n})`, { filename })(resolve, module, module.exports);
  return module.exports;
}

test("legacy builtin runner delegates to the managed action without inventing confirmation", async () => {
  let delegated;
  const route = load("app/api/ansible/playbooks/[playbookId]/run/route.ts", {
    "@/lib/playbook-registry": {
      getRegisteredPlaybook: () => ({ id: "networkPortScan", source: "builtin" }),
      runRegisteredPlaybook: () => { throw new Error("raw runner must not run"); },
    },
    "@/app/api/ansible/run/route": { POST: async (request) => { delegated = await request.json(); return Response.json({ error: "confirmation_required" }, { status: 400 }); } },
    "@/lib/ssh-bootstrap": { credentialTransportAllowed: () => true },
  });
  const response = await route.POST(new Request("http://localhost/api/ansible/playbooks/networkPortScan/run", {
    method: "POST", body: JSON.stringify({ action: "closePort", limit: "target" }),
  }), { params: Promise.resolve({ playbookId: "networkPortScan" }) });
  assert.equal(response.status, 400);
  assert.equal(delegated.action, "networkPortScan");
  assert.equal(delegated.confirmAudit, undefined);
  assert.equal(delegated.limit, "target");
});

test("discovery cannot bypass verified SSH onboarding", async () => {
  const route = load("app/api/ansible/discover/route.ts", {
    "@/lib/network-discovery": load("lib/network-discovery.ts"),
    "node:child_process": { execFile: () => { throw new Error("discovery must reject before process spawn"); } },
    "node:net": { Socket: class { constructor() { throw new Error("discovery must reject before network scan"); } } },
  });
  const response = await route.POST(new Request("http://localhost/api/ansible/discover", {
    method: "POST", body: JSON.stringify({ cidr: "192.168.1.0/24", addToInventory: true }),
  }));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "verified_onboarding_required");
});

test("report deletion requires confirmation and cannot erase referenced evidence", async () => {
  let removed = false;
  const route = load("app/api/ansible/reports/[reportId]/route.ts", {
    "@/lib/ansible-reports": {
      readAnsibleReport: () => ({ id: "host-1-nmap-run-1", mode: "nmap" }),
      targetAliasFromReport: () => "host-1",
      listAnsibleReportDependents: () => [{ id: "host-1-dependent", mode: "dependency-track" }],
      deleteAnsibleReport: () => { removed = true; return { id: "host-1-nmap-run-1", hostAlias: "host-1", mode: "nmap", sbomRemoved: false }; },
    },
    // This suite isolates route guards; the real SQLite lock and renderer race
    // are exercised together in project-report-lifecycle.test.mjs.
    "@/lib/state-store": { withReportEvidenceLock: (operation) => operation(), appendAuditEvent: () => {}, listStoredReportReferences: () => [] },
    "@/lib/project-report": { listProjectReportSourceReferences: () => [] },
  });
  const params = { params: Promise.resolve({ reportId: "host-1-nmap-run-1" }) };
  const unconfirmed = await route.DELETE(new Request("http://localhost/api/ansible/reports/host-1-nmap-run-1", { method: "DELETE", body: "{}" }), params);
  assert.equal(unconfirmed.status, 400);
  assert.equal((await unconfirmed.json()).error, "delete_confirmation_required");

  const referenced = await route.DELETE(new Request("http://localhost/api/ansible/reports/host-1-nmap-run-1", {
    method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmReportId: "host-1-nmap-run-1" }),
  }), params);
  assert.equal(referenced.status, 409);
  assert.equal((await referenced.json()).error, "report_is_referenced");
  assert.equal(removed, false);
});

test("a standalone confirmed report is removed and the deletion is recorded", async () => {
  let removed = false;
  const events = [];
  const route = load("app/api/ansible/reports/[reportId]/route.ts", {
    "@/lib/ansible-reports": {
      readAnsibleReport: () => ({ id: "host-1-nmap-run-1", mode: "nmap" }),
      targetAliasFromReport: () => "host-1",
      listAnsibleReportDependents: () => [],
      deleteAnsibleReport: () => { removed = true; return { id: "host-1-nmap-run-1", hostAlias: "host-1", mode: "nmap", sbomRemoved: true }; },
    },
    "@/lib/state-store": { withReportEvidenceLock: (operation) => operation(), appendAuditEvent: (...args) => events.push(args), listStoredReportReferences: () => [] },
    "@/lib/project-report": { listProjectReportSourceReferences: () => [] },
  });
  const response = await route.DELETE(new Request("http://localhost/api/ansible/reports/host-1-nmap-run-1", {
    method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmReportId: "host-1-nmap-run-1" }),
  }), { params: Promise.resolve({ reportId: "host-1-nmap-run-1" }) });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).ok, true);
  assert.equal(removed, true);
  assert.equal(events[0][0], "ansible_report_deleted");
});

test("read-only deletion preview names the exact PDF and links to its host and export", async () => {
  const id = "project_report_53f754a3-6c4c-4cf9-8791-17aa3e856e4e";
  const route = load("app/api/ansible/reports/[reportId]/route.ts", {
    "@/lib/ansible-reports": {
      listAnsibleReportsAsync: async () => [{ id: "host-1-facts-run", mode: "facts" }],
      listAnsibleReportDependentsAsync: async () => [],
      targetAliasFromReport: () => "host-1",
      listAnsibleReportDependents: () => [],
      readAnsibleReport: () => { throw new Error("preview must not load raw scanner trees"); },
      deleteAnsibleReport: () => { throw new Error("preview must never delete"); },
    },
    "@/lib/state-store": { listStoredReportReferences: () => [], getProjectReportRecord: () => ({ id, createdAt: "2026-10-10T10:07:47Z", subject: { projectName: "test_mk1", clientName: "Organisation" } }) },
    "@/lib/project-report": { listProjectReportSourceReferences: () => [{ id, hostAlias: "host-1", snapshotReadable: true }] },
  });
  const response = await route.GET(new Request("http://localhost/api/ansible/reports/host-1-facts-run?dependencies=1"), { params: Promise.resolve({ reportId: "host-1-facts-run" }) });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.ok, true);
  assert.equal(result.canDelete, false);
  assert.match(result.message, /PDF/);
  assert.equal(result.references.length, 1);
  assert.match(result.references[0].label, /test_mk1/);
  assert.match(result.references[0].description, /Organisation/);
  assert.match(result.references[0].description, /13:07:47/);
  assert.equal(result.references[0].href, `/project-reports?host=host-1&report=${id}#${id}`);
});

test("unreferenced preview is deletable and a later PDF reference still blocks DELETE", async () => {
  let saved = false;
  let removed = false;
  const route = load("app/api/ansible/reports/[reportId]/route.ts", {
    "@/lib/ansible-reports": {
      listAnsibleReportsAsync: async () => [{ id: "host-1-facts-run", mode: "facts" }],
      listAnsibleReportDependentsAsync: async () => [],
      readAnsibleReport: () => ({ id: "host-1-facts-run", mode: "facts" }),
      targetAliasFromReport: () => "host-1", listAnsibleReportDependents: () => [],
      deleteAnsibleReport: () => { removed = true; },
    },
    "@/lib/state-store": { withReportEvidenceLock: (operation) => operation(), listStoredReportReferences: () => [], getProjectReportRecord: () => null },
    "@/lib/project-report": { listProjectReportSourceReferences: () => saved ? [{ id: "missing-export", snapshotReadable: false }] : [] },
  });
  const params = { params: Promise.resolve({ reportId: "host-1-facts-run" }) };
  const preview = await route.GET(new Request("http://localhost/api/ansible/reports/host-1-facts-run?dependencies=1"), params);
  assert.equal((await preview.json()).canDelete, true);
  saved = true;
  const result = await route.DELETE(new Request("http://localhost/api/ansible/reports/host-1-facts-run", { method: "DELETE", body: JSON.stringify({ confirmReportId: "host-1-facts-run" }) }), params);
  assert.equal(result.status, 409);
  assert.match((await result.json()).references[0].description, /не удалось проверить/);
  assert.equal(removed, false);
});

test("bulk archive endpoint requires its reviewed token and explicit confirmation", async () => {
  let calls = 0;
  const token = "a".repeat(64);
  const route = load("app/api/ansible/archive/route.ts", {
    "@/lib/archive": {
      archivePreview: () => ({target:"reports",action:"archive",total:2,reports:1,pdf:1,journal:0,token,records:[{kind:"report",id:"private-path-must-not-be-returned"}]}),
      applyArchive: (target,action,provided) => {calls++;assert.equal(target,"reports");assert.equal(action,"archive");assert.equal(provided,token);return 2;},
    },
  });
  const preview = await route.GET(new Request("http://localhost/api/ansible/archive?target=reports&action=archive"));
  assert.equal((await preview.json()).preview.records,undefined);
  const rejected = await route.POST(new Request("http://localhost/api/ansible/archive",{method:"POST",body:JSON.stringify({target:"reports",action:"archive",token})}));
  assert.equal(rejected.status,400);assert.equal(calls,0);
  const accepted = await route.POST(new Request("http://localhost/api/ansible/archive",{method:"POST",body:JSON.stringify({target:"reports",action:"archive",token,confirmation:"archive:reports"})}));
  assert.equal(accepted.status,200);assert.equal(calls,1);
});

test("custom variable values remain one JSON value rather than injected Ansible options", async () => {
  const previousEnable = process.env.HCP_ENABLE_CUSTOM_AUDITS;
  const previousProduction = process.env.HCP_PRODUCTION_MODE;
  process.env.HCP_ENABLE_CUSTOM_AUDITS = "true";
  process.env.HCP_PRODUCTION_MODE = "false";
  let executedArgs;
  let executedRuntime;
  const selectedRuntime = { id: "modern", ansible: "/fixture/ansible", playbook: "/fixture/ansible-playbook", coreVersion: "2.21.5" };
  const exec = () => {};
  exec[promisify.custom] = async (_binary, args) => { executedArgs = args; return { stdout: "", stderr: "" }; };
  const registry = load("lib/playbook-registry.ts", {
    "node:child_process": { execFile: exec },
    "@/lib/ansible-control": { getRepoRoot: () => "/tmp/fake-hcp-test", isSafeLimit: () => true, appendIncident: () => {}, playbooks: {}, onDemandSudoHostForLimit: () => null,
      beginCustomAuditAssetExecution: async () => ({ inventoryPath: "/tmp/frozen-fixture.json", ansibleRuntime: selectedRuntime, release() {} }),
      endCustomAuditAssetExecution: () => {},
      executeAnsiblePlaybook: async ({args, ansibleRuntime}) => { executedArgs = args; executedRuntime = ansibleRuntime; return { stdout: "", stderr: "" }; } },
    "@/lib/inventory": { getInventoryTargetHosts: target => target === "target" ? [{ alias: "target", groups: ["linux_hosts"] }] : [] },
  });
  const playbook = { id: "custom-test", kind: "audit", source: "custom", file: "playbook.yml", requiresLimit: false, timeout: 10, variables: [{ name: "package_name", required: true }] };
  try {
    await registry.runRegisteredPlaybook({ playbook, limit: "target", variables: { package_name: "openssl ansible_connection=local" } });
    assert.deepEqual(executedRuntime, selectedRuntime);
    assert.deepEqual(JSON.parse(executedArgs[executedArgs.indexOf("-e") + 1]), { package_name: { __ansible_unsafe: "openssl ansible_connection=local" } });
    await registry.runRegisteredPlaybook({playbook:{...playbook,variables:[{name:"package_name",required:true,defaultValue:"bash"}]},limit:"target",variables:{}});
    assert.deepEqual(JSON.parse(executedArgs[executedArgs.indexOf("-e") + 1]),{package_name:{__ansible_unsafe:"bash"}});
    await assert.rejects(registry.runRegisteredPlaybook({playbook,limit:"missing",variables:{package_name:"bash"}}),/подключённых хостов/);
    await assert.rejects(registry.runRegisteredPlaybook({playbook:{...playbook,variables:[{name:"count",type:"number",required:true}]},limit:"target",variables:{count:"invalid"}}),/должно быть числом/);
    await assert.rejects(registry.runRegisteredPlaybook({ playbook: { ...playbook, source: "builtin" }, variables: {} }), /\/api\/ansible\/run/);
    await assert.rejects(registry.runRegisteredPlaybook({ playbook: { ...playbook, kind: "response" }, variables: {} }), /транзакционный/);
    process.env.HCP_PRODUCTION_MODE = "true";
    await assert.rejects(registry.syntaxCheckPlaybook(playbook), /тестовом контуре/);
    await assert.rejects(registry.runRegisteredPlaybook({ playbook, variables: { package_name: "openssl" } }), /production/);
  } finally {
    if (previousEnable === undefined) delete process.env.HCP_ENABLE_CUSTOM_AUDITS; else process.env.HCP_ENABLE_CUSTOM_AUDITS = previousEnable;
    if (previousProduction === undefined) delete process.env.HCP_PRODUCTION_MODE; else process.env.HCP_PRODUCTION_MODE = previousProduction;
  }
});

test("custom runner rejects malformed bodies and insecure sudo transport before execution", async () => {
  let executed = false;
  const route = load("app/api/ansible/playbooks/[playbookId]/run/route.ts", {
    "@/lib/playbook-registry": { customPlaybookMode:()=>"test", getRegisteredPlaybook:()=>({id:"custom-test",source:"custom"}), runRegisteredPlaybook:()=>{executed=true;} },
    "@/app/api/ansible/run/route": {},
    "@/lib/ssh-bootstrap": {credentialTransportAllowed:()=>false},
  });
  for (const body of [null, [], {sudoPassword:"bad\npassword"}, {sudoPassword:"fixture-only"}]) {
    const response = await route.POST(new Request("http://untrusted.invalid/api/ansible/playbooks/custom-test/run",{method:"POST",body:JSON.stringify(body)}),{params:Promise.resolve({playbookId:"custom-test"})});
    assert.equal(response.status,400);
  }
  assert.equal(executed,false);
});

test("custom playbook drafts use the durable HCP state directory when it is configured", () => {
  const previousStateDirectory = process.env.HCP_STATE_DIR;
  const registry = load("lib/playbook-registry.ts", {
    "@/lib/ansible-control": { getRepoRoot: () => "/tmp/fake-hcp-test", isSafeLimit: () => true, appendIncident: () => {}, playbooks: {} },
    "@/lib/inventory": {},
  });
  try {
    process.env.HCP_STATE_DIR = "/tmp/hcp-durable-state";
    assert.equal(registry.getCustomPlaybookPath("audit-draft", "/tmp/ignored-repo"), "/tmp/hcp-durable-state/custom-playbooks/audit-draft.yml");
    delete process.env.HCP_STATE_DIR;
    assert.equal(registry.getCustomPlaybookPath("audit-draft", "/tmp/fake-hcp-test"), "/tmp/fake-hcp-test/ansible/playbooks/custom/audit-draft.yml");
  } finally {
    if (previousStateDirectory === undefined) delete process.env.HCP_STATE_DIR; else process.env.HCP_STATE_DIR = previousStateDirectory;
  }
});

test("subnet suggestions remain available when both OS interface enumeration methods fail", async () => {
  const route = load("app/api/ansible/discover/route.ts", {
    "@/lib/network-discovery": load("lib/network-discovery.ts"),
    "node:child_process": { execFile: () => { throw new Error("ip unavailable"); } },
    "node:os": { networkInterfaces: () => { throw new Error("uv_interface_addresses denied"); } },
    "node:fs": { existsSync: () => false },
    "node:net": { Socket: class { constructor() { throw new Error("suggestions must not scan"); } } },
  });
  const response = await route.GET(new Request("http://localhost/api/ansible/discover?address=192.168.56.17"));
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.ok, true);
  assert.equal(result.defaultCidr, "192.168.56.0/24");
  const manual = await (await route.GET(new Request("http://localhost/api/ansible/discover"))).json();
  assert.equal(manual.ok, true);
  assert.equal(manual.defaultCidr, "");
  assert.match(manual.message, /вручную/);
});

test("invalid variable definitions cannot corrupt a saved draft", () => {
  let writes=0;
  const registry=load("lib/playbook-registry.ts",{
    "node:fs":{...nativeRequire("node:fs"),writeFileSync:()=>{writes++;}},
    "@/lib/ansible-control":{getRepoRoot:()=>"/tmp/fake-hcp-test",playbooks:{}},
    "@/lib/inventory":{},
  });
  const variable={name:"package_name",label:"Пакет",type:"string",required:true};
  for(const variables of [[null],[{}],[variable,variable],[{...variable,name:"ansible_connection"}]]) {
    assert.throws(()=>registry.updateCustomPlaybook({playbook:{id:"test-draft",source:"custom",timeout:1000},title:"Draft",kind:"audit",requiresLimit:true,variables,content:"---\n"}),/переменн/i);
  }
  assert.equal(writes,0);
});

test("YAML feedback locates syntax errors without resolving Ansible tags", () => {
  const { playbookYamlIssue } = load("lib/playbook-yaml.ts");
  assert.equal(playbookYamlIssue("- hosts: linux_hosts\n  vars: { package: !unsafe bash }\n"), null);
  assert.equal(playbookYamlIssue("- hosts: linux_hosts\n  tasks: [\n").line, 2);
  assert.match(playbookYamlIssue("hosts: linux_hosts\n").message, /список/);
});

test("custom draft keeps validation for the checked revision only", async () => {
  const fs = nativeRequire("node:fs");
  const directory = fs.mkdtempSync("/tmp/hcp-draft-validation-");
  const environment = { ...process.env };
  let finishSyntax;
  const exec = () => {};
  exec[promisify.custom] = () => new Promise(resolve => { finishSyntax = resolve; });
  const registry = load("lib/playbook-registry.ts", {
    "node:child_process": { execFile: exec },
    "@/lib/ansible-control": {
      getRepoRoot: () => directory, playbooks: {}, isSafeLimit: () => true,
      onDemandSudoHostForLimit: () => null, appendIncident: () => {},
      beginCustomAuditAssetExecution: async () => ({ inventoryPath: "/tmp/fixture-inventory" }),
      endCustomAuditAssetExecution: () => {},
      executeAnsiblePlaybook: async () => ({ stdout: "PLAY RECAP *****\nfixture : ok=1 changed=0 unreachable=0 failed=0 skipped=0\n", stderr: "" }),
    },
    "@/lib/inventory": { getInventoryTargetHosts: () => [{ alias: "fixture", groups: ["linux_hosts"] }] },
  });
  Object.assign(process.env, { HCP_STATE_DIR: directory, HCP_ENABLE_CUSTOM_AUDITS: "true", HCP_PRODUCTION_MODE: "false" });
  try {
    const draft = registry.createCustomPlaybook({ id: "validation-fixture", title: "Проверка", templateId: "audit-package" });
    const initial = registry.getCustomPlaybookValidation(draft);
    assert.ok(initial.revision);
    assert.equal(initial.syntaxAt, undefined);
    assert.equal(initial.trial, undefined);
    const syntax = registry.syntaxCheckPlaybook(draft);
    finishSyntax({ stdout: "", stderr: "" });
    await syntax;
    assert.ok(registry.getCustomPlaybookValidation(draft).syntaxAt);
    await registry.runRegisteredPlaybook({ playbook: draft, limit: "fixture", variables: { package_name: "bash" } });
    assert.equal(registry.getCustomPlaybookValidation(draft).trial.host, "fixture");
    const pending = registry.syntaxCheckPlaybook(draft);
    const updated = registry.updateCustomPlaybook({ playbook: draft, title: draft.title, kind: "audit", requiresLimit: true, variables: draft.variables, content: "- hosts: [" });
    finishSyntax({ stdout: "", stderr: "" });
    await pending;
    assert.equal(registry.readPlaybookContent(updated), "- hosts: [");
    const current = registry.getCustomPlaybookValidation(updated);
    assert.notEqual(current.revision, initial.revision);
    assert.equal(current.syntaxAt, undefined);
    assert.equal(current.trial, undefined);
  } finally {
    for (const key of ["HCP_STATE_DIR", "HCP_ENABLE_CUSTOM_AUDITS", "HCP_PRODUCTION_MODE"]) {
      if (environment[key] === undefined) delete process.env[key];
      else process.env[key] = environment[key];
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("production executes only the trusted package template against one explicit inventory host without sudo", async () => {
  const fs = nativeRequire("node:fs");
  const directory = fs.mkdtempSync("/tmp/hcp-package-scenario-");
  const keys = ["HCP_STATE_DIR", "HCP_ENABLE_CUSTOM_AUDITS", "HCP_PRODUCTION_MODE"];
  const previous = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  let calls = 0;
  const registry = load("lib/playbook-registry.ts", {
    "@/lib/ansible-control": {
      getRepoRoot: () => directory, playbooks: {}, isSafeLimit: () => true, appendIncident: () => {},
      onDemandSudoHostForLimit: () => { throw new Error("The package lookup must stay unprivileged"); },
      beginCustomAuditAssetExecution: async () => ({ inventoryPath: "/tmp/isolated-inventory", bindings: new Map([["fixture", {}]]) }),
      endCustomAuditAssetExecution: () => {},
      executeAnsiblePlaybook: async ({args, becomePassword}) => {
        calls++;
        assert.notEqual(args[2], registry.getCustomPlaybookPath("package-test"));
        assert.equal(fs.readFileSync(args[2], "utf8"), registry.playbookTemplates[0].content.replace("become: true", "become: false"));
        assert.equal(becomePassword, undefined);
        assert.deepEqual(JSON.parse(args[args.indexOf("-e") + 1]), { package_name: { __ansible_unsafe: "python3-yaml" }, ansible_become: false });
        return { stdout: "PLAY RECAP ***\nfixture : ok=6 changed=0 unreachable=0 failed=0\n", stderr: "" };
      },
    },
    "@/lib/inventory": { getInventoryTargetHosts: () => [{ alias: "fixture", groups: ["linux_hosts"] }] },
  });
  Object.assign(process.env, { HCP_STATE_DIR: directory, HCP_ENABLE_CUSTOM_AUDITS: "true", HCP_PRODUCTION_MODE: "true" });
  try {
    const playbook = registry.createCustomPlaybook({ id: "package-test", title: "Версия YAML", templateId: "audit-package" });
    assert.equal(registry.customPlaybookMode(playbook), "package");
    const run = (limit, package_name, options = {}) => registry.runRegisteredPlaybook({ playbook, limit, variables: { package_name }, ...options });
    await assert.rejects(run("linux_hosts", "python3-yaml"), /один/);
    await assert.rejects(run("fixture", "-bad"), /имя пакета/i);
    await assert.rejects(run("fixture", "python3-yaml", { becomePassword: "fixture" }), /sudo/);
    await run("fixture", "python3-yaml");
    assert.equal(calls,1);
    fs.appendFileSync(registry.getCustomPlaybookPath(playbook.id), "\n# изменённый YAML\n");
    await assert.rejects(run("fixture", "python3-yaml"), /тестов/);
    assert.equal(calls,1);
  } finally {
    for (const key of keys) {
      if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key];
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
