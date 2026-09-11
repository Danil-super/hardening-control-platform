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
  const resolve = (name) => name in replacements ? replacements[name] : name === "next/server" ? next : nativeRequire(name);
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

test("legacy DELETE cannot erase audit or remediation evidence", async () => {
  const route = load("app/api/ansible/reports/[reportId]/route.ts", { "@/lib/ansible-reports": {} });
  const response = await route.DELETE();
  assert.equal(response.status, 405);
  assert.equal((await response.json()).error, "report_history_preserved");
});

test("custom variable values remain one JSON value rather than injected Ansible options", async () => {
  const previousEnable = process.env.HCP_ENABLE_CUSTOM_AUDITS;
  const previousProduction = process.env.HCP_PRODUCTION_MODE;
  process.env.HCP_ENABLE_CUSTOM_AUDITS = "true";
  process.env.HCP_PRODUCTION_MODE = "false";
  let executedArgs;
  const exec = () => {};
  exec[promisify.custom] = async (_binary, args) => { executedArgs = args; return { stdout: "", stderr: "" }; };
  const registry = load("lib/playbook-registry.ts", {
    "node:child_process": { execFile: exec },
    "@/lib/ansible-control": { getRepoRoot: () => "/tmp/fake-hcp-test", isSafeLimit: () => true, appendIncident: () => {}, playbooks: {} },
  });
  const playbook = { id: "custom-test", kind: "audit", source: "custom", file: "playbook.yml", requiresLimit: false, timeout: 10, variables: [{ name: "package_name", required: true }] };
  try {
    await registry.runRegisteredPlaybook({ playbook, variables: { package_name: "openssl ansible_connection=local" } });
    assert.deepEqual(JSON.parse(executedArgs[executedArgs.indexOf("-e") + 1]), { package_name: "openssl ansible_connection=local" });
    await assert.rejects(registry.runRegisteredPlaybook({ playbook: { ...playbook, source: "builtin" }, variables: {} }), /\/api\/ansible\/run/);
    await assert.rejects(registry.runRegisteredPlaybook({ playbook: { ...playbook, kind: "response" }, variables: {} }), /транзакционный/);
    process.env.HCP_PRODUCTION_MODE = "true";
    await assert.rejects(registry.syntaxCheckPlaybook(playbook), /production/);
    await assert.rejects(registry.runRegisteredPlaybook({ playbook, variables: { package_name: "openssl" } }), /production/);
  } finally {
    if (previousEnable === undefined) delete process.env.HCP_ENABLE_CUSTOM_AUDITS; else process.env.HCP_ENABLE_CUSTOM_AUDITS = previousEnable;
    if (previousProduction === undefined) delete process.env.HCP_PRODUCTION_MODE; else process.env.HCP_PRODUCTION_MODE = previousProduction;
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
