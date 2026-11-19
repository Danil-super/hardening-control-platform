import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import ts from "typescript";
import { compileServerModules } from "./_typescript-loader.mjs";
import { after } from "node:test";

const compiled = compileServerModules(["inventory"]);
const { parseStaticInventory } = await import(compiled.url("inventory"));
after(() => require("node:fs").rmSync(compiled.directory, { recursive: true, force: true }));

const require = createRequire(import.meta.url);
const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function load(file, stubs) {
  const code = ts.transpileModule(readFileSync(path.join(webRoot, file), "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", code)(
    name => Object.hasOwn(stubs, name) ? stubs[name] : require(name),
    module, module.exports,
  );
  return module.exports;
}

test("host list exposes a zero-audit summary on a new install with no reports directory", async () => {
  const observed = [];
  let viewResolved = false;
  let viewCalls = 0;
  const endpoint = load("app/api/ansible/hosts/route.ts", {
    "@/lib/inventory": { parseStaticInventory, withInventoryConnectionView: async work => {
      viewCalls++;
      await Promise.resolve();
      viewResolved = true;
      return work();
    } },
    "node:fs": {
      existsSync: file => String(file).endsWith("/ansible/inventory.ini"),
      readFileSync: () => "[linux_hosts]\nastra-lab ansible_host=192.0.2.10 ansible_user=operator ansible_port=22\n",
    },
    "next/server": { NextResponse: { json: (body, options) => Response.json(body, options) } },
    "@/lib/ansible-reports": {
      getReportsDir: () => "/not-yet-created/reports",
      listAnsibleReportsAsync: async () => [],
      targetAliasFromReport: () => { throw new Error("No reports exist"); },
    },
    "@/lib/host-risk-summary": {
      buildHostRiskSummary: (alias, reports) => {
        assert.equal(viewResolved, true, "host risks must wait for the nonblocking inventory view");
        observed.push({ alias, reports });
        return {
          critical: 0, high: 0, medium: 0, low: 0, unknown: 0, info: 0,
          total: 0, auditCount: 0, freshCount: 0, partialCount: 0,
          staleCount: 0, identityExcludedCount: 0, maxAgeHours: 168,
          scope: "latest-per-tool-and-profile",
        };
      },
      isSecurityAudit: () => true,
    },
    "@/lib/ssh-access": { normalizeSshPort: value => Number(value) || 22 },
    "@/lib/host-credentials": { publicCredentialSummary: () => ({ credentialReady: false }) },
    "@/lib/state-store": {},
  });
  const response = await endpoint.GET();
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(viewCalls, 1);
  assert.equal(body.summary.total, 1);
  assert.equal(body.summary.withReports, 0);
  assert.equal(body.hosts[0].alias, "astra-lab");
  assert.equal(body.hosts[0].lastReport, null);
  assert.equal(body.hosts[0].reportCount, 0);
  assert.equal(body.hosts[0].riskSummary.auditCount, 0);
  assert.equal(body.hosts[0].riskSummary.freshCount, 0);
  assert.deepEqual(observed, [{ alias: "astra-lab", reports: [] }]);
});

test("group edits preserve connection settings and inherited membership without running SSH", async () => {
  let inventory = "[linux_hosts:children]\nweb\n[web:children]\nfrontend\n[frontend]\nnode1 ansible_host=192.0.2.10 ansible_user=operator custom_var='keep this'\n[qa]\nnode1 maintenance=true\n[empty_group]\n";
  const endpoint = load("app/api/ansible/hosts/route.ts", {
    "@/lib/inventory": { parseStaticInventory, withInventoryConnectionView: async work => work() },
    "node:fs": { existsSync: path => String(path).endsWith("/ansible/inventory.ini"), readFileSync: () => inventory, realpathSync: path => path,
      writeFileSync: (_file, value) => { inventory = value; }, renameSync: () => {} },
    "next/server": { NextResponse: { json: (body, options) => Response.json(body, options) } },
    "@/lib/ansible-reports": { getReportsDir: () => "/fixture", listAnsibleReportsAsync: async () => [] },
    "@/lib/host-risk-summary": { buildHostRiskSummary: () => ({}), isSecurityAudit: () => true },
    "@/lib/ssh-access": { normalizeSshPort: value => Number(value) || 22 },
    "@/lib/host-credentials": { publicCredentialSummary: () => ({}) },
    "@/lib/state-store": { assertAssetIdle: () => {}, hasActiveRemediationForHost: () => false,
      listOpenScapPolicies: () => [{ groupName: "frontend" }], listOpenScapExceptions: () => [], listAstraOvalPolicies: () => [] },
  });
  const url = "http://localhost/api/ansible/hosts";
  const patch = body => endpoint.PATCH(new Request(url, { method: "PATCH", body: JSON.stringify(body) }));
  const full = await (await endpoint.GET()).json();
  assert.deepEqual(full.hosts[0].groups, ["frontend", "linux_hosts", "qa", "web"]);
  assert.equal((await patch({ group: "database" })).status, 201);
  assert.equal((await patch({ group: "node1" })).status, 400);
  assert.equal((await patch({ alias: "node1", groups: ["database", "frontend"], previousGroups: ["frontend", "qa"] })).status, 200);
  assert.equal((await patch({ alias: "node1", groups: [], previousGroups: ["frontend", "qa"] })).status, 409);
  assert.match(inventory, /node1 ansible_host=192\.0\.2\.10 ansible_user=operator custom_var='keep this'/);
  assert.match(inventory, /node1 maintenance=true/);
  const { groups, hosts } = await (await endpoint.GET(new Request(url + "?view=groups"))).json();
  assert.ok(groups.includes("empty_group"));
  assert.deepEqual(hosts, [{ alias: "node1", groups: ["database", "frontend", "linux_hosts", "web"], directGroups: ["database", "frontend", "linux_hosts"] }]);

  const removeGroup = (group, expectedMembers) => endpoint.DELETE(new Request(url, {
    method: "DELETE", body: JSON.stringify({ group, confirmedGroup: group, expectedMembers }),
  }));
  assert.equal((await removeGroup("linux_hosts", ["node1"])).status, 400);
  assert.equal((await removeGroup("frontend", ["node1"])).status, 409);
  assert.equal((await removeGroup("web", ["node1"])).status, 409);
  assert.equal((await removeGroup("database", [])).status, 409);
  assert.equal((await removeGroup("database", ["node1"])).status, 200);
  assert.equal((await removeGroup("empty_group", [])).status, 200);
  assert.deepEqual(parseStaticInventory(inventory).hosts[0].groups, ["all", "frontend", "linux_hosts", "web"]);
  assert.match(inventory, /ansible_user=operator custom_var='keep this'/);
  assert.doesNotMatch(inventory, /\[(database|empty_group)\]/);
});
