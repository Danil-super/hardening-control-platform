import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import ts from "typescript";
import test from "node:test";

const tasks = [];
const config = { mode: "online", url: "https://mirror.example/source.xml", sha256: "a".repeat(64), releasePattern: "1.7.*" };
let resolved, executed = false;
const stubs = {
  "next/server": { after: task => tasks.push(task), NextResponse: { json: (body, options) => Response.json(body, options) } },
  "@/lib/astra-oval-policy": { resolveAstraOvalPolicyForHost(alias) {
    resolved = alias;
    if (alias !== "fixture-host") throw new Error("Unknown host");
    return { groupName: "linux_hosts", config };
  } },
  "@/lib/astra-oval-preparation": {
    ovalPreparationStatus: value => { assert.equal(value, config); return { state: "missing" }; },
    startOvalPreparation: value => { assert.equal(value, config); return { status: { state: "preparing" }, run: async () => { executed = true; } }; },
  },
};
const source = ts.transpileModule(readFileSync(new URL("../app/api/ansible/hosts/oval-preparation/route.ts", import.meta.url), "utf8"),
  { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const module = { exports: {} };
new Function("require", "module", "exports", source)(name => { assert.ok(stubs[name], name); return stubs[name]; }, module, module.exports);
const route = module.exports;

test("readiness uses the host's saved policy and never reflects arbitrary request configuration", async () => {
  const response = await route.GET(new Request("http://localhost/api/ansible/hosts/oval-preparation?alias=fixture-host&url=https://untrusted.example"));
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.source.url, config.url);
  assert.equal(body.preparation.state, "missing");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(tasks.length, 0);
});

test("preparation continues after the response and accepts only a saved host alias", async () => {
  const response = await route.POST(new Request("http://localhost", { method: "POST", body: JSON.stringify({ alias: "fixture-host", config: { url: "https://untrusted.example" } }) }));
  assert.equal(response.status, 202);
  assert.equal(resolved, "fixture-host");
  assert.equal(executed, false);
  assert.equal(tasks.length, 1);
  await tasks.shift()();
  assert.equal(executed, true);
  for (const body of [{}, { alias: "unregistered" }]) {
    const rejected = await route.POST(new Request("http://localhost", { method: "POST", body: JSON.stringify(body) }));
    assert.equal(rejected.status, 400);
    assert.equal(tasks.length, 0);
  }
});
