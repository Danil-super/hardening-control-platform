import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function load(file, stubs) {
  const code = ts.transpileModule(readFileSync(path.join(webRoot, file), "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", code)(
    (name) => Object.hasOwn(stubs, name) ? stubs[name] : require(name),
    module, module.exports,
  );
  return module.exports;
}

let ovalPolicies = [];
let scapPolicies = [];
let member = ["all", "linux_hosts", "astra-1.7"];
let calls = [];

const oval = groupName => ({
  groupName, config: {
    mode: "online", releasePattern: "1.7.*", architectures: ["x86_64"],
    sourceReviewedAt: null, sha256: "a".repeat(64),
    sourceName: "Источник Astra", sourceReference: "CATALOG-ID",
    url: "https://dl.example/secret-path.xml", path: "",
  },
});
const scap = groupName => ({
  groupName, datastream: "/__hcp_builtin__/astra-baseline.xml",
  profile: "xccdf_org.hcp_profile_astra_baseline",
});
const choose = (groups, policies) => policies.find(p => p.groupName !== "linux_hosts" && groups.includes(p.groupName))
  ?? policies.find(p => p.groupName === "linux_hosts" && groups.includes(p.groupName));
const route = load("app/api/ansible/hosts/audit-preparation/route.ts", {
  "next/server": { NextResponse: { json: (body, options) => Response.json(body, options) } },
  "@/lib/inventory": { getInventoryHost: alias => {
    calls.push("inventory:" + alias);
    return member && alias === "node" ? { alias, groups: member } : null;
  } },
  "@/lib/astra-oval-policy": { selectAstraOvalPolicy: (groups, list) => {
    calls.push("oval-selection");
    const p = choose(groups, list);
    if (!p) throw Error("Назначьте OVAL-базу");
    return p;
  } },
  "@/lib/openscap-policy": { selectOpenScapPolicy: (alias, groups, list) => {
    calls.push("scap-selection");
    return { policy: choose(groups, list) ?? null, source: "group" };
  } },
  "@/lib/astra-oval-config": { assertAstraOvalProvenance: config => {
    if (!config.sha256 || !config.sourceName || !config.sourceReference) throw Error("Отсутствуют подтверждающие реквизиты");
  } },
  "@/lib/scap-presets": {
    ASTRA_BASELINE_DATASTREAM: "/__hcp_builtin__/astra-baseline.xml",
    ASTRA_BASELINE_PROFILE: "xccdf_org.hcp_profile_astra_baseline",
  },
  "@/lib/state-store": {
    listAstraOvalPolicies: () => ovalPolicies,
    listOpenScapPolicies: () => scapPolicies,
  },
});

function request(alias = "node") {
  return new Request("http://localhost/api/ansible/hosts/audit-preparation?alias=" + encodeURIComponent(alias));
}
function reset() {
  ovalPolicies = [];
  scapPolicies = [];
  member = ["all", "linux_hosts", "astra-1.7"];
  calls = [];
}

test("invalid or unregistered alias fails before policy resolution", async () => {
  reset();
  for (const value of ["all", "../passwd", "node:group"]) {
    const response = await route.GET(request(value));
    assert.equal(response.status, 400);
  }
  assert.deepEqual(calls, []);
  const absent = await route.GET(request("other"));
  assert.equal(absent.status, 404);
  assert.deepEqual(calls, ["inventory:other"]);
});

test("source settings are reported as assignments, never authenticated CVE verification", async () => {
  reset();
  ovalPolicies = [oval("linux_hosts"), oval("astra-1.7")];
  scapPolicies = [scap("linux_hosts"), scap("astra-1.7")];
  const response = await route.GET(request());
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(body.assessment, "saved-settings-only");
  assert.equal(body.astraOval.state, "configured");
  assert.equal(body.astraOval.group, "astra-1.7");
  assert.equal(body.astraOval.declaredRelease, "1.7.*");
  assert.equal(body.astraOval.sourceReviewRecorded, false);
  assert.equal(body.openScap.profileKind, "astra-hcp-18");
  assert.equal(body.openScap.group, "astra-1.7");
  assert.match(body.warning, /не проверка ОС/);
  assert.doesNotMatch(JSON.stringify(body), /secret-path|aaaaaaaaaaaaaaaaaaaaaaaa/);
  assert.deepEqual(calls, ["inventory:node", "oval-selection", "scap-selection"]);
});

test("absence of optional policies does not falsely claim applicable scanners", async () => {
  reset();
  const response = await route.GET(request());
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.astraOval.state, "missing");
  assert.equal(body.openScap.state, "missing");
  assert.match(body.openScap.message, /не назначен/);
});

test("conflicting concrete groups fail closed without choosing a silent fallback", async () => {
  reset();
  member = ["all", "linux_hosts", "astra-1.7", "high-security"];
  ovalPolicies = [oval("linux_hosts"), oval("astra-1.7"), oval("high-security")];
  scapPolicies = [scap("linux_hosts"), scap("astra-1.7"), scap("high-security")];
  const body = await (await route.GET(request())).json();
  assert.equal(body.astraOval.state, "conflict");
  assert.equal(body.openScap.state, "conflict");
  assert.equal(calls.includes("oval-selection"), false);
  assert.equal(calls.includes("scap-selection"), false);
});

test("incomplete provenance is not labelled configured", async () => {
  reset();
  ovalPolicies = [oval("astra-1.7")];
  ovalPolicies[0].config.sourceReference = "";
  scapPolicies = [scap("astra-1.7")];
  const body = await (await route.GET(request())).json();
  assert.equal(body.astraOval.state, "incomplete");
  assert.equal(body.openScap.state, "configured");
});

test("OpenSCAP environment fallback requires both fields and carries no group authority", async () => {
  reset();
  const oldData = process.env.HCP_OPENSCAP_DATASTREAM;
  const oldProfile = process.env.HCP_OPENSCAP_PROFILE;
  try {
    process.env.HCP_OPENSCAP_DATASTREAM = "/config/scap.xml";
    delete process.env.HCP_OPENSCAP_PROFILE;
    let body = await (await route.GET(request())).json();
    assert.equal(body.openScap.state, "missing");
    process.env.HCP_OPENSCAP_PROFILE = "xccdf_profile";
    body = await (await route.GET(request())).json();
    assert.equal(body.openScap.state, "configured");
    assert.equal(body.openScap.profileKind, "environment");
    assert.equal(body.openScap.group, null);
  } finally {
    if (oldData === undefined) delete process.env.HCP_OPENSCAP_DATASTREAM;
    else process.env.HCP_OPENSCAP_DATASTREAM = oldData;
    if (oldProfile === undefined) delete process.env.HCP_OPENSCAP_PROFILE;
    else process.env.HCP_OPENSCAP_PROFILE = oldProfile;
  }
});

test("hosts outside the Linux audit group are not offered a configured status", async () => {
  reset();
  member = ["all", "network"];
  ovalPolicies = [oval("network")];
  scapPolicies = [scap("network")];
  const response = await route.GET(request());
  assert.equal(response.status, 404);
  assert.deepEqual(calls, ["inventory:node"]);
});
