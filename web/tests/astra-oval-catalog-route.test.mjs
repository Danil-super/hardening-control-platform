import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

let policies, tasks, reads, failure, cached, prepareFailure, executed;
const preview = { url: "https://dl.astralinux.ru/artifactory/al-oval/1.7_x86-64/oval-definitions-alse-1.7.xml",
  sha256: "a".repeat(64), release: "1.7", sourceName: "Каталог Astra Linux OVAL 1.7", sourceReference: "https://dl.astralinux.ru/metadata" };
const stubs = {
  "next/server": { after: task => tasks.push(task), NextResponse: { json: (body, options) => Response.json(body, options) } },
  "@/lib/openscap-policy": { listInventoryGroups: () => ["astra_hosts"] },
  "@/lib/state-store": {
    listAstraOvalPolicies: () => policies,
    upsertAstraOvalPolicy(groupName, config) {
      const policy = { groupName, config: { ...config, sourceReviewedAt: "2026-11-17T00:00:00.000Z" } };
      policies = [policy];
      return policy;
    },
  },
  "@/lib/astra-oval-official-catalog": { async readOfficialAstraOvalCatalog(release) {
    reads.push(release);
    if (failure) throw new Error("private proxy password must never appear");
    return preview;
  } },
  "@/lib/astra-oval-preparation": { startOvalPreparation(config) {
    assert.equal(config, policies[0].config, "prepare the exact saved policy, including its provenance date");
    if (prepareFailure) throw new Error("Уже подготавливается другая OVAL-база.");
    return { status: { state: cached ? "ready" : "preparing" }, run: cached ? null : async () => { executed = true; } };
  } },
};
const source = ts.transpileModule(readFileSync(new URL("../app/api/settings/astra-oval/catalog/route.ts", import.meta.url), "utf8"),
  { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const module = { exports: {} };
new Function("require", "module", "exports", source)(name => { assert.ok(stubs[name], name); return stubs[name]; }, module, module.exports);
const route = module.exports;
const post = body => route.POST(new Request("http://localhost/api/settings/astra-oval/catalog", { method: "POST", body: JSON.stringify(body) }));
test.beforeEach(() => { policies = [{ groupName: "astra_hosts", config: { sha256: "b".repeat(64), maxAgeDays: 3, evidenceProjection: "detailed" } }]; tasks = []; reads = []; failure = false; cached = false; prepareFailure = false; executed = false; });

test("official update validates group and release before any network or state change", async () => {
  for (const body of [{}, { groupName: "missing", release: "1.7" }, { groupName: "astra_hosts", release: "https://untrusted.example" }]) {
    assert.equal((await post(body)).status, 400);
  }
  assert.deepEqual(reads, []);
  assert.deepEqual(tasks, []);
  assert.equal(policies[0].config.sha256, "b".repeat(64));
});

test("unavailable vendor leaves the saved source unchanged and never exposes upstream errors", async () => {
  failure = true;
  const response = await post({ groupName: "astra_hosts", release: "1.7" });
  assert.equal(response.status, 502);
  assert.equal(policies[0].config.sha256, "b".repeat(64));
  assert.equal(tasks.length, 0);
  const body = await response.text();
  assert.match(body, /не изменён/);
  assert.doesNotMatch(body, /private|password/);
});

test("one official update saves fixed catalog data and schedules existing verified preparation", async () => {
  const response = await post({ groupName: "astra_hosts", release: "1.7", config: { url: "https://untrusted.example", sha256: "evil" } });
  assert.equal(response.status, 202);
  const body = await response.json();
  assert.equal(body.ok, true);
  assert.equal(body.preparation.state, "preparing");
  assert.equal(policies[0].config.url, preview.url);
  assert.equal(policies[0].config.sha256, preview.sha256);
  assert.equal(policies[0].config.releasePattern, "1.7.*");
  assert.deepEqual(policies[0].config.architectures, ["x86_64"]);
  assert.equal(policies[0].config.maxAgeDays, 3, "an update must not relax the operator's freshness limit");
  assert.equal(policies[0].config.evidenceProjection, "detailed");
  assert.equal(executed, false);
  assert.equal(tasks.length, 1);
  await tasks.shift()();
  assert.equal(executed, true);
});

test("an unchanged ready source is reused without another download", async () => {
  cached = true;
  const response = await post({ groupName: "astra_hosts", release: "1.7" });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).preparation.state, "ready");
  assert.equal(tasks.length, 0);
});

test("a busy preparation reports the already saved source accurately", async () => {
  prepareFailure = true;
  const response = await post({ groupName: "astra_hosts", release: "1.7" });
  assert.equal(response.status, 409);
  const body = await response.json();
  assert.equal(body.ok, false);
  assert.equal(body.sourceSaved, true);
  assert.match(body.message, /Источник сохранён/);
  assert.equal(tasks.length, 0);
});
