import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import test, { after } from "node:test";
import ts from "typescript";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ansible-reports"]);
const reports = mkdtempSync(path.join(tmpdir(), "hcp-description-route-"));
process.env.HCP_REPORTS_DIR = reports;
const reportLibrary = await import(compiled.url("ansible-reports"));
const require = createRequire(import.meta.url);
const source = ts.transpileModule(readFileSync(new URL("../app/api/ansible/reports/[reportId]/description/route.ts", import.meta.url), "utf8"), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText;
const module = { exports: {} };
let reads = 0;
const inputs = [];
const stubs = {
  "next/server": { NextResponse: { json: (body, init) => Response.json(body, init) } },
  "@/lib/ansible-reports": { ...reportLibrary, readAnsibleReport: (...args) => { reads += 1; return reportLibrary.readAnsibleReport(...args); } },
  "@/lib/description-translation": { translateDescription: async (text) => { inputs.push(text); return { text: "Перевод: " + text, language: "ru", machineTranslated: true, engine: "test" }; } },
};
new Function("require", "module", "exports", source)((name) => stubs[name] ?? require(name), module, module.exports);
const route = module.exports;
after(() => { delete process.env.HCP_REPORTS_DIR; rmSync(compiled.directory, { recursive: true, force: true }); rmSync(reports, { recursive: true, force: true }); });
const id = "host-astra-oval-run-description";
const pathname = path.join(reports, id + ".json");
function fixture(description) {
  return JSON.stringify({ inventoryHost: "host", profileId: "astra-oval", mode: "astra-oval", findings: [{ id: "oval:test:def:1", profileId: "astra-oval", title: "Astra test", category: "CVE", risk: "info", status: "failed", source: "openscap", description, recommendation: "Update" }] });
}
function request(reportId = id, findingId = "oval:test:def:1") {
  return route.GET(new Request("http://localhost/api/ansible/reports/test/description?findingId=" + encodeURIComponent(findingId)), { params: Promise.resolve({ reportId }) });
}

test("translation reads only the selected finding, caches prose and preserves source bytes", async () => {
  const original = fixture("Public CVE description, version 130.0.6723.92.");
  writeFileSync(pathname, original);
  const response = await request();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal((await response.json()).translation.language, "ru");
  assert.equal(inputs.at(-1), "Public CVE description, version 130.0.6723.92.");
  const count = reads;
  await request();
  assert.equal(reads, count);
  assert.equal(readFileSync(pathname, "utf8"), original);
  writeFileSync(pathname, fixture("Replacement public description with a different version 140.0.7339.127."));
  await request();
  assert.equal(reads, count + 1);
  assert.ok(inputs.at(-1).includes("140.0.7339.127"));
});

test("unknown records and invalid IDs cannot submit arbitrary prose for translation", async () => {
  const count = inputs.length;
  assert.equal((await request("../../outside")).status, 400);
  assert.equal((await request(id, "missing-finding")).status, 404);
  assert.equal((await request("missing-report")).status, 404);
  assert.equal(inputs.length, count);
});
