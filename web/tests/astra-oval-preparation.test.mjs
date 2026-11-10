import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["astra-oval-preparation"]);
const { ovalPreparationStatus, preparedOvalExtraVars, startOvalPreparation } = await import(compiled.url("astra-oval-preparation"));
const { validateAstraOvalConfig } = await import(compiled.url("astra-oval-config"));
const root = mkdtempSync(path.join(tmpdir(), "hcp-oval-preparation-"));
process.env.HCP_STATE_DIR = root;
after(() => { delete process.env.HCP_STATE_DIR; rmSync(root, { recursive: true, force: true }); rmSync(compiled.directory, { recursive: true, force: true }); });
const xml = Buffer.from("<oval_definitions>synthetic validated fixture</oval_definitions>");
const hash = createHash("sha256").update(xml).digest("hex");
const config = (extra = {}) => validateAstraOvalConfig({ mode: "online", url: "https://mirror.example/astra.xml", sha256: hash, releasePattern: "1.7.*", architectures: ["x86_64"], maxAgeDays: 30, sourceName: "Fixture source", sourceReference: "TEST-OVAL", ...extra });
const directory = c => path.join(root, "oval-prepared", createHash("sha256").update(JSON.stringify(c)).digest("hex"));
const result = (c, extra = {}) => ({ ok: true, database: { sha256: c.sha256, bytes: xml.length, generatedAt: new Date().toISOString(), freshness: "current" }, sourceValidation: { sha256: c.sha256, schemaExitCode: 0, schematronExitCode: 0, location: "control_node" }, warnings: [], ...extra });
const execute = async (c, output) => { writeFileSync(output, xml, { flag: "wx", mode: 0o600 }); return result(c); };

test("network source requires explicit preparation and reuses exactly the verified bytes", async () => {
  const c = config();
  assert.equal(ovalPreparationStatus(c).state, "missing");
  assert.throws(() => preparedOvalExtraVars(c), /подготовьте/i);
  const pending = startOvalPreparation(c, execute);
  assert.equal(pending.status.state, "preparing");
  assert.equal(startOvalPreparation(c, execute).run, null);
  await pending.run();
  assert.equal(ovalPreparationStatus(c).state, "ready");
  const vars = preparedOvalExtraVars(c);
  assert.deepEqual(readFileSync(vars.hcp_oval_prepared_input), xml);
  assert.equal(JSON.parse(vars.hcp_oval_source_validation).schemaExitCode, 0);
  assert.equal(startOvalPreparation(c, () => { throw new Error("No second download"); }).run, null);
  assert.equal(ovalPreparationStatus(config({ url: "https://mirror.example/new.xml" })).state, "missing");
});

test("changed source settings, expired dates, partial XML validation and warnings cannot authorize a run", async () => {
  for (const [name, mutate] of [
    ["checksum", r => ({ ...r, database: { ...r.database, sha256: "0".repeat(64) } })],
    ["stale", r => ({ ...r, database: { ...r.database, generatedAt: "2000-01-01T00:00:00Z" } })],
    ["future", r => ({ ...r, database: { ...r.database, generatedAt: "2099-01-01T00:00:00Z" } })],
    ["schematron", r => ({ ...r, sourceValidation: { ...r.sourceValidation, schematronExitCode: null } })],
    ["xsd", r => ({ ...r, sourceValidation: { ...r.sourceValidation, schemaExitCode: 1 } })],
    ["warnings", r => ({ ...r, warnings: ["origin unresolved"] })],
  ]) {
    const c = config({ sourceReference: name });
    const started = startOvalPreparation(c, async (_, out) => { writeFileSync(out, xml); return mutate(result(c)); });
    await started.run();
    assert.equal(ovalPreparationStatus(c).state, "failed", name);
    assert.throws(() => preparedOvalExtraVars(c));
  }
});

test("tampered copy is rejected at launch and can be explicitly prepared again", async () => {
  const c = config({ sourceReference: "tampered" });
  await startOvalPreparation(c, execute).run();
  const vars = preparedOvalExtraVars(c);
  writeFileSync(vars.hcp_oval_prepared_input, Buffer.alloc(xml.length, 65));
  assert.throws(() => preparedOvalExtraVars(c), /SHA-256/);
  await startOvalPreparation(c, execute).run();
  assert.equal(ovalPreparationStatus(c).state, "ready");
  rmSync(vars.hcp_oval_prepared_input);
  symlinkSync("/etc/passwd", vars.hcp_oval_prepared_input);
  assert.equal(ovalPreparationStatus(c).state, "failed");
  assert.throws(() => preparedOvalExtraVars(c));
});

test("interrupted preparation never becomes ready after a process restart", async () => {
  const c = config({ sourceReference: "restart" });
  await startOvalPreparation(c, execute).run();
  const file = path.join(directory(c), "status.json");
  const state = JSON.parse(readFileSync(file, "utf8"));
  writeFileSync(file, JSON.stringify({ ...state, state: "preparing", owner: "old-process" }));
  assert.equal(ovalPreparationStatus(c).state, "failed");
  assert.throws(() => preparedOvalExtraVars(c));
  await startOvalPreparation(c, execute).run();
  assert.equal(ovalPreparationStatus(c).state, "ready");
});

test("transport errors stay separate from audit results and credentials are redacted", async () => {
  const c = config({ sourceReference: "transport" });
  await startOvalPreparation(c, async () => { throw new Error("https://user:secret@proxy.example timeout"); }).run();
  const status = ovalPreparationStatus(c);
  assert.equal(status.state, "failed");
  assert.doesNotMatch(status.message, /user:secret/);
  assert.match(status.message, /timeout/);
});

test("local source keeps target-side validation and never fetches from the controller", () => {
  const c = config({ mode: "local", path: "/usr/share/oval/db.xml" });
  assert.equal(ovalPreparationStatus(c).state, "local");
  assert.deepEqual(preparedOvalExtraVars(c), {});
  assert.equal(startOvalPreparation(c, () => { throw new Error("network not allowed"); }).run, null);
});
