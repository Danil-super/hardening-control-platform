import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { promisify } from "node:util";
import test, { after, beforeEach, afterEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["state-store"]);
const store = await import(compiled.url("state-store"));
const execute = promisify(execFile);
const oldDirectory = process.env.HCP_STATE_DIR;
const oldKey = process.env.HCP_AUDIT_HMAC_KEY;
let directory;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-state-integrity-"));
  process.env.HCP_STATE_DIR = directory;
  process.env.HCP_AUDIT_HMAC_KEY = "test-key-only-do-not-deploy";
  store.getVulnerabilityDatabaseSettings();
});
afterEach(() => rmSync(directory, { recursive: true, force: true }));
after(() => {
  if (oldDirectory === undefined) delete process.env.HCP_STATE_DIR; else process.env.HCP_STATE_DIR = oldDirectory;
  if (oldKey === undefined) delete process.env.HCP_AUDIT_HMAC_KEY; else process.env.HCP_AUDIT_HMAC_KEY = oldKey;
  rmSync(compiled.directory, { recursive: true, force: true });
});
const transaction = (id, hostAlias = "host-one") => store.createRemediationTransaction({
  id, hostAlias, action: "closePort", profileId: "basic_linux", reason: "test", parameters: { port: "8080", protocol: "tcp" },
});

test("audit HMAC detects edits deep inside nested payloads", () => {
  store.appendAuditEvent("change", "one", { parameters: { firewall: { port: "8080" } }, steps: [{ allowed: false }] });
  assert.equal(store.verifyAuditChain().valid, true);
  const database = new DatabaseSync(path.join(directory, "hcp.sqlite"));
  database.prepare("UPDATE audit_events SET payload_json = ?").run(JSON.stringify({ parameters: { firewall: { port: "22" } }, steps: [{ allowed: false }] }));
  database.close();
  assert.equal(store.verifyAuditChain().valid, false);
});

test("parallel processes append one unbranched audit chain", async () => {
  await Promise.all(Array.from({ length: 4 }, (_, worker) => execute(process.execPath, ["--input-type=module", "-e", `
    const store = await import(${JSON.stringify(compiled.url("state-store"))});
    for (let i = 0; i < 20; i++) store.appendAuditEvent("parallel", "${worker}-" + i, { worker: ${worker}, i });
  `], { env: { ...process.env }, timeout: 20000 })));
  assert.deepEqual(store.verifyAuditChain(), { valid: true, entries: 80, brokenAt: null, legacyEntries: 0, payloadProtected: true });
});

test("failed audit insertion rolls back the associated state update", () => {
  const database = new DatabaseSync(path.join(directory, "hcp.sqlite"));
  database.exec("CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'test audit failure'); END;");
  assert.throws(() => store.setVulnerabilityDatabaseMode("offline"), /test audit failure/);
  assert.equal(database.prepare("SELECT count(*) AS count FROM runtime_settings").get().count, 0);
  assert.throws(() => transaction("rejected"), /test audit failure/);
  assert.equal(store.getRemediationTransaction("rejected"), null);
  database.close();
});

test("legacy signatures are preserved and marked as lacking full payload protection", () => {
  const database = new DatabaseSync(path.join(directory, "hcp.sqlite"));
  const value = { createdAt: "2025-01-01T00:00:00.000Z", eventType: "legacy", entityId: "old", payload: { parameters: { port: "22" } }, previousHash: null };
  const hash = createHmac("sha256", process.env.HCP_AUDIT_HMAC_KEY).update(JSON.stringify(value, Object.keys(value).sort())).digest("hex");
  database.prepare("INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run("old", value.createdAt, value.eventType, value.entityId, JSON.stringify(value.payload), null, hash, 1);
  database.close();
  store.appendAuditEvent("new", "new", { parameters: { port: "8080" } });
  assert.deepEqual(store.verifyAuditChain(), { valid: true, entries: 2, brokenAt: null, legacyEntries: 1, payloadProtected: false });
});

test("rollback atomically claims its host and rejects duplicate requests", () => {
  transaction("first");
  store.updateRemediationTransaction("first", { status: "applied", backupRef: "/backup/first" });
  assert.equal(store.claimRemediationRollback("first").status, "rolling_back");
  assert.equal(store.hasActiveRemediationForHost("host-one"), true);
  assert.throws(() => store.claimRemediationRollback("first"), { code: "rollback_not_available" });
  assert.throws(() => transaction("competing"), /UNIQUE constraint failed/);
  store.updateRemediationTransaction("first", { status: "rollback_failed" });
  assert.equal(store.claimRemediationRollback("first").status, "rolling_back");
});

test("rollback of old backup is blocked until later changes have been rolled back", () => {
  transaction("old");
  store.updateRemediationTransaction("old", { status: "applied", backupRef: "/backup/old" });
  transaction("new");
  store.updateRemediationTransaction("new", { status: "failed", backupRef: "/backup/new" });
  assert.throws(() => store.claimRemediationRollback("old"), { code: "newer_remediation_exists" });
  store.claimRemediationRollback("new");
  store.updateRemediationTransaction("new", { status: "rolled_back" });
  assert.equal(store.claimRemediationRollback("old").status, "rolling_back");
});

test("two workers cannot start the same rollback concurrently", async () => {
  transaction("shared");
  store.updateRemediationTransaction("shared", { status: "applied", backupRef: "/backup/shared" });
  const result = await Promise.all(Array.from({ length: 2 }, () => execute(process.execPath, ["--input-type=module", "-e", `
    const store = await import(${JSON.stringify(compiled.url("state-store"))});
    try { store.claimRemediationRollback("shared"); process.stdout.write("claimed"); }
    catch (error) { process.stdout.write(error.code); }
  `], { env: { ...process.env }, timeout: 20000 })));
  assert.deepEqual(result.map((item) => item.stdout).sort(), ["claimed", "rollback_not_available"]);
  assert.equal(store.verifyAuditChain().valid, true);
});
