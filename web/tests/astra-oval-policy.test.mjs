import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["astra-oval-config", "astra-oval-policy", "state-store", "inventory"]);
const { validateAstraOvalConfig } = await import(compiled.url("astra-oval-config"));
const { selectAstraOvalPolicy } = await import(compiled.url("astra-oval-policy"));
const store = await import(compiled.url("state-store"));
const state = mkdtempSync(path.join(tmpdir(), "hcp-oval-settings-"));
process.env.HCP_STATE_DIR = state;
after(() => { delete process.env.HCP_STATE_DIR; rmSync(compiled.directory, { recursive: true, force: true }); rmSync(state, { recursive: true, force: true }); });
const local = () => ({ mode: "local", path: "/usr/share/oval/db.xml", url: "", sha256: "", releasePattern: "*", architectures: [], maxAgeDays: 30 });

test("OVAL settings persist isolated sources for different Astra groups and survive edits", () => {
  store.upsertAstraOvalPolicy("astra-old", { ...local(), releasePattern: "1.6.*" });
  store.upsertAstraOvalPolicy("astra-new", { ...local(), releasePattern: "1.8.*", architectures: ["x86_64"] });
  assert.equal(store.listAstraOvalPolicies().length, 2);
  store.upsertAstraOvalPolicy("astra-old", { ...local(), maxAgeDays: 7 });
  assert.equal(store.listAstraOvalPolicies().find((p) => p.groupName === "astra-old").config.maxAgeDays, 7);
  assert.equal(store.listAstraOvalPolicies().find((p) => p.groupName === "astra-new").config.releasePattern, "1.8.*");
  assert.equal(store.deleteAstraOvalPolicy("astra-old"), true);
  assert.equal(store.listAstraOvalPolicies().length, 1);
});

test("OVAL group selection rejects ambiguity and does not silently select an unrelated database", () => {
  const policies = ["linux_hosts", "astra-a", "astra-b"].map((groupName) => ({ groupName, config: local() }));
  assert.equal(selectAstraOvalPolicy(["linux_hosts", "astra-a"], policies).groupName, "astra-a");
  assert.equal(selectAstraOvalPolicy(["linux_hosts"], policies).groupName, "linux_hosts");
  assert.throws(() => selectAstraOvalPolicy(["astra-a", "astra-b"], policies), /несколько/);
  assert.throws(() => selectAstraOvalPolicy(["astra-c"], policies), /Назначьте/);
});

test("online OVAL requires HTTPS and an independently pinned digest; local does not inherit an URL", () => {
  const online = { ...local(), mode: "online", url: "https://mirror.example/astra.xml", sha256: "A".repeat(64) };
  assert.equal(validateAstraOvalConfig(online).sha256, "a".repeat(64));
  assert.equal(validateAstraOvalConfig(online).path, "");
  assert.equal(validateAstraOvalConfig({ ...local(), url: online.url }).url, "");
  for (const url of ["http://mirror.example/db.xml", "https://user:secret@mirror.example/db.xml", "file:///etc/passwd", "https://mirror.example/db.xml?token=secret", "https://mirror.example/db.xml#fragment"]) {
    assert.throws(() => validateAstraOvalConfig({ ...online, url }));
  }
  assert.throws(() => validateAstraOvalConfig({ ...online, sha256: "" }));
});

test("OVAL input guards reject path traversal, malformed scopes and unbounded parameters", () => {
  for (const value of [{ path: "../db.xml" }, { path: "/tmp/../db.xml" }, { path: "/tmp/db\n.xml" }, { releasePattern: ".*" }, { releasePattern: "1.*.8" }, { architectures: ["$(uname)"] }, { maxAgeDays: 0 }, { maxAgeDays: 1.5 }, { sha256: "abc" }]) {
    assert.throws(() => validateAstraOvalConfig({ ...local(), ...value }));
  }
  for (const releasePattern of ["1.6.7.15", "1.7.*", "1.8.*", "future-release", "*"]) {
    assert.equal(validateAstraOvalConfig({ ...local(), releasePattern }).releasePattern, releasePattern);
  }
});
