import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { beforeEach, afterEach, after, test } from "node:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ssh-access", "host-credentials", "ssh-bootstrap"]);
const credentials = await import(compiled.url("host-credentials"));
const { credentialTransportAllowed, readCredentialRequest, runSshBootstrap } = await import(compiled.url("ssh-bootstrap"));
let temporary;
const previousState = process.env.HCP_STATE_DIR;
const previousProxy = process.env.HCP_TRUSTED_TLS_PROXY;
const identity = (alias = "astra-a") => ({ alias, address: alias === "astra-a" ? "192.0.2.10" : "192.0.2.11", user: "lab", port: 22 });
beforeEach(() => { temporary = mkdtempSync(path.join(os.tmpdir(), "hcp-credentials-")); process.env.HCP_STATE_DIR = temporary; delete process.env.HCP_TRUSTED_TLS_PROXY; });
afterEach(() => {
  rmSync(temporary, { recursive: true, force: true });
  if (previousState === undefined) delete process.env.HCP_STATE_DIR; else process.env.HCP_STATE_DIR = previousState;
  if (previousProxy === undefined) delete process.env.HCP_TRUSTED_TLS_PROXY; else process.env.HCP_TRUSTED_TLS_PROXY = previousProxy;
});
after(() => rmSync(compiled.directory, { recursive: true, force: true }));
function generate(prepared, host) {
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", prepared.keyPath]);
  const publicKey = readFileSync(prepared.keyPath + ".pub", "utf8").trim();
  const fingerprint = execFileSync("ssh-keygen", ["-lf", prepared.keyPath, "-E", "sha256"], { encoding: "utf8" }).split(/\s+/)[1];
  return credentials.markHostCredentialVerified(prepared.credential.id, host, publicKey, fingerprint);
}

test("each host has its own actual key pair and only public metadata is returned", () => {
  const a = credentials.beginHostCredential(identity());
  const b = credentials.beginHostCredential(identity("astra-b"));
  try {
    const ca = generate(a, identity()), cb = generate(b, identity("astra-b"));
    assert.notEqual(a.credential.id, b.credential.id);
    assert.notEqual(ca.publicKey, cb.publicKey);
    assert.notEqual(ca.fingerprint, cb.fingerprint);
    assert.equal(credentials.connectionPrivateKey(identity(), ca.id), a.keyPath);
    assert.equal(statSync(a.keyPath).mode & 0o777, 0o600);
    assert.equal(statSync(path.dirname(a.keyPath)).mode & 0o777, 0o700);
    const summary = JSON.stringify(credentials.publicCredentialSummary(ca.id));
    assert.doesNotMatch(summary, /PRIVATE KEY|password|keyPath/);
    assert.doesNotMatch(readFileSync(path.join(path.dirname(a.keyPath), "metadata.json"), "utf8"), /PRIVATE KEY|password|keyPath/);
  } finally { a.release(); b.release(); }
});

test("unverified credentials and cross-host, user, port or path substitution are rejected", () => {
  const host = identity(), prepared = credentials.beginHostCredential(host);
  try {
    assert.throws(() => credentials.connectionPrivateKey(host, prepared.credential.id), /ещё не подтверждён/);
    generate(prepared, host);
    for (const changed of [{ ...host, address: "192.0.2.12" }, { ...host, alias: "other" }, { ...host, user: "root" }, { ...host, port: 2222 }]) {
      assert.throws(() => credentials.connectionPrivateKey(changed, prepared.credential.id), /другому хосту/);
    }
    assert.throws(() => credentials.connectionPrivateKey(host, "../../secrets/hcp-control"), /идентификатор/);
    assert.throws(() => credentials.connectionPrivateKey(host, "f".repeat(64)), /не найден/);
  } finally { prepared.release(); }
});

test("concurrent setup is locked and a retry preserves the key and its binding", () => {
  const host = identity(), first = credentials.beginHostCredential(host);
  generate(first, host);
  const before = readFileSync(first.keyPath, "utf8");
  assert.throws(() => credentials.beginHostCredential(host), /уже выполняется/);
  first.release();
  const second = credentials.beginHostCredential(host);
  try {
    assert.equal(second.credential.id, first.credential.id);
    assert.equal(readFileSync(second.keyPath, "utf8"), before);
  } finally { second.release(); }
});

test("password transport permits HTTPS or local loopback and requires explicit proxy trust", () => {
  const req = (url, origin, extra = {}) => new Request(url, { headers: { origin, ...extra } });
  assert.equal(credentialTransportAllowed(req("http://127.0.0.1:3000/api", "http://127.0.0.1:3000")), true);
  assert.equal(credentialTransportAllowed(req("http://localhost:3000/api", "http://192.168.1.5:3000")), false);
  assert.equal(credentialTransportAllowed(req("https://hcp.example/api", "https://hcp.example")), true);
  assert.equal(credentialTransportAllowed(req("http://localhost:3000/api", "https://hcp.example", { "x-forwarded-proto": "https" })), false);
  process.env.HCP_TRUSTED_TLS_PROXY = "true";
  assert.equal(credentialTransportAllowed(req("http://localhost:3000/api", "https://hcp.example", { "x-forwarded-proto": "https" })), true);
  assert.equal(credentialTransportAllowed(req("http://localhost:3000/api", "http://hcp.example", { "x-forwarded-proto": "https" })), false);
});

test("password endpoint rejects oversized and non-object payloads without echoing contents", async () => {
  for (const body of ['"secret-fixture"', "null", "[]", JSON.stringify({ password: "x".repeat(17000) })]) {
    await assert.rejects(readCredentialRequest(new Request("http://localhost/api", { method: "POST", body })), /Проверьте данные/);
  }
});


test("SSH helper receives secrets only through stdin and unrecognized errors never echo them", async () => {
  const cwd = process.cwd();
  mkdirSync(path.join(temporary, "web"));
  mkdirSync(path.join(temporary, "ansible/scripts"), { recursive: true });
  const helper = path.join(temporary, "ansible/scripts/hcp-ssh-bootstrap.py");
  writeFileSync(helper, `import json, os, sys
value = json.load(sys.stdin)
assert len(sys.argv) == 1
assert value["password"] not in os.environ.values()
print(value["password"], file=sys.stderr)
print(json.dumps({"ok": True, "fingerprint": "fixture", "publicKey": "public fixture"}))
`);
  try {
    process.chdir(path.join(temporary, "web"));
    const options = { credentialId: "a".repeat(64), keyPath: "/fixture/key", password: "bootstrap-secret-fixture", sudoPassword: "sudo-secret-fixture", configureSudo: false };
    const result = await runSshBootstrap(identity(), options);
    assert.equal(result.ok, true);
    assert.doesNotMatch(JSON.stringify(result), /secret-fixture/);
    writeFileSync(helper, `import json, sys
value = json.load(sys.stdin)
print(json.dumps({"ok": False, "error": value["password"]}))
`);
    await assert.rejects(runSshBootstrap(identity(), options), (error) => {
      assert.doesNotMatch(error.message, /secret-fixture/);
      return error.code === "ssh_setup_failed";
    });
  } finally { process.chdir(cwd); }
});


test("missing verified keys and dangling symlinks cannot silently create a replacement", () => {
  const host = identity(), prepared = credentials.beginHostCredential(host);
  generate(prepared, host);
  prepared.release();
  rmSync(prepared.keyPath);
  assert.throws(() => credentials.beginHostCredential(host), /приватный ключ отсутствует/);
  symlinkSync(path.join(temporary, "missing-private-key"), prepared.keyPath);
  assert.throws(() => credentials.beginHostCredential(host), /недопустимый тип/);
});
