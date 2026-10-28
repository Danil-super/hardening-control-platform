import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["auth"]);
const state = mkdtempSync(path.join(tmpdir(), "hcp-auth-sessions-"));
const environment = Object.fromEntries(["HCP_STATE_DIR", "HCP_ADMIN_PASSWORD", "HCP_AUTH_SECRET"].map((key) => [key, process.env[key]]));
process.env.HCP_STATE_DIR = state;
process.env.HCP_ADMIN_PASSWORD = "session-test-password";
process.env.HCP_AUTH_SECRET = "session-test-secret";
const auth = await import(compiled.url("auth"));
after(() => {
  for (const [key, value] of Object.entries(environment)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  rmSync(compiled.directory, { recursive: true, force: true });
  rmSync(state, { recursive: true, force: true });
});

test("sessions are independent random bearer tokens and only hashes are stored", () => {
  const first = auth.createSessionToken();
  const second = auth.createSessionToken();
  assert.match(first, /^[a-f0-9]{64}$/);
  assert.notEqual(first, second);
  assert.equal(auth.isValidSessionToken(first), true);
  assert.equal(auth.isValidSessionToken(second), true);
  const database = new DatabaseSync(path.join(state, "hcp.sqlite"));
  const rows = database.prepare("SELECT * FROM admin_sessions").all();
  database.close();
  assert.ok(rows.some((row) => row.token_hash === createHash("sha256").update(first).digest("hex")));
  for (const secret of [first, second, process.env.HCP_ADMIN_PASSWORD, process.env.HCP_AUTH_SECRET]) {
    assert.ok(!JSON.stringify(rows).includes(secret));
  }
  auth.revokeSessionToken(first);
  assert.equal(auth.isValidSessionToken(first), false);
  assert.equal(auth.isValidSessionToken(second), true);
  auth.revokeSessionToken(first); // Logout is idempotent.
});

test("server expiry is enforced at the eight-hour boundary", () => {
  const originalNow = Date.now;
  let now = originalNow();
  Date.now = () => now;
  try {
    const token = auth.createSessionToken();
    now += auth.sessionMaxAgeSeconds * 1000 - 1;
    assert.equal(auth.isValidSessionToken(token), true);
    now += 1;
    assert.equal(auth.isValidSessionToken(token), false);
    now += 365 * 86400_000;
    assert.equal(auth.isValidSessionToken(token), false);
  } finally { Date.now = originalNow; }
});

test("password and secret rotation invalidate existing sessions and legacy tokens", () => {
  const password = process.env.HCP_ADMIN_PASSWORD;
  const secret = process.env.HCP_AUTH_SECRET;
  try {
    const token = auth.createSessionToken();
    const legacy = createHash("sha256").update(`${password}:${secret}`).digest("hex");
    assert.equal(auth.isValidSessionToken(legacy), false);
    process.env.HCP_ADMIN_PASSWORD = "rotated-test-password";
    assert.equal(auth.isValidSessionToken(token), false);
    process.env.HCP_ADMIN_PASSWORD = password;
    process.env.HCP_AUTH_SECRET = "rotated-test-secret";
    assert.equal(auth.isValidSessionToken(token), false);
    delete process.env.HCP_ADMIN_PASSWORD;
    assert.equal(auth.createSessionToken(), "");
    assert.equal(auth.isValidSessionToken(token), false);
  } finally {
    process.env.HCP_ADMIN_PASSWORD = password;
    process.env.HCP_AUTH_SECRET = secret;
  }
  for (const value of [undefined, null, "", "x".repeat(64), "0".repeat(63), "0".repeat(65), {}, []]) {
    assert.equal(auth.isValidSessionToken(value), false);
  }
});

test("a separate process sees valid sessions and revocation is immediately shared", () => {
  const token = auth.createSessionToken();
  const output = execFileSync(process.execPath, ["--input-type=module", "-e", `
    const auth = await import(${JSON.stringify(compiled.url("auth"))});
    let token = ''; for await (const chunk of process.stdin) token += chunk;
    const valid = auth.isValidSessionToken(token);
    auth.revokeSessionToken(token);
    process.stdout.write(JSON.stringify({ valid, revoked: !auth.isValidSessionToken(token) }));
  `], { input: token, encoding: "utf8", env: process.env, timeout: 10_000 });
  assert.deepEqual(JSON.parse(output), { valid: true, revoked: true });
  assert.equal(auth.isValidSessionToken(token), false);
});
