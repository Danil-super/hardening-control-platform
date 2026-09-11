import assert from "node:assert/strict";
import { after, test } from "node:test";
import { rmSync } from "node:fs";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["client-navigation", "client-api", "clipboard"]);
const { normalizeNextPath, signIn } = await import(compiled.url("client-navigation"));
const { readApiResponse } = await import(compiled.url("client-api"));
const { copyText } = await import(compiled.url("clipboard"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test("login waits for successful API response and then opens the intended page", async () => {
  let resolveRequest;
  let destination;
  const pending = signIn("fixture-only", "/hosts", {
    request: async (url, options) => {
      if (url === "/api/ansible/session") return Response.json({ ok: true });
      assert.equal(url, "/api/ansible/auth/login");
      assert.equal(options.credentials, "same-origin");
      return new Promise((resolve) => { resolveRequest = resolve; });
    },
    navigate: (path) => { destination = path; },
  });
  assert.equal(destination, undefined);
  resolveRequest(Response.json({ ok: true }));
  await pending;
  assert.equal(destination, "/hosts");
});

test("an accepted password without a usable session reports an error instead of looping to login", async () => {
  await assert.rejects(signIn("fixture-only", "/hosts", {
    request: async (url) => Response.json({ ok: url.endsWith("/login") }, { status: url.endsWith("/login") ? 200 : 401 }),
    navigate: () => assert.fail("missing session must not navigate"),
  }), /сеанс не сохранился/);
});

test("failed login, malformed proxy response and offline requests never navigate", async () => {
  for (const request of [
    async () => Response.json({ ok: false, message: "Неверный пароль" }, { status: 401 }),
    async () => Response.json({ ok: true }, { status: 503 }),
    async () => new Response("<html>Bad gateway</html>", { status: 502 }),
    async () => { throw new TypeError("Failed to fetch"); },
  ]) {
    let navigated = false;
    await assert.rejects(signIn("fixture-only", "/hosts", { request, navigate: () => { navigated = true; } }));
    assert.equal(navigated, false);
  }
});

test("login timeout is reported and does not navigate", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const pending = signIn("fixture-only", "/hosts", {
    request: async (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    }),
    navigate: () => assert.fail("timeout must not navigate"),
  });
  const rejected = assert.rejects(pending, /не ответил вовремя/);
  context.mock.timers.tick(15000);
  await rejected;
});

test("next destinations remain local pages and cannot return to the login loop", () => {
  for (const input of [undefined, "//example.org", "/\\example.org", "/%5cexample.org", "/%2fexample.org", "javascript:alert(1)", "/login", "/a/../login", "/%6cogin", "/api/ansible/hosts", "/\n/example.org", "/%zz"]) {
    assert.equal(normalizeNextPath(input), "/hosts", String(input));
  }
  assert.equal(normalizeNextPath("/reports/agentless?host=astra#latest"), "/reports/agentless?host=astra#latest");
});

test("API decoder reports expired sessions, proxy errors and retains preflight checks", async () => {
  await assert.rejects(readApiResponse(Response.json({ ok: false }, { status: 401 })), /Сеанс завершён/);
  await assert.rejects(readApiResponse(new Response("Bad gateway", { status: 502 })), /HTTP 502/);
  const payload = await readApiResponse(Response.json({ ok: true, checks: { ssh: { ok: false } } }, { status: 400 }));
  assert.equal(payload.ok, false);
  assert.equal(payload.checks.ssh.ok, false);
});

test("copy supports secure clipboard and HTTP fallback without claiming a failed copy succeeded", async () => {
  const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  let copied, fallbackResult = true, removals = 0, focuses = 0;
  const field = { value: "", style: {}, select() {}, remove() { removals++; } };
  Object.defineProperty(globalThis, "document", { configurable: true, value: {
    activeElement: { focus() { focuses++; } }, body: { appendChild() {} },
    createElement: () => field, execCommand: () => { copied = field.value; return fallbackResult; },
  } });
  try {
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async (value) => { copied = value; } } } });
    await copyText("public fixture key");
    assert.equal(copied, "public fixture key");
    assert.equal(removals, 0);
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: {} });
    await copyText("HTTP fallback");
    assert.equal(copied, "HTTP fallback");
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async () => { throw new Error("denied"); } } } });
    await copyText("denied permission fallback");
    assert.equal(copied, "denied permission fallback");
    fallbackResult = false;
    await assert.rejects(copyText("failure"));
    assert.equal(removals, 3);
    assert.equal(focuses, 3);
  } finally {
    if (originalNavigator) Object.defineProperty(globalThis, "navigator", originalNavigator); else delete globalThis.navigator;
    if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument); else delete globalThis.document;
  }
});
