import assert from "node:assert/strict";
import { after, test } from "node:test";
import { rmSync } from "node:fs";
import { compileServerModules } from "./_typescript-loader.mjs";
const compiled = compileServerModules(["client-api", "host-onboarding"]);
const { connectAndSaveHost } = await import(compiled.url("host-onboarding"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));
const connection = { alias: "astra-a", address: "192.0.2.10", user: "lab", port: "22", group: "linux_hosts", become: true, credentialId: null };
const secrets = () => ({ password: "ssh-fixture-only", sudoPassword: "sudo-fixture-only", configureSudo: true });

test("one action installs an individual key then saves only after successful key preflight, without saving passwords", async () => {
  const calls = [], progress = [];
  const input = secrets();
  let passwordSubmitted = false;
  const result = await connectAndSaveHost(connection, input, { editing: false,
    onPasswordSubmit: () => { passwordSubmitted = true; }, onStage: (stage) => progress.push(stage),
    request: async (url, options) => {
      const body = JSON.parse(options.body); calls.push(url);
      if (url.endsWith("/access")) {
        assert.equal(passwordSubmitted, false);
        assert.doesNotMatch(options.body, /fixture-only/);
        return Response.json({ ok: true, trusted: true });
      }
      if (url.endsWith("/bootstrap")) {
        assert.equal(passwordSubmitted, true);
        assert.equal(body.password, "ssh-fixture-only");
        return Response.json({ ok: true, credentialId: "a".repeat(64) });
      }
      assert.equal(body.credentialId, "a".repeat(64));
      assert.doesNotMatch(options.body, /password|fixture-only/i);
      assert.equal(input.password, "");
      if (url.endsWith("/preflight")) return Response.json({ ok: true });
      assert.equal(options.method, "POST");
      return Response.json({ ok: true });
    },
  });
  assert.equal(result.ok, true);
  assert.deepEqual(progress, ["trust", "bootstrap", "preflight", "save"]);
  assert.equal(calls.at(-1), "/api/ansible/hosts");
  assert.equal(input.sudoPassword, "");
});

test("an unknown server is not sent a password and the UI need not clear its password field yet", async () => {
  const calls = [], input = secrets();
  const result = await connectAndSaveHost(connection, input, { editing: false,
    onPasswordSubmit: () => assert.fail("password has not been submitted"),
    request: async (url, options) => { calls.push(url); assert.doesNotMatch(options.body, /fixture-only/); return Response.json({ ok: true, trusted: false }); },
  });
  assert.equal(result.stage, "trust");
  assert.equal(result.ok, false);
  assert.deepEqual(calls, ["/api/ansible/access"]);
});

test("rejected password or unsuccessful sudo preflight never creates a host; an installed key is retained for retry", async () => {
  for (const rejectedStage of ["bootstrap", "preflight"]) {
    let retainedKey = false, checks = 0;
    const result = await connectAndSaveHost(connection, secrets(), { editing: false,
      onCredential: () => { retainedKey = true; },
      request: async (url) => {
        if (url.endsWith("/access")) return Response.json({ ok: true, trusted: true });
        if (url.endsWith("/bootstrap")) return Response.json({ ok: rejectedStage !== "bootstrap", credentialId: "a".repeat(64) });
        if (url.endsWith("/preflight")) { checks++; return Response.json({ ok: false, checks: { sudo: { state: "failed" } } }); }
        assert.fail("failed onboarding must not save inventory");
      },
    });
    assert.equal(result.stage, rejectedStage);
    assert.equal(result.ok, false);
    assert.equal(retainedKey, rejectedStage === "preflight");
    assert.equal(checks, rejectedStage === "preflight" ? 1 : 0);
  }
});

test("existing connections can be checked and updated without a password or key regeneration", async () => {
  for (const credentialId of [null, "a".repeat(64)]) {
    const calls = [];
    const result = await connectAndSaveHost({ ...connection, credentialId }, { password: "", sudoPassword: "", configureSudo: false }, { editing: true,
      request: async (url, options) => {
        calls.push(url); assert.doesNotMatch(options.body, /password/i);
        assert.ok(!url.endsWith("/bootstrap"));
        if (url.endsWith("/access")) return Response.json({ ok: true, trusted: true });
        if (url.endsWith("/preflight")) return Response.json({ ok: true });
        assert.equal(options.method, "PUT");
        return Response.json({ ok: true });
      },
    });
    assert.equal(result.ok, true);
    assert.equal(calls.length, 3);
  }
});
