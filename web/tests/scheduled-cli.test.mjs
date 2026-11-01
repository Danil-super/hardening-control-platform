import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execute = promisify(execFile);
const script = fileURLToPath(new URL("../../deployment/hcp-scheduled-audit", import.meta.url));

async function withScheduler(run, reply = () => ({ status: 200, body: { ok: true, partial: false, results: [{ hostAlias: "modern-host", reportId: "fresh-report", partial: false }] } })) {
  const directory = mkdtempSync(path.join(tmpdir(), "hcp-scheduled-cli-test-"));
  const bin = path.join(directory, "bin");
  const marker = path.join(directory, "unexpected-ansible");
  mkdirSync(bin);
  // If the shell regresses to bypassing the service, this executable is called
  // and records that real behavior; no source-text assertion is involved.
  writeFileSync(path.join(bin, "ansible-playbook"), '#!/bin/sh\n: > "$HCP_TEST_ANSIBLE_MARKER"\nexit 97\n', { mode: 0o700 });
  const requests = [];
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => {
      const record = { path: request.url, headers: request.headers, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) };
      requests.push(record);
      const result = reply(record);
      response.writeHead(result.status, { "content-type": "application/json" });
      response.end(JSON.stringify(result.body));
    });
  });
  try {
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const invoke = async overrides => {
      const env = { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`, PORT: String(server.address().port),
        HCP_SCHEDULE_API_KEY: "schedule-cli-key", HCP_SCHEDULE_PROFILE: "ssh_security", HCP_SCHEDULE_LIMIT: "modern-host",
        HCP_SCHEDULE_DEEP_LIMIT: "linux_hosts", HCP_SCHEDULE_TASKS: "agentless", HCP_SCHEDULE_LOCK: path.join(directory, "schedule.lock"),
        HCP_TEST_ANSIBLE_MARKER: marker, ...overrides };
      let result;
      try { result = { ...(await execute("/bin/sh", [script], { env, timeout: 20_000, maxBuffer: 1024 * 1024 })), code: 0 }; }
      catch (error) { result = { code: error.code, stdout: error.stdout, stderr: error.stderr }; }
      assert.equal(existsSync(marker), false, "scheduled collection must never invoke PATH ansible-playbook directly");
      return { ...result, payloads: (result.stdout ?? "").trim().split("\n").filter(Boolean).map(line => JSON.parse(line)) };
    };
    await run({ invoke, requests });
  } finally {
    await new Promise(resolve => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  }
}

test("the scheduled CLI authenticates agentless and package collection through their common API paths", async () => {
  await withScheduler(async ({ invoke, requests }) => {
    const result = await invoke({ HCP_SCHEDULE_TASKS: "agentless,packages,openscap" });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.payloads.length, 3);
    assert.deepEqual(requests.map(request => request.path), ["agentless", "package-vulnerabilities", "openscap"].map(task => `/api/internal/scheduled/${task}`));
    assert.deepEqual(requests.map(request => request.body.limit), ["modern-host", "linux_hosts", "linux_hosts"]);
    assert.equal(requests[0].body.profileId, "ssh_security");
    assert.equal(requests[1].body.profileId, undefined);
    assert.ok(requests.every(request => request.headers["x-hcp-schedule-key"] === "schedule-cli-key"));
    assert.ok(requests.every(request => /^schedule-\d{8}T\d{6}Z$/.test(request.body.reportRunId)));
    assert.equal(new Set(requests.map(request => request.body.reportRunId)).size, 1);
  });
});

test("a partial first task prints its evidence, runs the remaining tasks, and leaves the batch unsuccessful", async () => {
  await withScheduler(async ({ invoke, requests }) => {
    const result = await invoke({ HCP_SCHEDULE_TASKS: "packages,agentless,openscap" });
    assert.equal(result.code, 1);
    assert.equal(requests.length, 3);
    assert.deepEqual(result.payloads.map(body => body.partial), [true, false, false]);
    assert.equal(result.payloads[0].results[0].errorCode, "sudo_password_required");
    assert.match(result.stderr, /207/);
  }, request => request.path.endsWith("package-vulnerabilities")
    ? { status: 207, body: { ok: false, partial: true, results: [{ hostAlias: "modern-host", partial: true, errorCode: "sudo_password_required" }] } }
    : { status: 200, body: { ok: true, partial: false, results: [{ hostAlias: "modern-host", partial: false }] } });
});

test("invalid scheduler configuration is rejected before any request or Ansible call", async () => {
  await withScheduler(async ({ invoke, requests }) => {
    for (const overrides of [
      { HCP_SCHEDULE_API_KEY: "" }, { HCP_SCHEDULE_API_KEY: "  " },
      { HCP_SCHEDULE_TASKS: "agentless,unknown" }, { HCP_SCHEDULE_TASKS: "agentless,,packages" },
      { HCP_SCHEDULE_LIMIT: "--all" }, { HCP_SCHEDULE_DEEP_LIMIT: "host1,host2" },
      { HCP_SCHEDULE_PROFILE: "unknown" }, { PORT: "0" },
    ]) {
      const result = await invoke(overrides);
      assert.notEqual(result.code, 0, JSON.stringify(overrides));
      assert.deepEqual(result.payloads, []);
    }
    assert.equal(requests.length, 0);
  });
});

test("HTTP authorization errors and empty-success responses cannot make the CLI succeed", async () => {
  for (const reply of [
    { status: 401, body: { ok: false, message: "Invalid schedule key" } },
    { status: 200, body: { ok: true, partial: false, results: [] } },
    { status: 207, body: { ok: true, partial: true, results: [{ hostAlias: "modern-host", partial: true }] } },
  ]) {
    await withScheduler(async ({ invoke }) => {
      const result = await invoke();
      assert.equal(result.code, 1);
      assert.deepEqual(result.payloads, [reply.body]);
    }, () => reply);
  }
});
