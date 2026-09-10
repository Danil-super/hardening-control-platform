import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, afterEach, beforeEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

// Test the production adapter over HTTP against a local contract stub.
// This verifies request/response handling, not a deployed Dependency-Track instance.
const compiled = compileServerModules(["dependency-track"]);
writeFileSync(path.join(compiled.directory, "ansible-control.mjs"), 'export const getStateDir = () => process.env.HCP_TEST_DT_DIR;');
writeFileSync(path.join(compiled.directory, "ansible-reports.mjs"), 'export const getReportsDir = () => process.env.HCP_TEST_DT_DIR + "/reports";');
const { syncDependencyTrack } = await import(compiled.url("dependency-track"));
const priorEnvironment = Object.fromEntries(["HCP_TEST_DT_DIR", "HCP_DEPENDENCY_TRACK_URL", "HCP_DEPENDENCY_TRACK_API_KEY"].map((key) => [key, process.env[key]]));
const token = "3f6d559b-4023-4d72-a17e-5aa083e621b3";
let directory;
let server;
let received;
let reply;

beforeEach(async () => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-dependency-track-"));
  mkdirSync(path.join(directory, "reports"));
  mkdirSync(path.join(directory, "sbom"));
  process.env.HCP_TEST_DT_DIR = directory;
  process.env.HCP_DEPENDENCY_TRACK_API_KEY = "test-api-key";
  writeFileSync(path.join(directory, "reports", "cve-test.json"), JSON.stringify({
    inventoryHost: "host-one", mode: "vulnerabilities", os: "Linux test",
    vulnerabilityScan: { sbomFile: "host-one.json" },
  }));
  writeFileSync(path.join(directory, "sbom", "host-one.json"), JSON.stringify({
    bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components: [{ type: "library", name: "test-package", version: "1.0" }],
  }));
  received = [];
  reply = { status: 200, body: JSON.stringify({ token }) };
  server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received.push({ method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString() });
    response.writeHead(reply.status, reply.headers ?? { "Content-Type": "application/json" });
    response.end(reply.body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  process.env.HCP_DEPENDENCY_TRACK_URL = `http://127.0.0.1:${server.address().port}`;
});

afterEach(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  rmSync(directory, { recursive: true, force: true });
});
after(() => {
  for (const [key, value] of Object.entries(priorEnvironment)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  rmSync(compiled.directory, { recursive: true, force: true });
});

const synchronize = (hostAlias = "host-one") => syncDependencyTrack({ hostAlias, vulnerabilityReportId: "cve-test" });

test("Dependency-Track upload uses the correct contract and preserves a pending token", async () => {
  const result = await synchronize();
  assert.equal(result.configured, true);
  assert.equal(received.length, 1);
  assert.equal(received[0].method, "PUT");
  assert.equal(received[0].url, "/api/v1/bom");
  assert.equal(received[0].headers["x-api-key"], "test-api-key");
  const body = JSON.parse(received[0].body);
  assert.equal(body.projectName, "host-one");
  assert.equal(body.autoCreate, true);
  assert.equal(JSON.parse(Buffer.from(body.bom, "base64").toString()).bomFormat, "CycloneDX");
  const report = JSON.parse(readFileSync(path.join(directory, "reports", `${result.reportId}.json`), "utf8"));
  assert.equal(report.scanner.processingToken, token);
  assert.equal(report.scanner.analysisStatus, "pending");
  assert.equal(report.scanner.partial, true);
  assert.equal(report.findings[0].status, "manual");
});

test("Dependency-Track rejects a report belonging to a different host before transmission", async () => {
  await assert.rejects(synchronize("host-two"), /не принадлежит/);
  assert.equal(received.length, 0);
});

test("Dependency-Track rejects empty component inventories before transmission", async () => {
  writeFileSync(path.join(directory, "sbom", "host-one.json"), JSON.stringify({ bomFormat: "CycloneDX", components: [] }));
  await assert.rejects(synchronize(), /не содержит компонентов/);
  assert.equal(received.length, 0);
});

test("Dependency-Track does not mistake an HTTP 200 frontend or empty JSON for accepted analysis", async () => {
  for (const body of ["<html>frontend</html>", "{}", '{"token":"invalid"}']) {
    reply.body = body;
    await assert.rejects(synchronize(), /не вернул токен/);
  }
  assert.deepEqual(readdirSync(path.join(directory, "reports")), ["cve-test.json"]);
});

test("Dependency-Track reports rejected HTTP responses without a success report", async () => {
  reply = { status: 403, body: "forbidden" };
  await assert.rejects(synchronize(), /403/);
  assert.deepEqual(readdirSync(path.join(directory, "reports")), ["cve-test.json"]);
});

test("Dependency-Track does not forward its API key through redirects", async () => {
  reply = { status: 302, headers: { Location: "/other-server" }, body: "redirect" };
  await assert.rejects(synchronize());
  assert.equal(received.length, 1);
});

test("Unconfigured Dependency-Track performs no network request", async () => {
  delete process.env.HCP_DEPENDENCY_TRACK_API_KEY;
  const result = await synchronize();
  assert.equal(result.configured, false);
  assert.equal(received.length, 0);
});
