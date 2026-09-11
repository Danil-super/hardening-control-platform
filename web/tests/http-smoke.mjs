// Exercises the production Next server with isolated state and explicit fixtures.
// Does not claim to execute remote scanners or change any host's firewall.
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporary = mkdtempSync(path.join(os.tmpdir(), "hcp-http-smoke-"));
const reports = path.join(temporary, "reports");
const sshKey = path.join(temporary, "fixture-key");
execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-f", sshKey], { stdio: "ignore" });
mkdirSync(reports);
const probe = createServer();
await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
const port = probe.address().port;
await new Promise((resolve) => probe.close(resolve));
const base = `http://127.0.0.1:${port}`;
const reportId = "smoke-vulnerabilities-run-http";
writeFileSync(path.join(reports, `${reportId}.json`), JSON.stringify({
  inventoryHost: "smoke", hostname: "fixture-host", createdAt: new Date().toISOString(),
  mode: "vulnerabilities", profileId: "cve_packages", summary: { score: 99, high: 7, total: 7 },
  scanner: { available: false, partial: true },
  vulnerabilityScan: { partial: true, message: "Фикстура: база отсутствует" },
  findings: [{ id: "fixture", title: "Сканер недоступен", description: "Контролируемый вход интеграционного теста",
    category: "CVE пакеты", source: "trivy", risk: "info", status: "manual", recommendation: "Повторить аудит", remediationAvailable: false }],
}));
let child;
const ovalReportId = "smoke-astra-oval-run-http";
writeFileSync(path.join(reports, `${ovalReportId}.json`), JSON.stringify({
  inventoryHost: "smoke", hostname: "fixture-host", createdAt: new Date().toISOString(), mode: "astra-oval", profileId: "astra-oval",
  scanner: { available: true, partial: false, fullCveCoverage: false, uniqueCveCount: 1, definitionCount: 2, evaluatedDefinitionCount: 2,
    version: "OpenSCAP HTTP fixture", hostIdentity: { astraVersion: "test-release" },
    database: { generatedAt: new Date().toISOString(), sourceMode: "local", path: "/fixture/oval.xml", sha256: "a".repeat(64), checksumVerified: true, releasePattern: "*", freshness: "current", ageDays: 0 },
    definitionResults: [{ id: "oval:fixture:def:1", title: "HTTP fixture only", class: "vulnerability", result: "true", cveIds: ["CVE-2099-999999"] }] },
  findings: [{ id: "fixture-oval", profileId: "astra-oval", title: "CVE-2099-999999", category: "packages",
    source: "openscap", risk: "info", severityUnknown: true, status: "failed", description: "Контрольная находка без оценки поставщика",
    recommendation: "Проверить бюллетень", remediationAvailable: false }], events: [],
}));
let output = "";
let cookie = "";
let checks = 0;

async function start() {
  child = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", String(port)], {
    cwd: webDir, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, NODE_ENV: "production", NEXT_TELEMETRY_DISABLED: "1",
      HCP_STATE_DIR: temporary, HCP_REPORTS_DIR: reports,
      HCP_ADMIN_PASSWORD: "http-smoke-password", HCP_AUTH_SECRET: "http-smoke-session-key",
      HCP_AUDIT_HMAC_KEY: "http-smoke-ledger-key", HCP_SCHEDULE_API_KEY: "http-smoke-schedule-key",
      HCP_TRIVY_MODE: "offline", HCP_TRIVY_CACHE_DIR: path.join(temporary, "trivy-cache"),
      HCP_SSH_PRIVATE_KEY_PATH: sshKey, HCP_PRODUCTION_MODE: "true" },
  });
  for (const stream of [child.stdout, child.stderr]) stream.on("data", (value) => { output = (output + value).slice(-12000); });
  for (let attempt = 0; attempt < 160; attempt++) {
    if (child.exitCode !== null) throw new Error(`Next exited during startup: ${output}`);
    try { if ((await fetch(`${base}/login`)).ok) return; } catch { /* server is starting */ }
    await delay(250);
  }
  throw new Error(`Next did not become ready: ${output}`);
}

async function stop() {
  if (!child || child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGTERM");
  await Promise.race([exited, delay(5000)]);
  if (child.exitCode === null) { child.kill("SIGKILL"); await exited; }
}

async function request(endpoint, { method = "GET", body, auth = true, origin = base, status = 200 } = {}) {
  const response = await fetch(base + endpoint, {
    method, redirect: "manual", headers: { "Content-Type": "application/json", Origin: origin, ...(auth && cookie ? { Cookie: cookie } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  assert.equal(response.status, status, `${method} ${endpoint}`);
  checks++;
  return response;
}

try {
  await start();
  await request("/api/ansible/hosts", { auth: false, status: 401 });
  await request("/api/ansible/session", { auth: false, status: 401 });
  await request("/api/settings/astra-oval", { auth: false, status: 401 });
  await request(`/reports/agentless/${reportId}`, { auth: false, status: 307 });
  await request("/reports/correlation/smoke", { auth: false, status: 307 });
  await request("/api/ansible/auth/login", { method: "POST", body: { password: "wrong" }, auth: false, status: 401 });
  const login = await request("/api/ansible/auth/login", { method: "POST", body: { password: "http-smoke-password" }, auth: false });
  cookie = login.headers.get("set-cookie").split(";", 1)[0];
  assert.match(cookie, /^hcp_admin_session=/);
  await request("/api/ansible/session");
  assert.match(login.headers.get("set-cookie"), /HttpOnly/i);
  assert.match(login.headers.get("set-cookie"), /Path=\//i);
  const hostsPage = await (await request("/hosts")).text();
  assert.match(hostsPage, /Управляемые хосты/);
  assert.match(hostsPage, /Обновить сведения/);
  const keyBefore = readFileSync(sshKey, "utf8");
  const firstKey = await (await request("/api/ansible/access")).json();
  const refreshedKey = await (await request("/api/ansible/access")).json();
  assert.equal(firstKey.ok, true);
  assert.match(firstKey.fingerprint, /^SHA256:/);
  assert.equal(firstKey.publicKey, refreshedKey.publicKey);
  assert.equal(readFileSync(sshKey, "utf8"), keyBefore, "reading the public key must never rotate the private key");
  renameSync(sshKey, `${sshKey}.unavailable`);
  const missingKey = await (await request("/api/ansible/access", { status: 400 })).json();
  assert.equal(missingKey.ok, false);
  assert.equal(missingKey.error, "control_key_missing");
  renameSync(`${sshKey}.unavailable`, sshKey);
  await request("/api/settings/vulnerability-data", { method: "PATCH", origin: "https://foreign.invalid", body: { mode: "online" }, status: 403 });
  const settings = await (await request("/api/settings/vulnerability-data", { method: "PATCH", body: { mode: "online" } })).json();
  assert.equal(settings.database.mode, "online");
  assert.equal(settings.freshness.status, "missing");
  const ovalSettings = await (await request("/api/settings/astra-oval")).json();
  assert.deepEqual(ovalSettings.policies, []);
  await request("/api/settings/astra-oval", { method: "POST", origin: "https://foreign.invalid", body: {}, status: 403 });
  await request("/api/settings/astra-oval", { method: "POST", body: { groupName: "nonexistent-smoke-group", config: {} }, status: 400 });
  const ovalPage = await (await request(`/reports/agentless/${ovalReportId}`)).text();
  assert.match(ovalPage, /Результат OVAL-аудита Astra/);
  assert.match(ovalPage, /Уникальных CVE обнаружено/);
  assert.match(ovalPage, /CVE-2099-999999/);
  assert.match(ovalPage, /test-release/);
  assert.match(ovalPage, /Риск не оценён/);
  const correlated = await (await request("/reports/correlation/smoke")).text();
  assert.match(correlated, /Риск не оценён/);
  await request("/api/internal/scheduled/openscap", { method: "POST", body: {}, auth: false, status: 401 });
  const report = await (await request(`/api/ansible/reports/${reportId}`)).json();
  assert.equal(report.report.partial, true);
  assert.equal(report.report.score, null);
  assert.equal(report.report.high, 0);
  assert.equal(report.report.eventsCount, 0);
  const rendered = await (await request(`/reports/agentless/${reportId}`)).text();
  assert.match(rendered, /Сканер не выполнил проверку/);
  assert.doesNotMatch(rendered, />99%/);
  await request("/reports/correlation/smoke");
  await request("/hosts");
  await request("/data-sources");
  await request("/policies");
  await stop();
  await start();
  const persisted = await (await request("/api/settings/vulnerability-data")).json();
  assert.equal(persisted.database.mode, "online");
  await request(`/api/ansible/reports/${reportId}`);
  await request("/reports/agentless");
  const logout = await request("/api/ansible/auth/logout", { method: "POST" });
  assert.match(logout.headers.get("set-cookie"), /Max-Age=0/i);
  assert.doesNotMatch(logout.headers.get("set-cookie"), /;\s*Secure/i, "HTTP deployment must be able to clear its session cookie");
  cookie = "";
  await request("/api/ansible/hosts", { status: 401 });
  console.log(`PASS ${checks} HTTP checks: auth, CSRF, report rendering, source selection and restart persistence (isolated fixtures)`);
} finally {
  await stop();
  rmSync(temporary, { recursive: true, force: true });
}
