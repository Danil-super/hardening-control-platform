import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(webDir, "..");

function read(relativePath) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

test("all production audit profiles have their own versioned rule files", () => {
  for (const fileName of ["basic-linux.yml", "ssh-security.yml", "web-server.yml", "docker-host.yml"]) {
    const content = read(path.join("ansible", "audit-rules", fileName));
    assert.match(content, /audit_rules_version:\s*"1\.0\.0"/);
  }
});

test("remediation flow uses backup, rollback and a typed host confirmation", () => {
  const route = read(path.join("web", "app", "api", "ansible", "run", "route.ts"));
  const remediation = read(path.join("web", "lib", "remediation.ts"));
  assert.match(route, /host_confirmation_required/);
  assert.match(route, /mode === "preview"/);
  assert.match(remediation, /backupRemediation/);
  assert.match(remediation, /rollbackRemediation/);
});

test("the old in-memory scheduler is not part of the application API", () => {
  const systemdService = read(path.join("deployment", "systemd", "hcp-scheduled-audit.service"));
  const timer = read(path.join("deployment", "systemd", "hcp-scheduled-audit.timer"));
  assert.match(systemdService, /hcp-scheduled-audit/);
  assert.match(timer, /Persistent=true/);
});

test("operator interface keeps routine work visible and hides destructive log controls", () => {
  const shell = read(path.join("web", "components", "layout", "app-shell.tsx"));
  const hosts = read(path.join("web", "components", "hosts", "ansible-control-client.tsx"));
  const reports = read(path.join("web", "app", "reports", "agentless", "page.tsx"));
  assert.doesNotMatch(shell, /Playbook'и/);
  assert.doesNotMatch(shell, /label: "Вход"/);
  assert.match(hosts, /Дополнительные проверки/);
  assert.match(hosts, /Обратимые изменения firewall/);
  assert.match(hosts, /Введите точный alias выбранного хоста/);
  assert.match(reports, /Журнал действий/);
  assert.doesNotMatch(reports, /DeleteRecordButton/);
});

test("host onboarding uses verified SSH host keys and persists them", () => {
  const accessRoute = read(path.join("web", "app", "api", "ansible", "access", "route.ts"));
  const access = read(path.join("web", "lib", "ssh-access.ts"));
  const hosts = read(path.join("web", "components", "hosts", "ansible-control-client.tsx"));
  const compose = read("docker-compose.yml");
  assert.match(accessRoute, /operation === "trust"/);
  assert.match(access, /host_key_mismatch/);
  assert.match(access, /StrictHostKeyChecking=yes/);
  assert.match(hosts, /Мастер первого SSH-подключения/);
  assert.match(hosts, /Сначала успешно проверьте это SSH-подключение/);
  assert.match(compose, /HCP_KNOWN_HOSTS_PATH: \/var\/lib\/hcp\/known_hosts/);
});

test("CVE checking has an explicit isolated-network mode", () => {
  const scan = read(path.join("web", "lib", "vulnerability-scan.ts"));
  const compose = read("docker-compose.yml");
  assert.match(scan, /HCP_OSV_MODE/);
  assert.match(scan, /CVE-сопоставление отключено для изолированной сети/);
  assert.match(compose, /HCP_OSV_BASE_URL/);
});
