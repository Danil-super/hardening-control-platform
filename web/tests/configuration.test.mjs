import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
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

test("operator interface keeps routine work visible and allows guarded report cleanup", () => {
  const shell = read(path.join("web", "components", "layout", "app-shell.tsx"));
  const hosts = read(path.join("web", "components", "hosts", "ansible-control-client.tsx"));
  const reports = read(path.join("web", "app", "reports", "agentless", "page.tsx"));
  assert.doesNotMatch(shell, /Playbook'и/);
  assert.doesNotMatch(shell, /label: "Вход"/);
  assert.match(hosts, /Дополнительные проверки/);
  assert.match(hosts, /Глубина Nmap/);
  assert.match(hosts, /Полная TCP: 1–65 535/);
  assert.match(hosts, /nmap_scan_scope/);
  assert.match(hosts, /Обратимые изменения firewall/);
  assert.match(hosts, /Сетевой сканер Greenbone \/ OpenVAS/);
  assert.match(hosts, /Полная инструкция Greenbone/);
  assert.match(hosts, /Несвязанные ограничения основного аудита больше не блокируют изменение/);
  assert.match(hosts, /Введите точный alias выбранного хоста/);
  assert.match(reports, /Журнал действий/);
  assert.match(reports, /DeleteRecordButton/);
  assert.match(reports, /Ненужные тестовые отчёты можно удалить/);
});

test("a matching completed audit is a confirmable warning, not a hard block", () => {
  const route = read(path.join("web", "app", "api", "ansible", "run", "route.ts"));
  const preflight = read(path.join("web", "app", "api", "ansible", "audit-repeat", "route.ts"));
  const helper = read(path.join("web", "lib", "audit-repeat.ts"));
  const hosts = read(path.join("web", "components", "hosts", "ansible-control-client.tsx"));
  assert.match(route, /audit_already_completed/);
  assert.match(route, /confirmRepeatAudit/);
  assert.match(preflight, /listRemediationTransactions\(500\)/);
  assert.match(helper, /обновилась база CVE/);
  assert.match(hosts, /Запустить проверку повторно/);
  assert.match(hosts, /Не запущено/);
});

test("Nmap validates its selected TCP coverage and records it in the report", () => {
  const control = read(path.join("web", "lib", "ansible-control.ts"));
  const playbook = read(path.join("ansible", "playbooks", "nmap-scan.yml"));
  const scanner = read(path.join("ansible", "scripts", "hcp-controller-scan.py"));
  const report = read(path.join("web", "app", "reports", "agentless", "[reportId]", "page.tsx"));
  assert.match(control, /nmap_scan_scope/);
  assert.match(control, /full_tcp/);
  assert.match(playbook, /--scan-scope/);
  assert.match(scanner, /NMAP_SCAN_SCOPES/);
  assert.match(scanner, /all_tcp_1_65535/);
  assert.match(report, /Охват проверки Nmap/);
});

test("host onboarding uses verified SSH host keys and persists them", () => {
  const accessRoute = read(path.join("web", "app", "api", "ansible", "access", "route.ts"));
  const access = read(path.join("web", "lib", "ssh-access.ts"));
  const hosts = read(path.join("web", "components", "hosts", "ansible-control-client.tsx"));
  const compose = read("docker-compose.yml");
  assert.match(accessRoute, /operation === "trust"/);
  assert.match(access, /host_key_mismatch/);
  assert.match(access, /StrictHostKeyChecking=yes/);
  assert.match(hosts, /SshCredentialSetup/);
  assert.match(hosts, /connectAndSaveHost/);
  assert.match(compose, /HCP_KNOWN_HOSTS_PATH: \/var\/lib\/hcp\/known_hosts/);
});

test("host closeout revokes the HCP-managed sudo rule together with its individual key", () => {
  const revocation = read(path.join("ansible", "scripts", "hcp-ssh-revoke.py"));
  const route = read(path.join("web", "app", "api", "ansible", "hosts", "decommission", "route.ts"));
  assert.match(revocation, /zz-hcp-/);
  assert.match(revocation, /NOPASSWD: ALL/);
  assert.match(revocation, /!requiretty/);
  assert.match(revocation, /unsafe_sudo_rule/);
  assert.match(revocation, /keyRemoved/);
  assert.match(route, /credentialId: host\.credentialId/);
});

test("password onboarding uses one-time sudo without creating a sudoers rule", () => {
  const bootstrap = read(path.join("web", "app", "api", "ansible", "hosts", "bootstrap", "route.ts"));
  const onboarding = read(path.join("web", "lib", "host-onboarding.ts"));
  const helper = read(path.join("ansible", "scripts", "hcp-ssh-bootstrap.py"));
  assert.match(bootstrap, /markHostCredentialSudoOnDemand/);
  assert.match(bootstrap, /sudoMode: "on_demand"/);
  assert.match(bootstrap, /sudo_password_rejected/);
  assert.match(bootstrap, /sudo_not_permitted/);
  assert.match(bootstrap, /sudo_safe_channel_failed/);
  assert.match(bootstrap, /sudo_auth_timeout/);
  assert.match(bootstrap, /sudo_elevation_rejected_or_policy/);
  assert.match(helper, /sudo_on_demand_readiness_script/);
  assert.match(helper, /without writing an HCP-owned NOPASSWD rule/);
  assert.doesNotMatch(helper.slice(helper.indexOf("def enroll")), /sudo_setup_script\(/);
  assert.match(onboarding, /credential\.credentialId/);
  assert.match(onboarding, /credential\.sudoMode === "on_demand"/);
});

test("Ansible supplies a one-time sudo secret through a protected extra-vars file", () => {
  const config = read("ansible.cfg");
  const bootstrap = read(path.join("ansible", "scripts", "hcp-ssh-bootstrap.py"));
  const preflight = read(path.join("web", "app", "api", "ansible", "hosts", "preflight", "route.ts"));
  const control = read(path.join("web", "lib", "ansible-control.ts"));
  const sshAccess = read(path.join("web", "lib", "ssh-access.ts"));
  assert.match(config, /pipelining\s*=\s*False/);
  assert.match(config, /become_method\s*=\s*sudo/);
  assert.match(config, /become_user\s*=\s*root/);
  assert.match(config, /become_flags\s*=\s*-H -S -n/);
  assert.match(bootstrap, /sudo_readiness_script/);
  assert.match(bootstrap, /sudo -H -S -k -n -u root/);
  assert.match(bootstrap, /stty -echo/);
  assert.match(bootstrap, /SUDO_READY_MARKER/);
  assert.match(preflight, /sudo_setup_incomplete/);
  assert.match(preflight, /ansible_become_password/);
  assert.match(preflight, /ansibleSshEnvironment/);
  assert.match(control, /ansibleSshEnvironment/);
  assert.match(sshAccess, /ANSIBLE_SSH_EXTRA_ARGS/);
  assert.match(sshAccess, /ANSIBLE_SSH_ARGS: ansibleSshArgs\(\)/);
});

test("CVE checking has an explicit Trivy-only isolated-network mode", () => {
  const scan = read(path.join("web", "lib", "vulnerability-scan.ts"));
  const stateStore = read(path.join("web", "lib", "state-store.ts"));
  const compose = read("docker-compose.yml");
  assert.match(scan, /getVulnerabilityDatabaseSettings/);
  assert.match(stateStore, /HCP_TRIVY_MODE/);
  assert.match(stateStore, /runtime_settings/);
  assert.match(scan, /--offline-scan/);
  assert.doesNotMatch(scan, /OSV/);
  assert.doesNotMatch(compose, /HCP_OSV/);
});

test("advanced audit integrations preserve source and incomplete-state evidence", () => {
  const scan = read(path.join("web", "lib", "vulnerability-scan.ts"));
  const stateStore = read(path.join("web", "lib", "state-store.ts"));
  const compose = read("docker-compose.yml");
  const playbook = read(path.join("ansible", "playbooks", "openscap-audit.yml"));
  const greenbone = read(path.join("web", "app", "api", "ansible", "greenbone", "import", "route.ts"));
  assert.match(scan, /getVulnerabilityDatabaseSettings/);
  assert.match(stateStore, /HCP_TRIVY_MODE/);
  assert.match(scan, /Trivy не выполнил CVE-сопоставление/);
  assert.match(compose, /profiles: \["dependency-track"\]/);
  assert.match(playbook, /HCP_OPENSCAP_DATASTREAM/);
  assert.match(playbook, /state: absent/);
  assert.match(greenbone, /maxXmlBytes/);
});

test("operator can select an online or local Trivy database in the interface", () => {
  const route = read(path.join("web", "app", "api", "settings", "vulnerability-data", "route.ts"));
  const screen = read(path.join("web", "components", "settings", "vulnerability-data-client.tsx"));
  const shell = read(path.join("web", "components", "layout", "app-shell.tsx"));
  const proxy = read(path.join("web", "proxy.ts"));
  assert.match(route, /setVulnerabilityDatabaseMode/);
  assert.match(route, /refreshTrivyDatabase/);
  assert.match(route, /Greenbone \/ OpenVAS/);
  assert.match(screen, /Локальная база/);
  assert.match(screen, /Сетевая база/);
  assert.match(screen, /Загрузить общую базу CVE/);
  assert.match(screen, /одна общая CVE-база пакетов/);
  assert.match(shell, /data-sources/);
  assert.match(proxy, /api\/settings/);
});

test("freshness, group profiles and expiring OpenSCAP exceptions are explicit", () => {
  const scan = read(path.join("web", "lib", "vulnerability-scan.ts"));
  const store = read(path.join("web", "lib", "state-store.ts"));
  const policies = read(path.join("web", "lib", "openscap-policy.ts"));
  const route = read(path.join("web", "app", "api", "ansible", "run", "route.ts"));
  const policyScreen = read(path.join("web", "components", "settings", "openscap-policies-client.tsx"));
  const playbook = read(path.join("ansible", "playbooks", "openscap-audit.yml"));
  assert.match(scan, /HCP_TRIVY_MAX_DB_AGE_HOURS/);
  assert.match(scan, /function freshnessFinding/);
  assert.match(scan, /trivyDatabaseRequiredMessage/);
  assert.match(store, /openscap_policies/);
  assert.match(store, /openscap_exceptions/);
  assert.match(policies, /exceptionsApplied/);
  assert.match(route, /resolveOpenScapPolicyForHost/);
  assert.match(route, /applyOpenScapExceptions/);
  assert.match(policyScreen, /Согласованное исключение/);
  assert.match(playbook, /hcp_openscap_datastream/);
  assert.match(playbook, /datastream-checksum/);
});

test("OpenSCAP and Greenbone XML are normalized as distinct sources", () => {
  const temporaryDir = mkdtempSync(path.join(tmpdir(), "hcp-parser-test-"));
  const script = path.join(repoRoot, "ansible", "scripts", "hcp-controller-scan.py");
  try {
    const openscapInput = path.join(temporaryDir, "openscap.xml");
    const openscapOutput = path.join(temporaryDir, "openscap.json");
    writeFileSync(openscapInput, `<?xml version="1.0"?>
      <root xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
        <Rule id="xccdf_rule_disable_root" severity="high"><title>Disable SSH root login</title></Rule>
        <xccdf:rule-result idref="xccdf_rule_disable_root"><xccdf:result>fail</xccdf:result></xccdf:rule-result>
      </root>`);
    execFileSync("python3", [script, "openscap-arf", "--input", openscapInput, "--inventory-host", "host-1", "--run-id", "run-test", "--profile", "profile", "--datastream", "/ssg.xml", "--policy-group", "scap_hosts", "--datastream-checksum", "sha256:test", "--output", openscapOutput]);
    const openscap = JSON.parse(readFileSync(openscapOutput, "utf8"));
    assert.equal(openscap.mode, "openscap");
    assert.equal(openscap.findings[0].source, "openscap");
    assert.equal(openscap.findings[0].status, "failed");
    assert.equal(openscap.findings[0].risk, "high");
    assert.equal(openscap.scanner.policyGroup, "scap_hosts");
    assert.equal(openscap.scanner.datastreamChecksum, "sha256:test");

    const greenboneInput = path.join(temporaryDir, "greenbone.xml");
    const greenboneOutput = path.join(temporaryDir, "greenbone.json");
    writeFileSync(greenboneInput, `<?xml version="1.0"?>
      <report><scan_run_status>Done</scan_run_status><results><result id="result-1"><host>10.0.0.10</host><port>443/tcp</port><threat>High</threat><severity>8.8</severity><qod><value>80</value></qod><description>Test finding</description><solution>Patch package</solution><nvt oid="1.3.6.1.4.1"><name>TLS issue</name><cve>CVE-2026-0001</cve></nvt></result></results></report>`);
    execFileSync("python3", [script, "greenbone-report", "--input", greenboneInput, "--host", "10.0.0.10", "--inventory-host", "host-1", "--run-id", "run-test", "--output", greenboneOutput]);
    const greenbone = JSON.parse(readFileSync(greenboneOutput, "utf8"));
    assert.equal(greenbone.mode, "greenbone");
    assert.equal(greenbone.findings[0].source, "greenbone");
    assert.equal(greenbone.findings[0].status, "failed");
    assert.match(greenbone.findings[0].evidence, /port=443\/tcp/);
  } finally {
    rmSync(temporaryDir, { recursive: true, force: true });
  }
});

test("deep audit scheduling keeps package scanning authenticated and OpenSCAP opt-in", () => {
  const scheduler = read(path.join("deployment", "hcp-scheduled-audit"));
  const deepService = read(path.join("deployment", "systemd", "hcp-deep-audit.service"));
  const deepTimer = read(path.join("deployment", "systemd", "hcp-deep-audit.timer"));
  const route = read(path.join("web", "app", "api", "internal", "scheduled", "package-vulnerabilities", "route.ts"));
  assert.match(scheduler, /HCP_SCHEDULE_TASKS/);
  assert.match(scheduler, /HCP_SCHEDULE_API_KEY/);
  assert.match(scheduler, /run_openscap/);
  assert.match(deepService, /HCP_DEEP_SCHEDULE_TASKS=packages/);
  assert.match(deepTimer, /OnCalendar=\*-\*-\* 02:30:00/);
  assert.match(route, /isScheduledRequestAuthorized/);
  assert.match(read(path.join("web", "lib", "scheduled-auth.ts")), /timingSafeEqual/);
  assert.match(route, /syncDependencyTrack/);
});

test("correlation and vendor-aware package evidence are available in reports", () => {
  const correlation = read(path.join("web", "lib", "audit-correlation.ts"));
  const reportPage = read(path.join("web", "app", "reports", "correlation", "[hostAlias]", "page.tsx"));
  const vulnerabilities = read(path.join("web", "lib", "vulnerability-scan.ts"));
  const inventory = read(path.join("ansible", "playbooks", "package-inventory.yml"));
  assert.match(correlation, /CVE-\\d\{4\}/);
  assert.match(correlation, /HCP_CORRELATION_MAX_AGE_HOURS/);
  assert.match(reportPage, /Совпадение CVE или порта не подтверждает уязвимость/);
  assert.match(vulnerabilities, /vendor_status=/);
  assert.match(vulnerabilities, /will_not_fix/);
  assert.match(inventory, /EPOCHNUM/);
});
