import { execFile, execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { getReportsDir } from "@/lib/ansible-reports";
import { ansibleSshArgs, configuredPrivateKeyPath } from "@/lib/ssh-access";
import { getInventoryHost, getInventoryTargetHosts } from "@/lib/inventory";
import { hostCredentialSudoMode } from "@/lib/host-credentials";
import {
  appendIncident as appendStoredIncident,
  readIncidents as readStoredIncidents,
  type IncidentRecord,
} from "@/lib/state-store";

const execFileAsync = promisify(execFile);

export const profileIds = new Set(["basic_linux", "ssh_security", "web_server", "docker_host"]);

export const playbooks = {
  ping: { file: "ping.yml", timeout: 120_000, kind: "audit" },
  collectFacts: { file: "collect-facts.yml", timeout: 240_000, kind: "audit" },
  agentlessAudit: { file: "agentless-audit.yml", timeout: 600_000, kind: "audit" },
  packageInventory: { file: "package-inventory.yml", timeout: 600_000, kind: "audit" },
  collectEvents: { file: "collect-security-events.yml", timeout: 360_000, kind: "audit" },
  sshCryptoAudit: { file: "ssh-crypto-audit.yml", timeout: 180_000, kind: "audit", requiresLimit: true },
  networkPortScan: { file: "nmap-scan.yml", timeout: 300_000, kind: "audit", requiresLimit: true, requiresConfirmation: true },
  lynisTemporaryAudit: { file: "lynis-temporary-audit.yml", timeout: 1_200_000, kind: "audit", requiresLimit: true, requiresConfirmation: true },
  openScapAudit: { file: "openscap-audit.yml", timeout: 1_800_000, kind: "audit", requiresLimit: true, requiresConfirmation: true },
  astraOvalAudit: { file: "astra-oval-audit.yml", timeout: 1_800_000, kind: "audit", requiresLimit: true, requiresConfirmation: true },
  closePort: { file: "close-port.yml", timeout: 240_000, kind: "response", requiresLimit: true },
  blockIp: { file: "block-ip.yml", timeout: 240_000, kind: "response", requiresLimit: true },
  backupRemediation: { file: "backup-remediation.yml", timeout: 240_000, kind: "audit", requiresLimit: true, internal: true },
  rollbackRemediation: { file: "rollback-remediation.yml", timeout: 240_000, kind: "response", requiresLimit: true, internal: true },
} as const;

export type PlaybookAction = keyof typeof playbooks;

function newReportRunId() {
  return `run-${new Date().toISOString().replace(/[-:.]/g, "")}-${randomUUID().slice(0, 8)}`;
}

/** The deterministic id of a report produced by a single-host audit run. */
export function reportIdForRun({
  action,
  profileId,
  limit,
  reportRunId,
}: {
  action: PlaybookAction;
  profileId: string;
  limit?: string;
  reportRunId: string | null;
}) {
  if (!limit || limit.includes(",") || !reportRunId || !inventoryHostExists(limit)) {
    return null;
  }

  const typeByAction: Partial<Record<PlaybookAction, string>> = {
    collectFacts: "facts",
    agentlessAudit: profileId,
    packageInventory: "packages",
    collectEvents: "events",
    sshCryptoAudit: "ssh-audit",
    networkPortScan: "nmap",
    lynisTemporaryAudit: "lynis",
    openScapAudit: "openscap",
    astraOvalAudit: "astra-oval",
  };
  const type = typeByAction[action];
  return type ? `${limit}-${type}-${reportRunId}` : null;
}

export type { IncidentRecord } from "@/lib/state-store";

export function getRepoRoot() {
  return path.resolve(process.cwd(), "..");
}

export function getStateDir(repoRoot = getRepoRoot()) {
  return process.env.HCP_STATE_DIR ? path.resolve(process.env.HCP_STATE_DIR) : path.join(repoRoot, "ansible");
}

export function isPlaybookAction(value: unknown): value is PlaybookAction {
  return typeof value === "string" && Object.hasOwn(playbooks, value);
}

export function isSafeLimit(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*(,[a-zA-Z0-9_][a-zA-Z0-9_.-]*)*$/.test(value);
}

export function isSafeServiceName(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.@:-]{1,96}$/.test(value);
}

export function isSafePackageName(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.:+-]{1,160}$/.test(value);
}

export function isSafeIp(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  const parts = value.split(".").map((part) => Number(part));
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255);
}

export function isBlockableIpv4(value: unknown): value is string {
  if (!isSafeIp(value)) {
    return false;
  }
  const [first] = value.split(".").map(Number);
  return !(
    first === 0
    || first === 127
    || first >= 224
  );
}

export function isSafePort(value: unknown): value is number {
  const port = typeof value === "string" ? Number(value) : value;
  return typeof port === "number" && Number.isInteger(port) && port > 0 && port <= 65535;
}

export function normalizeProfileId(value: unknown) {
  return typeof value === "string" && profileIds.has(value) ? value : "basic_linux";
}

type ExtraVarsResult =
  | { ok: true; values: Record<string, string> }
  | { ok: false; message: string };

export function validateExtraVars(action: PlaybookAction, extraVars: unknown): ExtraVarsResult {
  const values = extraVars && typeof extraVars === "object" ? extraVars as Record<string, unknown> : {};
  if (action === "closePort") {
    if (!isSafePort(values.target_port)) {
      return { ok: false as const, message: "Укажите корректный порт от 1 до 65535." };
    }
    if ([22].includes(Number(values.target_port))) {
      return { ok: false as const, message: "Этот порт защищен от автоматического закрытия. Изменяйте его только вручную по утвержденной процедуре." };
    }
    const protocol = values.target_protocol === "udp" ? "udp" : "tcp";
    return { ok: true, values: { target_port: String(values.target_port), target_protocol: protocol } };
  }
  if (action === "blockIp") {
    if (!isBlockableIpv4(values.block_ip)) {
      return { ok: false as const, message: "Укажите допустимый unicast IPv4-адрес для блокировки." };
    }
    return { ok: true, values: { block_ip: values.block_ip } };
  }
  return { ok: true, values: {} };
}

export function readIncidents() {
  return readStoredIncidents();
}

export function appendIncident(record: Omit<IncidentRecord, "id" | "createdAt">) {
  return appendStoredIncident(record);
}

export function inventoryHostExists(alias: string) {
  try { return Boolean(getInventoryHost(alias)); } catch { return false; }
}

export function inventoryHostConnection(alias: string) {
  if (!getInventoryHost(alias)) throw new Error("Укажите точный alias существующего хоста, не совпадающий с именем группы.");
  const inventoryPath = path.join(getRepoRoot(), "ansible", "inventory.ini");
  const output = execFileSync("ansible-inventory", ["-i", inventoryPath, "--host", alias], {
    cwd: getRepoRoot(), encoding: "utf8", timeout: 15_000, maxBuffer: 1024 * 1024,
    env: { ...process.env, ANSIBLE_FORCE_COLOR: "false" },
  });
  const variables = JSON.parse(output) as Record<string, unknown>;
  const address = variables.ansible_host ?? variables.ansible_ssh_host ?? alias;
  const port = Number(variables.ansible_port ?? variables.ansible_ssh_port ?? 22);
  if (typeof address !== "string" || !address || address.includes("{{") || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Не удалось однозначно определить адрес и порт SSH из inventory.");
  }
  const credentialId = typeof variables.hcp_ssh_credential_id === "string" && /^[a-f0-9]{64}$/.test(variables.hcp_ssh_credential_id)
    ? variables.hcp_ssh_credential_id
    : undefined;
  return { address, port, user: typeof variables.ansible_user === "string" ? variables.ansible_user : undefined, credentialId };
}

export function inventoryHostAddress(alias: string) {
  return inventoryHostExists(alias) ? inventoryHostConnection(alias).address : null;
}

/**
 * Return the host that needs a one-time sudo password for this playbook run.
 * A password cannot be sensibly or safely supplied for an inventory group,
 * therefore on-demand sudo is intentionally limited to one explicit host.
 */
export function onDemandSudoHostForLimit(limit?: string) {
  const targets = (limit ?? "linux_hosts").split(",").flatMap((target) => getInventoryTargetHosts(target));
  const aliases = [...new Set(targets.filter((host) => host.groups.includes("linux_hosts")).map((host) => host.alias))];
  const onDemand = aliases.filter((alias) => {
    const connection = inventoryHostConnection(alias);
    if (!connection.credentialId || !connection.user || connection.user === "root") return false;
    return hostCredentialSudoMode(connection.credentialId, { alias, address: connection.address, user: connection.user, port: connection.port }) === "on_demand";
  });
  if (!onDemand.length) return null;
  if (aliases.length !== 1 || !limit || limit.includes(",")) {
    throw Object.assign(new Error("Этот запуск включает хост с sudo по разовому паролю. Выберите один конкретный хост и выполните аудит вручную; плановые и групповые задания для него не запускаются."), { code: "sudo_password_host_required" });
  }
  return onDemand[0];
}

function validOneTimeSudoPassword(value: string | undefined) {
  return !value || (value.length <= 1024 && !/[\r\n\0]/.test(value));
}

function redactSecret(value: string | undefined, secret: string | undefined) {
  return secret && value ? value.split(secret).join("[скрыто]") : value ?? "";
}

export async function runAnsiblePlaybook({
  action,
  profileId,
  limit,
  extraVars = {},
  checkMode = false,
  becomePassword,
}: {
  action: PlaybookAction;
  profileId: string;
  limit?: string;
  extraVars?: Record<string, string>;
  checkMode?: boolean;
  /** A caller-provided password for one manual sudo operation; never stored. */
  becomePassword?: string;
}) {
  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  if (!existsSync(inventoryPath)) {
    throw Object.assign(new Error("Создайте ansible/inventory.ini из ansible/inventory.example.ini."), {
      code: "inventory_missing",
    });
  }

  const selected = playbooks[action];
  const targets = (limit ?? "linux_hosts").split(",").flatMap((target) => getInventoryTargetHosts(target));
  if (!targets.some((host) => host.groups.includes("linux_hosts"))) {
    throw Object.assign(new Error("В выбранной цели нет хостов группы linux_hosts; проверка не запущена."), { code: "inventory_target_missing" });
  }
  if (!validOneTimeSudoPassword(becomePassword)) {
    throw Object.assign(new Error("Пароль sudo должен быть одной строкой длиной до 1024 символов."), { code: "bad_sudo_password" });
  }
  const onDemandHost = onDemandSudoHostForLimit(limit);
  if (onDemandHost && !becomePassword) {
    throw Object.assign(new Error(`Для хоста ${onDemandHost} введите пароль sudo для этой операции. HCP не сохраняет его.`), { code: "sudo_password_required" });
  }
  const playbookPath = path.join(repoRoot, "ansible", "playbooks", selected.file);
  const args = ["-i", inventoryPath, playbookPath, "-e", `audit_profile=${profileId}`];
  if (process.env.HCP_REPORTS_DIR) {
    args.push("-e", `hcp_reports_dir=${getReportsDir(repoRoot)}`);
  }
  const reportRunId = selected.kind === "audit" && !("internal" in selected && selected.internal) && action !== "ping" ? newReportRunId() : null;
  if (reportRunId) {
    args.push("-e", `report_run_id=${reportRunId}`);
  }
  if (Object.keys(extraVars).length) {
    args.push("-e", JSON.stringify(extraVars));
  }
  if (limit) {
    args.push("--limit", limit);
  }
  if (checkMode) {
    args.push("--check", "--diff");
  }

  const command = `ansible-playbook ${args.join(" ")}`;
  let secretDirectory = "";
  try {
    let executionArgs = args;
    if (becomePassword) {
      secretDirectory = mkdtempSync(path.join(os.tmpdir(), "hcp-become-"));
      chmodSync(secretDirectory, 0o700);
      const secretFile = path.join(secretDirectory, "vars.json");
      // Keep the secret out of command arguments, environment variables,
      // inventory and report/incident data.  It is removed immediately after
      // this one Ansible child exits.
      writeFileSync(secretFile, JSON.stringify({ ansible_become_password: becomePassword }), { mode: 0o600 });
      executionArgs = [...args.slice(0, 2), "--extra-vars", `@${secretFile}`, ...args.slice(2)];
    }
    const result = await execFileAsync("ansible-playbook", executionArgs, {
      cwd: repoRoot,
      timeout: selected.timeout,
      maxBuffer: 1024 * 1024 * 8,
      // Password-prompting sudo on Astra can require a terminal.  It is
      // requested only for this one protected manual run, never globally.
      env: { ...process.env, ANSIBLE_FORCE_COLOR: "false", ANSIBLE_PIPELINING: "False", ANSIBLE_SSH_ARGS: `${ansibleSshArgs()}${becomePassword ? " -tt" : ""}`, ANSIBLE_PRIVATE_KEY_FILE: configuredPrivateKeyPath() },
    });
    return { ...result, stdout: redactSecret(result.stdout, becomePassword), stderr: redactSecret(result.stderr, becomePassword), command, repoRoot, reportRunId };
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string };
    if (becomePassword) {
      output.stdout = redactSecret(output.stdout, becomePassword);
      output.stderr = redactSecret(output.stderr, becomePassword);
      output.message = redactSecret(output.message, becomePassword);
    }
    throw error;
  } finally {
    if (secretDirectory) rmSync(secretDirectory, { recursive: true, force: true });
  }
}
