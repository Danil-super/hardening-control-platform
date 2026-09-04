import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { getReportsDir } from "@/lib/ansible-reports";
import { ansibleSshArgs } from "@/lib/ssh-access";
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
  if (!limit || limit.includes(",") || !reportRunId) {
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
  return typeof value === "string" && value in playbooks;
}

export function isSafeLimit(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.:-]+(,[a-zA-Z0-9_.:-]+)*$/.test(value);
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
  const inventoryPath = path.join(getRepoRoot(), "ansible", "inventory.ini");
  if (!existsSync(inventoryPath)) {
    return false;
  }
  return readFileSync(inventoryPath, "utf8").split("\n").some((rawLine) => {
    const line = rawLine.trim();
    return Boolean(line) && !line.startsWith("#") && !line.startsWith("[") && line.split(/\s+/, 1)[0] === alias;
  });
}

export function inventoryHostAddress(alias: string) {
  const inventoryPath = path.join(getRepoRoot(), "ansible", "inventory.ini");
  if (!existsSync(inventoryPath)) {
    return null;
  }
  for (const rawLine of readFileSync(inventoryPath, "utf8").split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("[")) {
      continue;
    }
    const tokens = line.split(/\s+/);
    if (tokens[0] !== alias) {
      continue;
    }
    const address = tokens.find((token) => token.startsWith("ansible_host="))?.slice("ansible_host=".length);
    return address ?? alias;
  }
  return null;
}

export async function runAnsiblePlaybook({
  action,
  profileId,
  limit,
  extraVars = {},
  checkMode = false,
}: {
  action: PlaybookAction;
  profileId: string;
  limit?: string;
  extraVars?: Record<string, string>;
  checkMode?: boolean;
}) {
  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  if (!existsSync(inventoryPath)) {
    throw Object.assign(new Error("Создайте ansible/inventory.ini из ansible/inventory.example.ini."), {
      code: "inventory_missing",
    });
  }

  const selected = playbooks[action];
  const playbookPath = path.join(repoRoot, "ansible", "playbooks", selected.file);
  const args = ["-i", inventoryPath, playbookPath, "-e", `audit_profile=${profileId}`];
  if (process.env.HCP_REPORTS_DIR) {
    args.push("-e", `hcp_reports_dir=${getReportsDir(repoRoot)}`);
  }
  const reportRunId = selected.kind === "audit" && !("internal" in selected && selected.internal) && action !== "ping" ? newReportRunId() : null;
  if (reportRunId) {
    args.push("-e", `report_run_id=${reportRunId}`);
  }
  for (const [key, value] of Object.entries(extraVars)) {
    args.push("-e", `${key}=${value}`);
  }
  if (limit) {
    args.push("--limit", limit);
  }
  if (checkMode) {
    args.push("--check", "--diff");
  }

  const command = `ansible-playbook ${args.join(" ")}`;
  const result = await execFileAsync("ansible-playbook", args, {
    cwd: repoRoot,
    timeout: selected.timeout,
    maxBuffer: 1024 * 1024 * 8,
    env: { ...process.env, ANSIBLE_FORCE_COLOR: "false", ANSIBLE_SSH_ARGS: ansibleSshArgs() },
  });

  return { ...result, command, repoRoot, reportRunId };
}
