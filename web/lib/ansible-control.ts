import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const profileIds = new Set(["basic_linux", "ssh_security", "web_server", "docker_host"]);

export const playbooks = {
  ping: { file: "ping.yml", timeout: 120_000, kind: "audit" },
  collectFacts: { file: "collect-facts.yml", timeout: 240_000, kind: "audit" },
  agentlessAudit: { file: "agentless-audit.yml", timeout: 600_000, kind: "audit" },
  packageInventory: { file: "package-inventory.yml", timeout: 600_000, kind: "audit" },
  collectEvents: { file: "collect-security-events.yml", timeout: 360_000, kind: "audit" },
  closeDangerousPorts: { file: "close-dangerous-ports.yml", timeout: 240_000, kind: "response", requiresLimit: true },
  closePort: { file: "close-port.yml", timeout: 240_000, kind: "response", requiresLimit: true },
  updatePackage: { file: "update-package.yml", timeout: 600_000, kind: "response", requiresLimit: true },
  blockIp: { file: "block-ip.yml", timeout: 240_000, kind: "response", requiresLimit: true },
  stopService: { file: "stop-service.yml", timeout: 240_000, kind: "response", requiresLimit: true },
} as const;

export type PlaybookAction = keyof typeof playbooks;

export type IncidentRecord = {
  id: string;
  createdAt: string;
  action: string;
  kind: "audit" | "response" | "system";
  status: "success" | "failed";
  profileId: string;
  limit: string | null;
  message: string;
  command?: string;
};

export function getRepoRoot() {
  return path.resolve(process.cwd(), "..");
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
    const protocol = values.target_protocol === "udp" ? "udp" : "tcp";
    return { ok: true, values: { target_port: String(values.target_port), target_protocol: protocol } };
  }
  if (action === "blockIp") {
    if (!isSafeIp(values.block_ip)) {
      return { ok: false as const, message: "Укажите корректный IPv4-адрес для блокировки." };
    }
    return { ok: true, values: { block_ip: values.block_ip } };
  }
  if (action === "updatePackage") {
    if (!isSafePackageName(values.package_name)) {
      return { ok: false as const, message: "Укажите корректное имя пакета." };
    }
    return { ok: true, values: { package_name: values.package_name } };
  }
  if (action === "stopService") {
    if (!isSafeServiceName(values.service_name)) {
      return { ok: false as const, message: "Укажите корректное имя systemd-сервиса." };
    }
    return { ok: true, values: { service_name: values.service_name } };
  }
  return { ok: true, values: {} };
}

function ensureDir(dirPath: string) {
  if (!existsSync(dirPath)) {
    mkdirSync(dirPath, { recursive: true });
  }
}

function getIncidentPath(repoRoot = getRepoRoot()) {
  return path.join(repoRoot, "ansible", "incidents.json");
}

export function readIncidents(repoRoot = getRepoRoot()) {
  const incidentPath = getIncidentPath(repoRoot);
  if (!existsSync(incidentPath)) {
    return [] as IncidentRecord[];
  }
  try {
    const parsed = JSON.parse(readFileSync(incidentPath, "utf8"));
    return Array.isArray(parsed) ? parsed as IncidentRecord[] : [];
  } catch {
    return [];
  }
}

export function appendIncident(record: Omit<IncidentRecord, "id" | "createdAt">, repoRoot = getRepoRoot()) {
  ensureDir(path.join(repoRoot, "ansible"));
  const incidents = readIncidents(repoRoot);
  const createdAt = new Date().toISOString();
  const next: IncidentRecord = {
    id: `incident_${createdAt.replace(/[-:.TZ]/g, "")}_${Math.random().toString(16).slice(2, 8)}`,
    createdAt,
    ...record,
  };
  writeFileSync(getIncidentPath(repoRoot), JSON.stringify([next, ...incidents].slice(0, 300), null, 2));
  return next;
}

export async function runAnsiblePlaybook({
  action,
  profileId,
  limit,
  extraVars = {},
}: {
  action: PlaybookAction;
  profileId: string;
  limit?: string;
  extraVars?: Record<string, string>;
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
  for (const [key, value] of Object.entries(extraVars)) {
    args.push("-e", `${key}=${value}`);
  }
  if (limit) {
    args.push("--limit", limit);
  }

  const command = `ansible-playbook ${args.join(" ")}`;
  const result = await execFileAsync("ansible-playbook", args, {
    cwd: repoRoot,
    timeout: selected.timeout,
    maxBuffer: 1024 * 1024 * 8,
    env: { ...process.env, ANSIBLE_FORCE_COLOR: "false" },
  });

  return { ...result, command, repoRoot };
}
