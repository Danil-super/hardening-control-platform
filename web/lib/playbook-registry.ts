import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { appendIncident, getRepoRoot, isSafeLimit, playbooks } from "@/lib/ansible-control";

const execFileAsync = promisify(execFile);

export type PlaybookVariable = {
  name: string;
  label: string;
  type: "string" | "number";
  required: boolean;
  defaultValue?: string;
  placeholder?: string;
};

export type RegisteredPlaybook = {
  id: string;
  title: string;
  file: string;
  kind: "audit" | "response";
  source: "builtin" | "custom";
  requiresLimit: boolean;
  timeout: number;
  variables: PlaybookVariable[];
};

type PlaybookMeta = Omit<RegisteredPlaybook, "source" | "file" | "timeout"> & {
  file?: string;
  timeout?: number;
};

export const customPlaybookDir = path.join("ansible", "playbooks", "custom");

/** Browser-authored YAML must not be executable on a production control node. */
export function customPlaybooksEnabled() {
  return process.env.HCP_ENABLE_CUSTOM_AUDITS === "true" && process.env.HCP_PRODUCTION_MODE !== "true";
}

const builtinTitles: Record<string, string> = {
  ping: "Ping",
  collectFacts: "Сбор фактов",
  agentlessAudit: "SSH-аудит Ansible",
  packageInventory: "Инвентарь пакетов",
  collectEvents: "Сбор событий",
  sshCryptoAudit: "SSH crypto-аудит (control node)",
  networkPortScan: "Nmap: top-100 TCP-портов (control node)",
  lynisTemporaryAudit: "Lynis: временный аудит без установки",
};

const builtinVariables: Record<string, PlaybookVariable[]> = {
};

export const playbookTemplates = [
  {
    id: "audit-package",
    title: "Проверить пакет",
    description: "Read-only проверка: установлен ли пакет на хосте и какая версия найдена.",
    kind: "audit" as const,
    variables: [{ name: "package_name", label: "Имя пакета", type: "string" as const, required: true, placeholder: "openssl" }],
    content: `---
- name: Check package installation
  hosts: linux_hosts
  become: true
  gather_facts: true

  tasks:
    - name: Validate package_name
      ansible.builtin.assert:
        that:
          - package_name is defined
          - package_name | length > 0
        fail_msg: "Set package_name."

    - name: Check package on Debian family
      ansible.builtin.command: "dpkg-query -W -f='\${Status} \${Version}\\n' {{ package_name }}"
      changed_when: false
      failed_when: false
      register: deb_package
      when: ansible_os_family == "Debian"

    - name: Check package on RedHat family
      ansible.builtin.command: "rpm -q {{ package_name }}"
      changed_when: false
      failed_when: false
      register: rpm_package
      when: ansible_os_family == "RedHat"

    - name: Show package status
      ansible.builtin.debug:
        msg: "{{ deb_package.stdout | default(rpm_package.stdout | default('package not found')) }}"
`,
  },
];

export function isSafePlaybookId(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_-]{3,64}$/.test(value);
}

export function getCustomPlaybookPath(id: string, repoRoot = getRepoRoot()) {
  return path.join(repoRoot, customPlaybookDir, `${id}.yml`);
}

function getCustomMetaPath(id: string, repoRoot = getRepoRoot()) {
  return path.join(repoRoot, customPlaybookDir, `${id}.meta.json`);
}

function ensureCustomDir(repoRoot = getRepoRoot()) {
  mkdirSync(path.join(repoRoot, customPlaybookDir), { recursive: true });
}

function readCustomMeta(id: string, repoRoot = getRepoRoot()) {
  try {
    return JSON.parse(readFileSync(getCustomMetaPath(id, repoRoot), "utf8")) as PlaybookMeta;
  } catch {
    return null;
  }
}

export function listRegisteredPlaybooks(repoRoot = getRepoRoot()): RegisteredPlaybook[] {
  const builtin = Object.entries(playbooks)
    .filter(([, config]) => config.kind === "audit" && !("internal" in config && config.internal))
    .map(([id, config]) => ({
    id,
    title: builtinTitles[id] ?? id,
    file: path.join("ansible", "playbooks", config.file),
    kind: config.kind,
    source: "builtin" as const,
    requiresLimit: Boolean("requiresLimit" in config && config.requiresLimit),
    timeout: config.timeout,
    variables: builtinVariables[id] ?? [],
    }));

  if (!customPlaybooksEnabled()) {
    return builtin;
  }

  const customDir = path.join(repoRoot, customPlaybookDir);
  const custom = existsSync(customDir)
    ? readdirSync(customDir)
      .filter((fileName) => fileName.endsWith(".meta.json"))
      .map((fileName) => fileName.replace(/\.meta\.json$/, ""))
      .filter(isSafePlaybookId)
      .map((id): RegisteredPlaybook | null => {
        const meta = readCustomMeta(id, repoRoot);
        if (!meta) {
          return null;
        }
        return {
          id,
          title: meta.title,
          file: path.join(customPlaybookDir, `${id}.yml`),
          kind: meta.kind,
          source: "custom" as const,
          requiresLimit: meta.requiresLimit,
          timeout: meta.timeout ?? 600_000,
          variables: Array.isArray(meta.variables) ? meta.variables : [],
        };
      })
      .filter((item): item is RegisteredPlaybook => Boolean(item))
    : [];

  return [...builtin, ...custom];
}

export function getRegisteredPlaybook(id: string, repoRoot = getRepoRoot()) {
  return listRegisteredPlaybooks(repoRoot).find((playbook) => playbook.id === id) ?? null;
}

export function readPlaybookContent(playbook: RegisteredPlaybook, repoRoot = getRepoRoot()) {
  return readFileSync(path.join(repoRoot, playbook.file), "utf8");
}

export function updateCustomPlaybook({
  playbook,
  title,
  kind,
  requiresLimit,
  variables,
  content,
}: {
  playbook: RegisteredPlaybook;
  title: string;
  kind: "audit" | "response";
  requiresLimit: boolean;
  variables: PlaybookVariable[];
  content: string;
}) {
  if (playbook.source !== "custom") {
    throw new Error("Встроенные playbook'и доступны только для чтения.");
  }
  if (kind !== "audit") {
    throw new Error("Пользовательские playbook'и могут выполнять только audit-проверки.");
  }
  if (!content.trim().startsWith("---")) {
    throw new Error("YAML playbook должен начинаться с ---.");
  }

  const repoRoot = getRepoRoot();
  const meta: PlaybookMeta = {
    id: playbook.id,
    title: title.trim() || playbook.title,
    kind,
    requiresLimit,
    variables,
    timeout: playbook.timeout,
  };

  writeFileSync(path.join(repoRoot, playbook.file), content);
  writeFileSync(getCustomMetaPath(playbook.id, repoRoot), JSON.stringify(meta, null, 2));
  return getRegisteredPlaybook(playbook.id, repoRoot)!;
}

export function deleteCustomPlaybook(playbook: RegisteredPlaybook) {
  if (playbook.source !== "custom") {
    throw new Error("Встроенные playbook'и нельзя удалить.");
  }

  const repoRoot = getRepoRoot();
  rmSync(path.join(repoRoot, playbook.file), { force: true });
  rmSync(getCustomMetaPath(playbook.id, repoRoot), { force: true });
}

export function createCustomPlaybook({
  id,
  title,
  templateId,
}: {
  id: string;
  title: string;
  templateId: string;
}) {
  if (!isSafePlaybookId(id)) {
    throw new Error("ID может содержать латиницу, цифры, дефис и подчёркивание, от 3 до 64 символов.");
  }

  const template = playbookTemplates.find((item) => item.id === templateId);
  if (!template) {
    throw new Error("Неизвестный шаблон.");
  }

  const repoRoot = getRepoRoot();
  ensureCustomDir(repoRoot);
  const playbookPath = getCustomPlaybookPath(id, repoRoot);
  const metaPath = getCustomMetaPath(id, repoRoot);
  if (existsSync(playbookPath) || existsSync(metaPath)) {
    throw new Error("Playbook с таким ID уже существует.");
  }

  const meta: PlaybookMeta = {
    id,
    title: title.trim() || template.title,
    kind: "audit",
    requiresLimit: false,
    variables: template.variables,
  };

  writeFileSync(playbookPath, template.content);
  writeFileSync(metaPath, JSON.stringify(meta, null, 2));
  return getRegisteredPlaybook(id, repoRoot)!;
}

export async function syntaxCheckPlaybook(playbook: RegisteredPlaybook) {
  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  const playbookPath = path.join(repoRoot, playbook.file);
  return execFileAsync("ansible-playbook", ["-i", inventoryPath, playbookPath, "--syntax-check"], {
    cwd: repoRoot,
    timeout: 120_000,
    maxBuffer: 1024 * 1024 * 4,
    env: { ...process.env, ANSIBLE_FORCE_COLOR: "false" },
  });
}

export async function runRegisteredPlaybook({
  playbook,
  limit,
  variables,
}: {
  playbook: RegisteredPlaybook;
  limit?: string;
  variables: Record<string, string>;
}) {
  if (playbook.kind !== "audit") {
    throw new Error("Response-playbook'и запускаются только через транзакционный контур remediation.");
  }
  if (playbook.requiresLimit && !limit) {
    throw new Error("Для response-playbook выберите host/group limit.");
  }
  if (limit && !isSafeLimit(limit)) {
    throw new Error("Limit может содержать только имена хостов/групп без пробелов.");
  }

  for (const variable of playbook.variables) {
    const value = variables[variable.name];
    if (variable.required && !value) {
      throw new Error(`Заполните переменную ${variable.name}.`);
    }
  }

  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  const playbookPath = path.join(repoRoot, playbook.file);
  const args = ["-i", inventoryPath, playbookPath];
  for (const variable of playbook.variables) {
    const value = variables[variable.name] || variable.defaultValue;
    if (value) {
      args.push("-e", `${variable.name}=${value}`);
    }
  }
  if (limit) {
    args.push("--limit", limit);
  }

  const result = await execFileAsync("ansible-playbook", args, {
    cwd: repoRoot,
    timeout: playbook.timeout,
    maxBuffer: 1024 * 1024 * 8,
    env: { ...process.env, ANSIBLE_FORCE_COLOR: "false" },
  });

  appendIncident({
    action: playbook.id,
    kind: playbook.kind,
    status: "success",
    profileId: "custom",
    limit: limit || null,
    message: "Playbook выполнен.",
    command: `ansible-playbook ${args.join(" ")}`,
  });

  return { ...result, command: `ansible-playbook ${args.join(" ")}` };
}
