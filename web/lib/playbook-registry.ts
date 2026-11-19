import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { actionRequiresTargetSudo, appendIncident, beginCustomAuditAssetExecution, endCustomAuditAssetExecution, executeAnsiblePlaybook, getRepoRoot, isSafeLimit, onDemandSudoHostForLimit, playbooks } from "@/lib/ansible-control";
import { getInventoryTargetHosts } from "@/lib/inventory";
import { ansibleLiteralExtraVars } from "@/lib/ansible-literal-vars";
import { auditToolLabels } from "@/lib/audit-tool-labels";

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
  requiresConfirmation?: boolean;
  requiresTargetSudo?: boolean;
};

type PlaybookMeta = Omit<RegisteredPlaybook, "source" | "file" | "timeout"> & {
  file?: string;
  timeout?: number;
  revision?: string;
  validation?: PlaybookValidation;
};

export type PlaybookValidation = {
  revision?: string;
  syntaxAt?: string;
  trial?: { at: string; host: string };
};

export const customPlaybookDir = path.join("ansible", "playbooks", "custom");
const customPlaybookStateDirectory = "custom-playbooks";

export type CustomPlaybookCapabilities = {
  authoringEnabled: boolean;
  executionEnabled: boolean;
  productionLocked: boolean;
  reason: string;
};

/** Browser-authored YAML may be drafted explicitly, but never executed on a production control node. */
export function customPlaybookCapabilities(): CustomPlaybookCapabilities {
  const authoringEnabled = process.env.HCP_ENABLE_CUSTOM_AUDITS === "true";
  const productionLocked = process.env.HCP_PRODUCTION_MODE === "true";
  if (!authoringEnabled) {
    return {
      authoringEnabled: false,
      executionEnabled: false,
      productionLocked,
      reason: "Черновики пользовательских сценариев выключены. Включите HCP_ENABLE_CUSTOM_AUDITS=true только в контролируемом контуре.",
    };
  }
  if (productionLocked) {
    return {
      authoringEnabled: true,
      executionEnabled: false,
      productionLocked: true,
      reason: "Сценарий из шаблона «Проверить пакет» можно запустить на выбранном хосте. Изменённый YAML проверяется в тестовом экземпляре.",
    };
  }
  return {
    authoringEnabled: true,
    executionEnabled: true,
    productionLocked: false,
    reason: "Режим тестового контура включён. Перед запуском ограничьте цель конкретным хостом или группой.",
  };
}

export function customPlaybookAuthoringEnabled() {
  return customPlaybookCapabilities().authoringEnabled;
}

/** Browser-authored YAML must not be executable on a production control node. */
export function customPlaybooksEnabled() {
  return customPlaybookCapabilities().executionEnabled;
}

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
  gather_facts: false

  tasks:
    - name: Validate package_name
      ansible.builtin.assert:
        that:
          - package_name is defined
          - package_name | length > 0
          - package_name is match('^[A-Za-z0-9][A-Za-z0-9+_.:-]*$')
        fail_msg: "Set package_name."

    - name: Find dpkg-query
      ansible.builtin.stat:
        path: /usr/bin/dpkg-query
        follow: true
      register: query_dpkg

    - name: Find rpm
      ansible.builtin.stat:
        path: /usr/bin/rpm
        follow: true
      register: query_rpm

    - name: Require a supported package tool
      ansible.builtin.assert:
        that:
          - (query_dpkg.stat.executable | default(false)) or (query_rpm.stat.executable | default(false))
        fail_msg: "Не найден dpkg-query или rpm; проверка пакета не выполнена."

    - name: Check package with dpkg-query
      ansible.builtin.command:
        argv:
          - /usr/bin/dpkg-query
          - -W
          - '-f=\${Status} \${Version}'
          - "{{ package_name }}"
      changed_when: false
      failed_when: deb_package.rc not in [0, 1]
      register: deb_package
      when: query_dpkg.stat.executable | default(false)

    - name: Check package with rpm
      ansible.builtin.command:
        argv:
          - /usr/bin/rpm
          - -q
          - "{{ package_name }}"
      changed_when: false
      failed_when: rpm_package.rc not in [0, 1]
      register: rpm_package
      when: not (query_dpkg.stat.executable | default(false)) and (query_rpm.stat.executable | default(false))

    - name: Show package status
      ansible.builtin.debug:
        msg: "{{ (deb_package.stdout | default('', true)) or (rpm_package.stdout | default('', true)) or 'Пакет не установлен' }}"
`,
  },
];

const managedPackageContent = playbookTemplates[0].content.replace("become: true", "become: false");

export type CustomPlaybookMode = "draft" | "test" | "package";

export function customPlaybookMode(playbook: RegisteredPlaybook, content?: string): CustomPlaybookMode {
  if (playbook.source !== "custom" || playbook.kind !== "audit" || !customPlaybookAuthoringEnabled()) return "draft";
  if (customPlaybooksEnabled()) return "test";
  if (playbook.variables.length !== 1 || playbook.variables[0].name !== "package_name" || playbook.variables[0].type !== "string") return "draft";
  if (content === undefined && !existsSync(registeredPlaybookPath(playbook))) return "draft";
  const yaml = (content ?? readPlaybookContent(playbook)).trim();
  return yaml === managedPackageContent.trim() || yaml === playbookTemplates[0].content.trim() ? "package" : "draft";
}

async function withPackageTemplate<T>(run: (file: string) => Promise<T>) {
  // Use fixed code even if someone saves a different YAML while a run is starting.
  const directory = mkdtempSync(path.join(tmpdir(), "hcp-package-check-"));
  try {
    const file = path.join(directory, "check-package.yml");
    writeFileSync(file, managedPackageContent, { mode: 0o600 });
    return await run(file);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function isSafePlaybookId(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_-]{3,64}$/.test(value);
}

export function getCustomPlaybookPath(id: string, repoRoot = getRepoRoot()) {
  return path.join(customPlaybookStorageDir(repoRoot), `${id}.yml`);
}

function getCustomMetaPath(id: string, repoRoot = getRepoRoot()) {
  return path.join(customPlaybookStorageDir(repoRoot), `${id}.meta.json`);
}

function ensureCustomDir(repoRoot = getRepoRoot()) {
  mkdirSync(customPlaybookStorageDir(repoRoot), { recursive: true });
}

/**
 * Container images are replaceable. Keep browser-authored drafts under the
 * durable HCP state volume; local source checkout remains a development fallback.
 */
function customPlaybookStorageDir(repoRoot = getRepoRoot()) {
  const stateDirectory = process.env.HCP_STATE_DIR?.trim();
  return stateDirectory ? path.join(stateDirectory, customPlaybookStateDirectory) : path.join(repoRoot, customPlaybookDir);
}

function customPlaybookDisplayPath(id: string) {
  return process.env.HCP_STATE_DIR?.trim()
    ? path.join("HCP state", customPlaybookStateDirectory, `${id}.yml`)
    : path.join(customPlaybookDir, `${id}.yml`);
}

function registeredPlaybookPath(playbook: RegisteredPlaybook, repoRoot = getRepoRoot()) {
  return playbook.source === "custom" ? getCustomPlaybookPath(playbook.id, repoRoot) : path.join(repoRoot, playbook.file);
}

function readCustomMeta(id: string, repoRoot = getRepoRoot()) {
  try {
    return JSON.parse(readFileSync(getCustomMetaPath(id, repoRoot), "utf8")) as PlaybookMeta;
  } catch {
    return null;
  }
}

function writeCustomMeta(meta: PlaybookMeta, repoRoot = getRepoRoot()) {
  const file = getCustomMetaPath(meta.id, repoRoot);
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, JSON.stringify(meta, null, 2), { flag: "wx", mode: 0o600 });
    renameSync(temporary, file);
  } finally {
    rmSync(temporary, { force: true });
  }
}

export function listRegisteredPlaybooks(repoRoot = getRepoRoot()): RegisteredPlaybook[] {
  const builtin = Object.entries(playbooks)
    .filter(([, config]) => config.kind === "audit" && !("internal" in config && config.internal))
    .map(([id, config]) => ({
    id,
    title: auditToolLabels[id] ?? id,
    file: path.join("ansible", "playbooks", config.file),
    kind: config.kind,
    source: "builtin" as const,
    requiresLimit: Boolean("requiresLimit" in config && config.requiresLimit),
    timeout: config.timeout,
    variables: builtinVariables[id] ?? [],
    requiresConfirmation: Boolean("requiresConfirmation" in config && config.requiresConfirmation),
    requiresTargetSudo: actionRequiresTargetSudo(id as keyof typeof playbooks),
    }));

  if (!customPlaybookAuthoringEnabled()) {
    return builtin;
  }

  const customDir = customPlaybookStorageDir(repoRoot);
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
          file: customPlaybookDisplayPath(id),
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
  return readFileSync(registeredPlaybookPath(playbook, repoRoot), "utf8");
}

function playbookRevision(playbook: RegisteredPlaybook, meta: PlaybookMeta) {
  return createHash("sha256").update(JSON.stringify([
    meta.revision, meta.kind, meta.requiresLimit, meta.variables, readPlaybookContent(playbook),
  ])).digest("hex");
}

export function getCustomPlaybookValidation(playbook: RegisteredPlaybook): PlaybookValidation {
  if (playbook.source !== "custom") return {};
  const meta = readCustomMeta(playbook.id);
  if (!meta) return {};
  const revision = playbookRevision(playbook, meta);
  return meta.validation?.revision === revision ? meta.validation : { revision };
}

function recordPlaybookValidation(playbook: RegisteredPlaybook, revision: string | undefined, result: PlaybookValidation) {
  if (!revision) return;
  const meta = readCustomMeta(playbook.id);
  if (!meta || !existsSync(registeredPlaybookPath(playbook)) || playbookRevision(playbook, meta) !== revision) return;
  const previous = meta.validation?.revision === revision ? meta.validation : {};
  writeCustomMeta({
    ...meta, validation: { ...previous, ...result, revision },
  });
}

function validateVariables(variables: PlaybookVariable[]) {
  if (!Array.isArray(variables) || variables.length > 50) throw new Error("Укажите не более 50 переменных.");
  const names = new Set<string>();
  for (const variable of variables) {
    if (!variable || typeof variable !== "object" || typeof variable.name !== "string"
      || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(variable.name) || /^(?:ansible_|hcp_)/.test(variable.name)
      || names.has(variable.name) || typeof variable.label !== "string" || !variable.label.trim() || variable.label.length > 160
      || !["string", "number"].includes(variable.type) || (variable.required !== undefined && typeof variable.required !== "boolean")
      || [variable.defaultValue, variable.placeholder].some((value) => value !== undefined && (typeof value !== "string" || value.length > 4096))) {
      throw new Error("Проверьте переменные: нужны уникальное допустимое имя, название и тип string или number; системные имена ansible_ и hcp_ запрещены.");
    }
    if (variable.type === "number" && variable.defaultValue && !Number.isFinite(Number(variable.defaultValue))) throw new Error("Значение числовой переменной по умолчанию должно быть числом.");
    names.add(variable.name);
  }
  return variables;
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
  const repoRoot = getRepoRoot();
  const meta: PlaybookMeta = {
    id: playbook.id,
    title: title.trim() || playbook.title,
    kind,
    requiresLimit,
    variables: validateVariables(variables),
    timeout: playbook.timeout,
    revision: randomUUID(),
  };

  writeFileSync(registeredPlaybookPath(playbook, repoRoot), content);
  writeCustomMeta(meta, repoRoot);
  return getRegisteredPlaybook(playbook.id, repoRoot)!;
}

export function deleteCustomPlaybook(playbook: RegisteredPlaybook) {
  if (playbook.source !== "custom") {
    throw new Error("Встроенные playbook'и нельзя удалить.");
  }

  const repoRoot = getRepoRoot();
  rmSync(registeredPlaybookPath(playbook, repoRoot), { force: true });
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
  if (Object.hasOwn(playbooks, id)) throw new Error("Этот ID занят встроенным сценарием.");

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
    requiresLimit: true,
    variables: template.variables,
    revision: randomUUID(),
  };

  writeFileSync(playbookPath, template.id === "audit-package" && !customPlaybooksEnabled() ? managedPackageContent : template.content);
  writeCustomMeta(meta, repoRoot);
  return getRegisteredPlaybook(id, repoRoot)!;
}

export async function syntaxCheckPlaybook(playbook: RegisteredPlaybook) {
  const mode = customPlaybookMode(playbook);
  if (playbook.source === "custom" && mode === "draft") {
    throw new Error("Проверка пользовательского YAML доступна только в тестовом контуре.");
  }
  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  const { revision } = getCustomPlaybookValidation(playbook);
  const check = (file: string) => execFileAsync("ansible-playbook", ["-i", inventoryPath, file, "--syntax-check"], {
    cwd: repoRoot,
    timeout: 120_000,
    maxBuffer: 1024 * 1024 * 4,
    env: { ...process.env, ANSIBLE_FORCE_COLOR: "false", ANSIBLE_PIPELINING: "False" },
  });
  const result = await (mode === "package" ? withPackageTemplate(check) : check(registeredPlaybookPath(playbook, repoRoot)));
  recordPlaybookValidation(playbook, revision, { syntaxAt: new Date().toISOString() });
  return result;
}

export async function runRegisteredPlaybook({
  playbook,
  limit,
  variables,
  becomePassword,
}: {
  playbook: RegisteredPlaybook;
  limit?: string;
  variables: Record<string, string>;
  becomePassword?: string;
}) {
  if (playbook.source === "builtin") {
    throw new Error("Встроенные проверки запускаются через /api/ansible/run с подтверждением и проверкой целей.");
  }
  if (playbook.kind !== "audit") {
    throw new Error("Response-playbook'и запускаются только через транзакционный контур remediation.");
  }
  const mode = customPlaybookMode(playbook);
  if (mode === "draft") throw new Error("Этот YAML можно запустить только в тестовом контуре (production режим).");
  if (!limit) {
    throw new Error("Для пользовательского сценария выберите конкретный host/group limit.");
  }
  if (limit && !isSafeLimit(limit)) {
    throw new Error("Limit может содержать только имена хостов/групп без пробелов.");
  }
  const targets = getInventoryTargetHosts(limit);
  if (!targets.some((host) => host.groups.includes("linux_hosts"))) {
    throw new Error("В выбранной цели нет подключённых хостов группы linux_hosts.");
  }
  if (mode === "package") {
    if (targets.length !== 1 || targets[0].alias !== limit) throw new Error("Выберите один конкретный хост.");
    if (becomePassword) throw new Error("Проверка пакета выполняется без sudo.");
    const packageName = variables.package_name ?? playbook.variables[0].defaultValue;
    if (typeof packageName !== "string" || !/^[A-Za-z0-9][A-Za-z0-9+_.:-]{0,127}$/.test(packageName)) {
      throw new Error("Укажите допустимое имя пакета.");
    }
  } else if (onDemandSudoHostForLimit(limit) && !becomePassword) {
    throw new Error("Введите пароль sudo для этой операции. HCP не сохраняет его.");
  }

  for (const variable of playbook.variables) {
    const value = variables[variable.name] ?? variable.defaultValue;
    if (variable.required && !value) {
      throw new Error(`Заполните переменную ${variable.name}.`);
    }
  }

  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  const playbookPath = registeredPlaybookPath(playbook, repoRoot);
  const args = ["-i", inventoryPath, playbookPath];
  const extraVars: Record<string, string | boolean> = {};
  for (const variable of playbook.variables) {
    const value = variables[variable.name] ?? variable.defaultValue;
    if (value) {
      if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(variable.name) || /^(?:ansible_|hcp_)/.test(variable.name)) {
        throw new Error("Недопустимое имя переменной пользовательского playbook.");
      }
      if (typeof value !== "string" || value.length > 4096) {
        throw new Error(`Значение ${variable.name} должно быть строкой не длиннее 4096 символов.`);
      }
      if (variable.type === "number" && !Number.isFinite(Number(value))) throw new Error(`Значение ${variable.name} должно быть числом.`);
      extraVars[variable.name] = value;
    }
  }
  if (mode === "package") extraVars.ansible_become = false;
  // JSON protects key boundaries; unsafe strings also prevent Jinja execution.
  if (Object.keys(extraVars).length) args.push("-e", ansibleLiteralExtraVars(extraVars));
  if (limit) {
    args.push("--limit", limit);
  }

  let result;
  let assetLease: Awaited<ReturnType<typeof beginCustomAuditAssetExecution>> | null = null;
  const { revision } = getCustomPlaybookValidation(playbook);
  try {
    assetLease = await beginCustomAuditAssetExecution(limit);
    if (mode === "package" && (assetLease.bindings.size !== 1 || !assetLease.bindings.has(limit))) {
      throw new Error("Цель изменилась при подготовке. Выберите хост заново.");
    }
    args[1] = assetLease.inventoryPath;
    const { sshTrust, ansibleRuntime } = assetLease;
    const execute = (file: string) => {
      args[2] = file;
      return executeAnsiblePlaybook({ args, timeout: playbook.timeout, becomePassword, sshTrust, ansibleRuntime });
    };
    result = await (mode === "package" ? withPackageTemplate(execute) : execute(playbookPath));
    const [, recap = ""] = result.stdout.split(/^PLAY RECAP\s+\*+\s*$/m);
    const completed = recap.match(/^([\w.-]+)\s+:\s+ok=[1-9]\d*\s+changed=\d+\s+unreachable=0\s+failed=0\b/m)?.[1];
    if (mode === "package" && completed !== limit) throw new Error("Проверка пакета не завершилась на выбранном хосте.");
    if (/skipping: no hosts matched/i.test(result.stdout) && !/\s+ok=\d+\s+changed=\d+/.test(result.stdout)) throw new Error("Сценарий не выполнил задачи: его hosts не совпадает с выбранной целью.");
    if (completed === limit) recordPlaybookValidation(playbook, revision, { trial: { at: new Date().toISOString(), host: limit } });
  } catch (error) {
    appendIncident({ action: playbook.id, kind: playbook.kind, status: "failed", profileId: "custom", limit, message: error instanceof Error ? error.message : "Сценарий завершился ошибкой." });
    throw error;
  } finally {
    if (assetLease) endCustomAuditAssetExecution(assetLease);
  }

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
