import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import os from "node:os";
import { createHash } from "node:crypto";
import path from "node:path";
import { configuredPrivateKeyPath, isSafeSshHostAddress } from "@/lib/ssh-access";
import { assetConnectionId } from "@/lib/asset-binding";

export type InventoryHost = { alias: string; groups: string[] };
export type StaticInventory = { hosts: InventoryHost[]; groups: string[] };

/** Membership only: connection variables are resolved by ansible-inventory. */
export function parseStaticInventory(text: string): StaticInventory {
  const direct = new Map<string, Set<string>>();
  const parents = new Map<string, Set<string>>();
  const known = new Set<string>(["all", "ungrouped"]);
  let group = "ungrouped";
  let section = "hosts";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || /^[#;]/.test(line)) continue;
    const header = line.match(/^\[([A-Za-z0-9_.-]+)(?::(vars|children))?\]\s*(?:[#;].*)?$/);
    if (header) {
      group = header[1];
      section = header[2] ?? "hosts";
      known.add(group);
      continue;
    }
    if (line.startsWith("[")) throw new Error("Неподдерживаемый заголовок inventory. Используйте статические INI-группы.");
    if (section === "vars") continue;
    const token = line.split(/\s+/, 1)[0];
    if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(token)) {
      throw new Error("Для запуска через HCP используйте явные alias в inventory без диапазонов и портов в имени; задавайте порт через ansible_port.");
    }
    if (section === "children") {
      known.add(token);
      const values = parents.get(token) ?? new Set<string>();
      values.add(group);
      parents.set(token, values);
    } else {
      const values = direct.get(token) ?? new Set<string>();
      values.add(group);
      direct.set(token, values);
    }
  }

  function ancestors(groupName: string, visiting = new Set<string>()): Set<string> {
    if (visiting.has(groupName)) throw new Error(`Циклическое наследование inventory-группы ${groupName}.`);
    const result = new Set<string>([groupName]);
    const next = new Set(visiting).add(groupName);
    for (const parent of parents.get(groupName) ?? []) {
      for (const ancestor of ancestors(parent, next)) result.add(ancestor);
    }
    return result;
  }
  for (const name of known) ancestors(name);
  const hosts = [...direct].map(([alias, groups]) => {
    const membership = new Set<string>(["all"]);
    for (const name of groups) for (const ancestor of ancestors(name)) membership.add(ancestor);
    if ([...membership].some((name) => name !== "all" && name !== "ungrouped")) membership.delete("ungrouped");
    return { alias, groups: [...membership].sort() };
  });
  return { hosts: hosts.sort((a, b) => a.alias.localeCompare(b.alias)), groups: [...known].sort() };
}

export function readStaticInventory(): StaticInventory {
  const file = path.resolve(process.cwd(), "..", "ansible", "inventory.ini");
  if (!existsSync(file)) throw new Error("Создайте ansible/inventory.ini из ansible/inventory.example.ini.");
  return parseStaticInventory(readFileSync(file, "utf8"));
}

export function getInventoryHost(alias: string, inventory = readStaticInventory()) {
  // Ansible treats a name shared by a host and group as a group limit as well.
  if (inventory.groups.includes(alias)) return null;
  return inventory.hosts.find((host) => host.alias === alias) ?? null;
}

export function getInventoryTargetHosts(target: string, inventory = readStaticInventory()) {
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(target)) throw new Error("Укажите один точный alias хоста или имя inventory-группы.");
  if (inventory.groups.includes(target) && inventory.hosts.some((host) => host.alias === target)) {
    throw new Error(`Имя ${target} совпадает с хостом и группой; переименуйте один из них.`);
  }
  return inventory.hosts.filter((host) => host.alias === target || host.groups.includes(target));
}

const managedPrivateKeyExpression = "{{ ((lookup('env', 'HCP_STATE_DIR') | default(inventory_dir, true)) ~ '/ssh-host-keys/' ~ hcp_ssh_credential_id ~ '/id_ed25519') if hcp_ssh_credential_id is defined else (lookup('env', 'HCP_SSH_PRIVATE_KEY_PATH') | default(lookup('env', 'HOME') ~ '/.ssh/hcp-control', true)) }}";
export function resolvedInventoryVariables(alias: string, inventoryPath = path.resolve(process.cwd(), "..", "ansible", "inventory.ini")) {
  const output = execFileSync("ansible-inventory", ["-i", inventoryPath, "--host", alias, "--playbook-dir", path.resolve(process.cwd(), "..", "ansible")], {
    cwd: path.resolve(process.cwd(), ".."), encoding: "utf8", timeout: 15_000, maxBuffer: 1024 * 1024,
    env: { ...process.env, ANSIBLE_FORCE_COLOR: "false" },
  });
  const variables = JSON.parse(output);
  if (!variables || typeof variables !== "object" || Array.isArray(variables)) throw new Error("Inventory не вернул переменные хоста.");
  return variables as Record<string, unknown>;
}

export function connectionFromInventoryVariables(alias: string, variables: Record<string, unknown>) {
  const address = variables.ansible_host ?? variables.ansible_ssh_host ?? alias;
  const port = Number(variables.ansible_port ?? variables.ansible_ssh_port ?? 22);
  if (!isSafeSshHostAddress(address) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Не удалось однозначно определить адрес и порт SSH из inventory.");
  const credentialId = typeof variables.hcp_ssh_credential_id === "string" && /^[a-f0-9]{64}$/.test(variables.hcp_ssh_credential_id) ? variables.hcp_ssh_credential_id : undefined;
  let privateKey = variables.ansible_ssh_private_key_file ?? variables.ansible_private_key_file;
  // Evaluate only the repository's fixed managed-key choice in ordinary TS;
  // never execute a user-supplied Jinja expression to resolve a key path.
  if (privateKey === managedPrivateKeyExpression) privateKey = undefined;
  if (privateKey != null && (typeof privateKey !== "string" || /\{[{%#]|\0/.test(privateKey))) throw new Error("Неподдерживаемый шаблон приватного SSH-ключа. Укажите явный путь или управляемый ключ HCP.");
  const rawKey = typeof privateKey === "string" ? privateKey : configuredPrivateKeyPath();
  const privateKeyPath = path.resolve(path.resolve(process.cwd(), ".."), rawKey.startsWith("~/") ? path.join(os.homedir(), rawKey.slice(2)) : rawKey);
  return { address, port, user: typeof (variables.ansible_user ?? variables.ansible_ssh_user) === "string" ? String(variables.ansible_user ?? variables.ansible_ssh_user) : undefined, credentialId,
    privateKeyPath, ...(typeof variables.ansible_connection === "string" ? { transport: variables.ansible_connection } : {}) };
}

/** Resolve every target from one private INI snapshot before any network await. */
export function freezeInventoryTargets(limit = "linux_hosts") {
  const source = path.resolve(process.cwd(), "..", "ansible", "inventory.ini");
  const bytes = readFileSync(source);
  if (bytes.length > 4 * 1024 * 1024) throw new Error("Inventory превышает допустимые 4 МиБ.");
  const inventory = parseStaticInventory(bytes.toString("utf8"));
  const targets = [...new Map(limit.split(",").flatMap((target) => getInventoryTargetHosts(target, inventory))
    .filter((host) => host.groups.includes("linux_hosts")).map((host) => [host.alias, host])).values()];
  if (!targets.length || targets.length > 256) throw new Error("Выберите от 1 до 256 хостов группы linux_hosts.");
  const directory = mkdtempSync(path.join(os.tmpdir(), "hcp-execution-inventory-"));
  chmodSync(directory, 0o700);
  try {
    const sourcePath = path.join(directory, "source.ini");
    writeFileSync(sourcePath, bytes, { mode: 0o600 });
    const resolved = targets.map((host) => {
      const variables = resolvedInventoryVariables(host.alias, sourcePath);
      return { ...host, variables, connection: connectionFromInventoryVariables(host.alias, variables) };
    });
    return { directory, targets: resolved, inventoryPath: path.join(directory, "inventory.json") };
  } catch (error) { rmSync(directory, { recursive: true, force: true }); throw error; }
}

const connectionViewCache = new Map<string, { expiresAt: number; value: string }>();
/** The view cache must follow effective Ansible precedence, including host_vars
 * overriding an inline address. Hash bounded variable files so an edit cannot
 * retain a previously verified endpoint until the time-based cache expires. */
function connectionConfigurationSignature(file: string, bytes: Buffer) {
  const hash = createHash("sha256").update(bytes);
  let entries = 0; let total = bytes.length;
  const visit = (entry: string, depth = 0) => {
    if (++entries > 512 || depth > 5) throw new Error("Inventory variable files exceed the bounded view resolver");
    const stat = lstatSync(entry);
    hash.update(entry);
    if (stat.isDirectory()) {
      for (const name of readdirSync(entry).sort()) visit(path.join(entry, name), depth + 1);
    } else {
      if (!stat.isFile() || (total += stat.size) > 4 * 1024 * 1024) throw new Error("Unsupported inventory variable file");
      hash.update(readFileSync(entry));
    }
  };
  for (const name of ["group_vars", "host_vars"]) {
    const directory = path.join(path.dirname(file), name);
    if (existsSync(directory)) visit(directory);
  }
  return hash.digest("hex");
}

/** Bounded effective lookup; an unresolved configuration never means "same
 * machine". A missing inventory still permits a historical/offline view. */
export function explicitInventoryConnectionId(alias: string): string | null {
  const file = path.resolve(process.cwd(), "..", "ansible", "inventory.ini");
  if (!existsSync(file)) return null;
  try {
    const bytes = readFileSync(file);
    if (bytes.length > 4 * 1024 * 1024 || !getInventoryHost(alias, parseStaticInventory(bytes.toString("utf8")))) return "unresolved";
    const key = `${file}:${alias}:${connectionConfigurationSignature(file, bytes)}`;
    const cached = connectionViewCache.get(key);
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    let value = "unresolved";
    try {
      const connection = connectionFromInventoryVariables(alias, resolvedInventoryVariables(alias, file));
      if (connection.user) value = assetConnectionId(connection);
    } catch { /* Unknown configuration is a visible coverage gap, not trust. */ }
    if (connectionViewCache.size > 128) connectionViewCache.clear();
    connectionViewCache.set(key, { expiresAt: Date.now() + 5_000, value });
    return value;
  } catch { return "unresolved"; }
}
