import { existsSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { normalizeSshPort } from "@/lib/ssh-access";

export type InventoryCloseoutHost = { alias: string; address: string; user: string; port: number; credentialId: string | null };

function safeAlias(value: string) {
  return /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value) && !["all", "ungrouped"].includes(value);
}

function parseValues(tokens: string[]) {
  const values = new Map<string, string>();
  for (const token of tokens) {
    const index = token.indexOf("=");
    if (index > 0) values.set(token.slice(0, index), token.slice(index + 1));
  }
  return values;
}

function inventoryPath() {
  return path.join(path.resolve(process.cwd(), ".."), "ansible", "inventory.ini");
}

export function readInventoryCloseoutHost(alias: string): InventoryCloseoutHost | null {
  if (!safeAlias(alias)) return null;
  const pathname = inventoryPath();
  if (!existsSync(pathname)) return null;
  let section = "";
  let found: InventoryCloseoutHost | null = null;
  for (const raw of readFileSync(pathname, "utf8").split("\n")) {
    const line = raw.trim();
    const header = line.match(/^\[(.+)]$/);
    if (header) { section = header[1]; continue; }
    if (!line || line.startsWith("#") || !section || section.endsWith(":vars") || section.endsWith(":children")) continue;
    const [name, ...tokens] = line.split(/\s+/);
    if (name !== alias) continue;
    const values = parseValues(tokens);
    const address = values.get("ansible_host") ?? alias;
    const user = values.get("ansible_user") ?? "";
    const port = normalizeSshPort(values.get("ansible_port")) ?? 22;
    const credentialId = values.get("hcp_ssh_credential_id") ?? null;
    if (!user || !safeAlias(user) || !safeAlias(name)) throw new Error("Строка хоста в inventory имеет некорректные параметры.");
    const value = { alias, address, user, port, credentialId };
    if (found && (found.address !== value.address || found.user !== value.user || found.port !== value.port || found.credentialId !== value.credentialId)) {
      throw new Error("В inventory найдены противоречивые строки этого хоста. Завершение работ остановлено.");
    }
    found = value;
  }
  return found;
}

export function removeInventoryCloseoutHost(alias: string) {
  if (!safeAlias(alias)) throw new Error("Некорректный alias хоста.");
  const pathname = inventoryPath();
  if (!existsSync(pathname)) throw new Error("Файл inventory не найден.");
  let section = "";
  let removed = false;
  const lines = readFileSync(pathname, "utf8").split("\n").filter((raw) => {
    const line = raw.trim();
    const header = line.match(/^\[(.+)]$/);
    if (header) { section = header[1]; return true; }
    if (!line || line.startsWith("#") || !section || section.endsWith(":vars") || section.endsWith(":children")) return true;
    if (line.split(/\s+/)[0] === alias) { removed = true; return false; }
    return true;
  });
  if (!removed) throw new Error("Хост не найден в inventory.");
  const destination = realpathSync(pathname);
  const temporary = `${destination}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n", { mode: 0o600, flag: "wx" });
    renameSync(temporary, destination);
  } finally {
    if (existsSync(temporary)) {
      // A temporary inventory never contains credentials beyond the already
      // persistent path; removal is limited to this exact generated filename.
      try { unlinkSync(temporary); } catch { /* no-op */ }
    }
  }
}
