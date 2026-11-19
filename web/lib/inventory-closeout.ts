import { existsSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { normalizeSshPort } from "@/lib/ssh-access";

export type InventoryCloseoutHost = { alias: string; address: string; user: string; port: number; credentialId: string | null };

function safeAlias(value: string) {
  return /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value) && !["all", "ungrouped"].includes(value);
}

function inventorySection(line: string) {
  return line.match(/^\[([A-Za-z0-9_.-]+(?::(?:vars|children))?)\]\s*(?:[#;].*)?$/)?.[1];
}

function inventoryPath() {
  return path.join(path.resolve(process.cwd(), ".."), "ansible", "inventory.ini");
}

export function readInventoryCloseoutHost(alias: string): InventoryCloseoutHost | null {
  if (!safeAlias(alias)) return null;
  const pathname = inventoryPath();
  if (!existsSync(pathname)) return null;
  let section = "ungrouped";
  let found = false;
  const connection = new Map<string, string>();
  for (const raw of readFileSync(pathname, "utf8").split("\n")) {
    const line = raw.trim();
    const header = inventorySection(line);
    if (header) { section = header; continue; }
    if (!line || /^[#;]/.test(line) || section.endsWith(":vars") || section.endsWith(":children")) continue;
    const [name, ...tokens] = line.split(/\s+/);
    if (name !== alias) continue;
    found = true;
    for (const token of tokens) {
      if (/^[#;]/.test(token)) break;
      const match = token.match(/^(ansible_host|ansible_user|ansible_port|hcp_ssh_credential_id)=(.*)$/);
      if (!match) continue;
      const [, key, value] = match;
      if (connection.has(key) && connection.get(key) !== value) {
        throw new Error("В inventory найдены противоречивые строки этого хоста. Завершение работ остановлено.");
      }
      connection.set(key, value);
    }
  }
  if (!found) return null;
  const user = connection.get("ansible_user") ?? "";
  if (!safeAlias(user)) throw new Error("Строка хоста в inventory имеет некорректные параметры.");
  return {
    alias, user, address: connection.get("ansible_host") ?? alias,
    port: normalizeSshPort(connection.get("ansible_port")) ?? 22,
    credentialId: connection.get("hcp_ssh_credential_id") ?? null,
  };
}

export function removeInventoryCloseoutHost(alias: string) {
  if (!safeAlias(alias)) throw new Error("Некорректный alias хоста.");
  const pathname = inventoryPath();
  if (!existsSync(pathname)) throw new Error("Файл inventory не найден.");
  let section = "ungrouped";
  let removed = false;
  const lines = readFileSync(pathname, "utf8").split("\n").filter((raw) => {
    const line = raw.trim();
    const header = inventorySection(line);
    if (header) { section = header; return true; }
    if (!line || /^[#;]/.test(line) || section.endsWith(":vars") || section.endsWith(":children")) return true;
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
