import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

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
