import { existsSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { NextResponse } from "next/server";
import { getReportsDir, listAnsibleReports } from "@/lib/ansible-reports";
import { isSafeSshHostAddress, normalizeSshPort } from "@/lib/ssh-access";
import { HostCredentialError, credentialKeyPath, publicCredentialSummary, validateHostCredential } from "@/lib/host-credentials";
import { hasActiveRemediationForHost } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

type InventoryHost = {
  alias: string;
  address: string;
  user: string | null;
  port: number;
  become: boolean | null;
  groups: string[];
  raw: string;
  credentialId: string | null;
  lastReport: HostReport | null;
  reportCount: number;
};

type HostReport = {
  path: string;
  fileName: string;
  createdAt: string | null;
  profileId: string | null;
  mode: string;
  score: number | null;
  high: number;
  medium: number;
  low: number;
  info: number;
};

function getRepoRoot() {
  return path.resolve(process.cwd(), "..");
}

function isSafeAlias(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value) && !["all", "ungrouped"].includes(value);
}

function isSafeSshUser(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value);
}

function isSafeHostAddress(value: unknown): value is string {
  return isSafeSshHostAddress(value);
}

function isSafeGroup(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/.test(value) && !["all", "ungrouped"].includes(value);
}

function normalizePort(value: unknown) {
  return normalizeSshPort(value);
}

function ensureInventory(repoRoot: string) {
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  if (!existsSync(inventoryPath)) {
    const examplePath = path.join(repoRoot, "ansible", "inventory.example.ini");
    const content = existsSync(examplePath)
      ? readFileSync(examplePath, "utf8")
      : "[linux_hosts]\n\n[linux_hosts:vars]\nansible_python_interpreter=/usr/bin/python3\naudit_profile=basic_linux\n";
    writeFileSync(inventoryPath, content);
  }
  return inventoryPath;
}

function parseKeyValueTokens(tokens: string[]) {
  const values = new Map<string, string>();
  for (const token of tokens) {
    const separatorIndex = token.indexOf("=");
    if (separatorIndex <= 0) {
      continue;
    }
    values.set(token.slice(0, separatorIndex), token.slice(separatorIndex + 1));
  }
  return values;
}

function parseBoolean(value: string | undefined) {
  if (!value) {
    return null;
  }
  if (["true", "yes", "1"].includes(value.toLowerCase())) {
    return true;
  }
  if (["false", "no", "0"].includes(value.toLowerCase())) {
    return false;
  }
  return null;
}

function readInventoryHosts(inventoryPath: string) {
  if (!existsSync(inventoryPath)) {
    return [];
  }

  const hosts: InventoryHost[] = [];
  let currentGroup = "";
  for (const rawLine of readFileSync(inventoryPath, "utf8").split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const groupMatch = line.match(/^\[(.+)]$/);
    if (groupMatch) {
      currentGroup = groupMatch[1];
      continue;
    }

    if (!currentGroup || currentGroup.endsWith(":vars") || currentGroup.endsWith(":children")) {
      continue;
    }

    const [alias, ...tokens] = line.split(/\s+/);
    const values = parseKeyValueTokens(tokens);
    const address = values.get("ansible_host") ?? alias;
    const existing = hosts.find((host) => host.alias === alias);
    if (existing) {
      if (values.has("ansible_host")) existing.address = address;
      if (values.has("ansible_user")) existing.user = values.get("ansible_user") ?? null;
      if (values.has("hcp_ssh_credential_id")) existing.credentialId = values.get("hcp_ssh_credential_id") ?? null;
      if (values.has("ansible_port")) existing.port = normalizePort(values.get("ansible_port")) ?? 22;
      if (values.has("ansible_become")) existing.become = parseBoolean(values.get("ansible_become"));
      if (!existing.groups.includes(currentGroup)) existing.groups.push(currentGroup);
      continue;
    }
    hosts.push({
      alias,
      address,
      user: values.get("ansible_user") ?? null,
      port: normalizePort(values.get("ansible_port")) ?? 22,
      become: parseBoolean(values.get("ansible_become")),
      groups: [currentGroup],
      raw: line,
      credentialId: values.get("hcp_ssh_credential_id") ?? null,
      lastReport: null,
      reportCount: 0,
    });
  }

  return hosts;
}

function hostLine({
  alias,
  address,
  port,
  user,
  become,
  credentialId,
}: {
  alias: string;
  address: string;
  port: number;
  user: string;
  become: boolean;
  credentialId: string | null;
}) {
  return `${alias} ansible_host=${address} ansible_port=${port} ansible_user=${user} ansible_become=${become ? "true" : "false"}${credentialId ? ` hcp_ssh_credential_id=${credentialId} ansible_ssh_private_key_file=${JSON.stringify(credentialKeyPath(credentialId))}` : ""}`;
}

function removeHostLine(lines: string[], alias: string) {
  let currentGroup = "";
  let removed = false;
  const next = lines.filter((rawLine) => {
    const line = rawLine.trim();
    const groupMatch = line.match(/^\[(.+)]$/);
    if (groupMatch) {
      currentGroup = groupMatch[1];
      return true;
    }
    if (!line || line.startsWith("#") || currentGroup.endsWith(":vars") || currentGroup.endsWith(":children")) {
      return true;
    }
    const [currentAlias] = line.split(/\s+/);
    if (currentAlias === alias) {
      removed = true;
      return false;
    }
    return true;
  });
  return { lines: next, removed };
}

function insertHostLine(lines: string[], group: string, line: string) {
  const varsIndex = lines.findIndex((item) => item.trim() === "[linux_hosts:vars]");
  const groupHeader = `[${group}]`;
  const hostsIndex = lines.findIndex((item) => item.trim() === groupHeader);

  if (hostsIndex === -1) {
    const insertIndex = varsIndex === -1 ? lines.length : varsIndex;
    lines.splice(insertIndex, 0, "", groupHeader, line);
  } else {
    // Insert in this group's section, never before an unrelated later :vars.
    lines.splice(hostsIndex + 1, 0, line);
  }

  if (group !== "linux_hosts") {
    const childrenHeaderIndex = lines.findIndex((item) => item.trim() === "[linux_hosts:children]");
    if (childrenHeaderIndex === -1) {
      const nextVarsIndex = lines.findIndex((item) => item.trim() === "[linux_hosts:vars]");
      const insertIndex = nextVarsIndex === -1 ? lines.length : nextVarsIndex;
      lines.splice(insertIndex, 0, "", "[linux_hosts:children]", group);
    } else {
      let index = childrenHeaderIndex + 1;
      let groupAlreadyListed = false;
      while (index < lines.length && !lines[index].trim().startsWith("[")) {
        if (lines[index].trim() === group) {
          groupAlreadyListed = true;
          break;
        }
        index += 1;
      }
      if (!groupAlreadyListed) {
        lines.splice(childrenHeaderIndex + 1, 0, group);
      }
    }
  }

  return lines;
}

function normalizeInventoryText(lines: string[]) {
  return lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
}

function saveInventory(inventoryPath: string, lines: string[]) {
  // Deployment may link inventory.ini into the persistent state volume.
  const destination = existsSync(inventoryPath) ? realpathSync(inventoryPath) : inventoryPath;
  const temporaryPath = `${destination}.${randomUUID()}.tmp`;
  writeFileSync(temporaryPath, normalizeInventoryText(lines), { mode: 0o600 });
  renameSync(temporaryPath, destination);
}

function identityCollides(current: string, alias: string, group: string) {
  const groups = new Set(Array.from(current.matchAll(/^\[([^\]:]+)(?::(?:vars|children))?\]\s*$/gm), (match) => match[1]));
  let section = "";
  const hostAliases = current.split("\n").flatMap((raw) => {
    const line = raw.trim();
    if (line.startsWith("[")) { section = line; return []; }
    return !line || line.startsWith("#") || section.includes(":") ? [] : [line.split(/\s+/)[0]];
  });
  return alias === group || groups.has(alias) || hostAliases.includes(group);
}

function attachReports(hosts: InventoryHost[], reportsPath: string) {
  if (!existsSync(reportsPath)) {
    return hosts;
  }

  const reports = listAnsibleReports();

  return hosts.map((host) => {
    const hostReports = reports.filter((report) => (report.inventoryHost ?? report.host) === host.alias);
    // The host score is a hardening score. Package CVE and event reports have
    // different semantics and must not replace it merely because they are newer.
    const reportFile = hostReports.find((report) => report.mode === "agentless");
    return {
      ...host,
      lastReport: reportFile ?? null,
      reportCount: hostReports.length,
    };
  });
}

export async function GET() {
  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  const reportsPath = getReportsDir(repoRoot);
  const hosts = attachReports(readInventoryHosts(inventoryPath), reportsPath).map((host) => ({ ...host, ...publicCredentialSummary(host.credentialId) }));

  const withReports = hosts.filter((host) => host.lastReport).length;
  const becomeEnabled = hosts.filter((host) => host.become).length;
  const scores = hosts
    .map((host) => host.lastReport?.score)
    .filter((score): score is number => typeof score === "number");
  const averageScore = scores.length
    ? Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length)
    : null;

  return NextResponse.json({
    ok: true,
    inventoryReady: existsSync(inventoryPath),
    inventoryPath,
    reportsPath,
    hosts,
    summary: {
      total: hosts.length,
      withReports,
      withoutReports: hosts.length - withReports,
      becomeEnabled,
      averageScore,
    },
  });
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alias = typeof body?.alias === "string" ? body.alias.trim() : "";
  const address = typeof body?.address === "string" ? body.address.trim() : "";
  const user = typeof body?.user === "string" ? body.user.trim() : "";
  const become = typeof body?.become === "boolean" ? body.become : true;
  const port = normalizePort(body?.port);
  const group = isSafeGroup(body?.group) ? body.group.trim() : "linux_hosts";

  if (port === null || (body?.group !== undefined && !isSafeGroup(body.group))) {
    return NextResponse.json({ ok: false, message: "Укажите SSH-порт 1–65535 и группу из букв, цифр и подчёркивания." }, { status: 400 });
  }

  if (!isSafeAlias(alias)) {
    return NextResponse.json(
      { ok: false, error: "bad_alias", message: "Alias может содержать буквы, цифры, точку, дефис и подчёркивание." },
      { status: 400 },
    );
  }

  if (!isSafeHostAddress(address)) {
    return NextResponse.json(
      { ok: false, error: "bad_address", message: "Укажите корректный IP или hostname." },
      { status: 400 },
    );
  }

  if (!isSafeSshUser(user)) {
    return NextResponse.json(
      { ok: false, error: "bad_user", message: "SSH-пользователь может содержать буквы, цифры, точку, дефис и подчёркивание." },
      { status: 400 },
    );
  }

  const repoRoot = getRepoRoot();
  const inventoryPath = ensureInventory(repoRoot);
  const current = readFileSync(inventoryPath, "utf8");
  const hosts = readInventoryHosts(inventoryPath);

  if (identityCollides(current, alias, group)) {
    return NextResponse.json({ ok: false, message: "Имя хоста не должно совпадать с именем inventory-группы." }, { status: 400 });
  }

  if (hosts.some((host) => host.alias === alias)) {
    return NextResponse.json(
      { ok: false, error: "duplicate_alias", message: "Хост с таким alias уже есть в inventory." },
      { status: 409 },
    );
  }

  if (hosts.some((host) => host.address === address && host.port === port)) {
    return NextResponse.json(
      { ok: false, error: "duplicate_address", message: "Хост с таким IP уже есть в inventory." },
      { status: 409 },
    );
  }

  const credentialId = typeof body?.credentialId === "string" && body.credentialId ? body.credentialId : null;
  if (!credentialId && body?.legacyAccess !== true) return NextResponse.json({ ok: false, message: "Сначала настройте отдельный SSH-ключ этого хоста." }, { status: 400 });
  try { if (credentialId) validateHostCredential(credentialId, { alias, address, port, user }); }
  catch (error) { return NextResponse.json({ ok: false, message: error instanceof HostCredentialError ? error.message : "Ключ хоста недоступен." }, { status: 400 }); }
  const newLine = hostLine({ alias, address, port, user, become, credentialId });
  const lines = current.split("\n");
  saveInventory(inventoryPath, insertHostLine(lines, group, newLine));

  return NextResponse.json({
    ok: true,
    message: "Хост добавлен в inventory.",
    inventoryPath,
    host: {
      alias,
      address,
      user,
      port,
      become,
      groups: [group],
      ...publicCredentialSummary(credentialId),
    },
  });
}

export async function PUT(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alias = typeof body?.alias === "string" ? body.alias.trim() : "";
  const address = typeof body?.address === "string" ? body.address.trim() : "";
  const user = typeof body?.user === "string" ? body.user.trim() : "";
  const become = typeof body?.become === "boolean" ? body.become : true;
  const port = normalizePort(body?.port);
  const group = isSafeGroup(body?.group) ? body.group.trim() : "linux_hosts";

  if (!isSafeAlias(alias) || !isSafeHostAddress(address) || !isSafeSshUser(user) || port === null || (body?.group !== undefined && !isSafeGroup(body.group))) {
    return NextResponse.json(
      { ok: false, message: "Проверьте alias, IP/hostname и SSH-пользователя." },
      { status: 400 },
    );
  }

  const repoRoot = getRepoRoot();
  const inventoryPath = ensureInventory(repoRoot);
  const current = readFileSync(inventoryPath, "utf8");
  const hosts = readInventoryHosts(inventoryPath);
  if (identityCollides(current, alias, group)) {
    return NextResponse.json({ ok: false, message: "Имя хоста не должно совпадать с именем inventory-группы." }, { status: 400 });
  }
  if (hasActiveRemediationForHost(alias)) {
    return NextResponse.json({ ok: false, message: "Дождитесь завершения изменения или отката на этом хосте." }, { status: 409 });
  }
  const existing = hosts.find((host) => host.alias === alias);
  if (!existing) {
    return NextResponse.json({ ok: false, message: "Хост не найден в inventory." }, { status: 404 });
  }
  if (hosts.some((host) => host.alias !== alias && host.address === address && host.port === port)) {
    return NextResponse.json(
      { ok: false, error: "duplicate_address", message: "Другой хост с таким IP уже есть в inventory." },
      { status: 409 },
    );
  }

  const credentialId = typeof body?.credentialId === "string" && body.credentialId ? body.credentialId : existing.credentialId;
  try { if (credentialId) validateHostCredential(credentialId, { alias, address, port, user }); }
  catch (error) { return NextResponse.json({ ok: false, message: error instanceof HostCredentialError ? error.message : "Ключ хоста недоступен." }, { status: 400 }); }

  const removed = removeHostLine(current.split("\n"), alias);
  const nextLines = insertHostLine(
    removed.lines,
    group,
    hostLine({ alias, address, port, user, become, credentialId }),
  );
  saveInventory(inventoryPath, nextLines);

  return NextResponse.json({
    ok: true,
    message: "Хост обновлен.",
    host: { alias, address, user, port, become, groups: [group], ...publicCredentialSummary(credentialId) },
  });
}

export async function DELETE(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alias = typeof body?.alias === "string" ? body.alias.trim() : "";
  if (!isSafeAlias(alias)) {
    return NextResponse.json({ ok: false, message: "Укажите корректный alias." }, { status: 400 });
  }

  if (hasActiveRemediationForHost(alias)) {
    return NextResponse.json({ ok: false, message: "Дождитесь завершения изменения или отката на этом хосте." }, { status: 409 });
  }

  const repoRoot = getRepoRoot();
  const inventoryPath = ensureInventory(repoRoot);
  const current = readFileSync(inventoryPath, "utf8");
  const result = removeHostLine(current.split("\n"), alias);
  if (!result.removed) {
    return NextResponse.json({ ok: false, message: "Хост не найден в inventory." }, { status: 404 });
  }
  saveInventory(inventoryPath, result.lines);
  return NextResponse.json({ ok: true, message: "Хост удален из inventory." });
}
