import { existsSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { NextResponse } from "next/server";
import { getReportsDir, listAnsibleReportsAsync, type AnsibleReportSummary, targetAliasFromReport } from "@/lib/ansible-reports";
import { buildHostRiskSummary, isSecurityAudit, type HostRiskSummary } from "@/lib/host-risk-summary";
import { isSafeSshHostAddress, normalizeSshPort } from "@/lib/ssh-access";
import { HostCredentialError, credentialKeyPath, publicCredentialSummary, validateHostCredential } from "@/lib/host-credentials";
import { assertAssetIdle, hasActiveRemediationForHost, listAstraOvalPolicies, listOpenScapExceptions, listOpenScapPolicies } from "@/lib/state-store";
import { parseStaticInventory, withInventoryConnectionView } from "@/lib/inventory";

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
  riskSummary?: HostRiskSummary;
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

function inventorySection(line: string) {
  return line.match(/^\[([A-Za-z0-9_.-]+(?::(?:vars|children))?)\]\s*(?:[#;].*)?$/)?.[1];
}

function readInventoryHosts(inventoryText: string) {
  const hosts: InventoryHost[] = [];
  let currentGroup = "ungrouped";
  for (const rawLine of inventoryText.split("\n")) {
    const line = rawLine.trim();
    if (!line || /^[#;]/.test(line)) {
      continue;
    }

    const section = inventorySection(line);
    if (section) {
      currentGroup = section;
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

function inventoryMembership(inventoryText: string, connections = readInventoryHosts(inventoryText)) {
  const inventory = parseStaticInventory(inventoryText);
  const direct = new Map(connections.map((host) => [host.alias, host.groups.filter(isUserGroup).sort()]));
  return {
    groups: inventory.groups.filter(isUserGroup),
    hosts: inventory.hosts.map(({ alias, groups }) => ({ alias, groups: groups.filter(isUserGroup), directGroups: direct.get(alias) ?? [] })),
  };
}

function isUserGroup(group: string) {
  return group !== "all" && group !== "ungrouped";
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
  const removedLines: string[] = [];
  const next = lines.filter((rawLine) => {
    const line = rawLine.trim();
    const section = inventorySection(line);
    if (section) {
      currentGroup = section;
      return true;
    }
    if (!line || /^[#;]/.test(line) || currentGroup.endsWith(":vars") || currentGroup.endsWith(":children")) {
      return true;
    }
    const [currentAlias] = line.split(/\s+/);
    if (currentAlias === alias) {
      removedLines.push(rawLine.trim());
      return false;
    }
    return true;
  });
  return { lines: next, removed: removedLines.length > 0, removedLines };
}

function insertHostLine(lines: string[], group: string, line: string, attachToLinux = true) {
  const varsIndex = lines.findIndex((item) => inventorySection(item.trim()) === "linux_hosts:vars");
  const groupHeader = `[${group}]`;
  const hostsIndex = lines.findIndex((item) => inventorySection(item.trim()) === group);

  if (hostsIndex === -1) {
    const insertIndex = varsIndex === -1 ? lines.length : varsIndex;
    lines.splice(insertIndex, 0, "", groupHeader, line);
  } else {
    // Insert in this group's section, never before an unrelated later :vars.
    lines.splice(hostsIndex + 1, 0, line);
  }

  if (attachToLinux && group !== "linux_hosts") {
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

function moveHostToGroups(lines: string[], alias: string, [primary = "ungrouped", ...otherGroups]: string[]) {
  const removed = removeHostLine(lines, alias);
  const connectionLines = removed.removedLines.filter((line) => line !== alias);
  insertHostLine(removed.lines, primary, connectionLines.join("\n") || alias, false);
  for (const group of otherGroups) insertHostLine(removed.lines, group, alias, false);
  return removed.lines;
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

function attachReports(hosts: InventoryHost[], reports: AnsibleReportSummary[]) {

  return hosts.map((host) => {
    const hostReports = reports.filter((report) => targetAliasFromReport(report) === host.alias);
    const reportFile = hostReports.find((report) => report.reportTimeValid && isSecurityAudit(report.mode));
    return {
      ...host,
      lastReport: reportFile ?? null,
      reportCount: hostReports.length,
      riskSummary: buildHostRiskSummary(host.alias, reports),
    };
  });
}

export async function GET(request?: Request) {
  if (request && new URL(request.url).searchParams.get("view") === "groups") {
    const inventoryPath = path.join(getRepoRoot(), "ansible", "inventory.ini");
    try {
      const inventoryText = existsSync(inventoryPath) ? readFileSync(inventoryPath, "utf8") : "";
      return NextResponse.json({ ok: true, ...inventoryMembership(inventoryText) }, { headers: { "Cache-Control": "no-store" } });
    } catch {
      return NextResponse.json({ ok: false, message: "Проверьте формат групп в inventory." }, { status: 400 });
    }
  }
  const reports = await listAnsibleReportsAsync();
  return withInventoryConnectionView(() => hostListResponse(reports));
}

function hostListResponse(reports: AnsibleReportSummary[]) {
  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  const reportsPath = getReportsDir(repoRoot);
  const inventoryText = existsSync(inventoryPath) ? readFileSync(inventoryPath, "utf8") : "";
  const connections = readInventoryHosts(inventoryText);
  const membership = inventoryMembership(inventoryText, connections);
  const byAlias = new Map(membership.hosts.map((host) => [host.alias, host]));
  const hosts = attachReports(connections, reports).map((host) => ({
    ...host, ...byAlias.get(host.alias), ...publicCredentialSummary(host.credentialId),
  }));

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
  const hosts = readInventoryHosts(current);

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
  if (!credentialId) return NextResponse.json({ ok: false, message: "Сначала настройте отдельный SSH-ключ этого хоста." }, { status: 400 });
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
  const hosts = readInventoryHosts(current);
  if (body?.group !== undefined && identityCollides(current, alias, group)) {
    return NextResponse.json({ ok: false, message: "Имя хоста не должно совпадать с именем inventory-группы." }, { status: 400 });
  }
  if (hasActiveRemediationForHost(alias)) {
    return NextResponse.json({ ok: false, message: "Дождитесь завершения изменения или отката на этом хосте." }, { status: 409 });
  }
  try { assertAssetIdle(alias); }
  catch (error) { return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "На активе выполняется операция." }, { status: 409 }); }
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
  const directGroups = body?.group === undefined ? existing.groups : [group];
  const line = hostLine({ alias, address, port, user, become, credentialId });
  const nextLines = directGroups.reduce((lines, name, index) =>
    insertHostLine(lines, name, index === 0 ? line : alias, body?.group !== undefined), removed.lines);
  saveInventory(inventoryPath, nextLines);

  return NextResponse.json({
    ok: true,
    message: "Хост обновлен.",
    host: { alias, address, user, port, become, groups: directGroups, ...publicCredentialSummary(credentialId) },
  });
}

export async function PATCH(request: Request) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return NextResponse.json({ ok: false, message: "Укажите группу или состав групп хоста." }, { status: 400 });
  }
  const inventoryPath = ensureInventory(getRepoRoot());
  const current = readFileSync(inventoryPath, "utf8");
  const inventory = inventoryMembership(current);
  const conflict = () => NextResponse.json({ ok: false, message: "Группы хоста уже изменились. Откройте их заново." }, { status: 409 });
  if (body.alias === undefined) {
    const group = typeof body.group === "string" ? body.group.trim() : "";
    if (!isSafeGroup(group) || inventory.hosts.some((host) => host.alias === group)) {
      return NextResponse.json({ ok: false, message: "Введите имя группы из латинских букв, цифр и подчёркиваний. Имя должно отличаться от имени хоста." }, { status: 400 });
    }
    if (inventory.groups.includes(group)) return NextResponse.json({ ok: true });
    saveInventory(inventoryPath, [...current.split("\n"), "", `[${group}]`]);
    return NextResponse.json({ ok: true }, { status: 201 });
  }

  const { alias, groups, previousGroups } = body;
  if (!isSafeAlias(alias) || !Array.isArray(groups) || groups.length > 256
      || groups.some((name: unknown) => typeof name !== "string" || !inventory.groups.includes(name))
      || !Array.isArray(previousGroups) || previousGroups.some((name: unknown) => typeof name !== "string")) {
    return NextResponse.json({ ok: false, message: "Выберите существующие группы для хоста." }, { status: 400 });
  }
  const host = inventory.hosts.find((candidate) => candidate.alias === alias);
  if (!host) return NextResponse.json({ ok: false, message: "Хост не найден в inventory." }, { status: 404 });
  if (JSON.stringify([...new Set(previousGroups)].sort()) !== JSON.stringify(host.directGroups)) return conflict();
  const roleGroups = [...new Set<string>(groups)].filter((name) => name !== "linux_hosts").sort();
  if (host.groups.includes("linux_hosts") && JSON.stringify(roleGroups) === JSON.stringify(host.directGroups.filter((name) => name !== "linux_hosts"))) {
    return NextResponse.json({ ok: true });
  }
  try { assertAssetIdle(alias); }
  catch { return NextResponse.json({ ok: false, message: "Дождитесь завершения операции на хосте." }, { status: 409 }); }

  saveInventory(inventoryPath, moveHostToGroups(current.split("\n"), alias, ["linux_hosts", ...roleGroups]));
  return NextResponse.json({ ok: true });
}

function deleteHostGroup(group: unknown, confirmedGroup: unknown, expectedMembers: unknown) {
  const fail = (message: string, status: number) => NextResponse.json({ ok: false, message }, { status });
  if (typeof group !== "string" || !/^[A-Za-z0-9_.-]+$/.test(group) || [".", "..", "all", "ungrouped", "linux_hosts"].includes(group)
      || group !== confirmedGroup || !Array.isArray(expectedMembers) || expectedMembers.some((alias) => typeof alias !== "string")) {
    return fail("Укажите пользовательскую группу и подтвердите удаление.", 400);
  }
  const inventoryPath = ensureInventory(getRepoRoot());
  const current = readFileSync(inventoryPath, "utf8");
  const inventory = inventoryMembership(current);
  if (!inventory.groups.includes(group)) return fail("Группа не найдена.", 404);
  const members = inventory.hosts.filter((host) => host.groups.includes(group));
  if (JSON.stringify([...expectedMembers].sort()) !== JSON.stringify(members.map((host) => host.alias).sort())) {
    return fail("Состав группы изменился. Проверьте его перед удалением.", 409);
  }
  if ([...listOpenScapPolicies(), ...listAstraOvalPolicies(), ...listOpenScapExceptions()].some((item) => item.groupName === group)) {
    return fail("У группы есть настройки OpenSCAP, OVAL или исключения. Сначала перенесите или удалите их.", 409);
  }
  const inventoryDirs = new Set([path.dirname(inventoryPath), path.dirname(realpathSync(inventoryPath))]);
  if ([...inventoryDirs].some((dir) => ["", ".yml", ".yaml"].some((suffix) => existsSync(path.join(dir, "group_vars", group + suffix))))) {
    return fail("Для группы заданы переменные в group_vars. Сначала перенесите их.", 409);
  }
  const original = current.split("\n");
  const parents = new Set<string>();
  let section = "";
  let next: string[] = [];
  for (const raw of original) {
    const line = raw.trim();
    const header = inventorySection(line);
    if (header) section = header;
    if ([`${group}:vars`, `${group}:children`].includes(section) && !header && line && !/^[#;]/.test(line)) {
      return fail("У группы есть переменные или вложенные группы. Сначала перенесите их.", 409);
    }
    if ([group, `${group}:vars`, `${group}:children`].includes(section)) continue;
    if (section.endsWith(":children") && line.split(/\s+/)[0] === group) {
      parents.add(section.slice(0, -":children".length));
      continue;
    }
    next.push(raw);
  }
  for (const host of members) {
    try { assertAssetIdle(host.alias); }
    catch { return fail("Дождитесь завершения операций на хостах этой группы.", 409); }
    const groups = [...new Set([...parents, ...host.directGroups])].filter((name) => name !== group && name !== "all");
    // Extract from the original inventory before removing connection lines in the deleted section.
    const { removedLines } = removeHostLine(original, host.alias);
    next = removeHostLine(next, host.alias).lines;
    const [primary = "ungrouped", ...others] = groups;
    insertHostLine(next, primary, removedLines.filter((line) => line !== host.alias).join("\n") || host.alias, false);
    for (const other of others) insertHostLine(next, other, host.alias, false);
  }
  saveInventory(inventoryPath, next);
  return NextResponse.json({ ok: true, message: "Группа удалена. Хосты сохранены." });
}

export async function DELETE(request: Request) {
  const body = await request.json().catch(() => ({}));
  if (body?.group !== undefined) return deleteHostGroup(body.group, body.confirmedGroup, body.expectedMembers);
  const alias = typeof body?.alias === "string" ? body.alias.trim() : "";
  if (!isSafeAlias(alias)) {
    return NextResponse.json({ ok: false, message: "Укажите корректный alias." }, { status: 400 });
  }

  if (hasActiveRemediationForHost(alias)) {
    return NextResponse.json({ ok: false, message: "Дождитесь завершения изменения или отката на этом хосте." }, { status: 409 });
  }
  try { assertAssetIdle(alias); }
  catch (error) { return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "На активе выполняется операция." }, { status: 409 }); }

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
