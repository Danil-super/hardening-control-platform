import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";
import { getReportsDir } from "@/lib/ansible-reports";

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
  return typeof value === "string" && /^[a-zA-Z0-9_.-]{1,64}$/.test(value);
}

function isSafeSshUser(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.-]{1,64}$/.test(value);
}

function isSafeHostAddress(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  return /^(?:[a-zA-Z0-9.-]{1,253}|\d{1,3}(?:\.\d{1,3}){3})$/.test(value);
}

function isSafeGroup(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.-]{1,64}$/.test(value);
}

function normalizePort(value: unknown) {
  const port = typeof value === "string" ? Number(value) : value;
  return typeof port === "number" && Number.isInteger(port) && port > 0 && port <= 65535 ? port : 22;
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
    hosts.push({
      alias,
      address,
      user: values.get("ansible_user") ?? null,
      port: normalizePort(values.get("ansible_port")),
      become: parseBoolean(values.get("ansible_become")),
      groups: [currentGroup],
      raw: line,
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
}: {
  alias: string;
  address: string;
  port: number;
  user: string;
  become: boolean;
}) {
  return `${alias} ansible_host=${address} ansible_port=${port} ansible_user=${user} ansible_become=${become ? "true" : "false"}`;
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
  } else if (varsIndex !== -1 && varsIndex > hostsIndex) {
    lines.splice(varsIndex, 0, line);
  } else {
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

function readReport(reportPath: string): HostReport | null {
  try {
    const content = JSON.parse(readFileSync(reportPath, "utf8")) as {
      createdAt?: string;
      profileId?: string;
      mode?: string;
      summary?: Partial<Record<"score" | "high" | "medium" | "low" | "info", number>>;
    };
    const summary = content.summary ?? {};
    return {
      path: reportPath,
      fileName: path.basename(reportPath),
      createdAt: content.createdAt ?? null,
      profileId: content.profileId ?? null,
      mode: content.mode ?? "agentless",
      score: typeof summary.score === "number" ? summary.score : null,
      high: typeof summary.high === "number" ? summary.high : 0,
      medium: typeof summary.medium === "number" ? summary.medium : 0,
      low: typeof summary.low === "number" ? summary.low : 0,
      info: typeof summary.info === "number" ? summary.info : 0,
    };
  } catch {
    return null;
  }
}

function attachReports(hosts: InventoryHost[], reportsPath: string) {
  if (!existsSync(reportsPath)) {
    return hosts;
  }

  const reportFiles = readdirSync(reportsPath)
    .filter((fileName) => fileName.endsWith(".json"))
    .map((fileName) => {
      const fullPath = path.join(reportsPath, fileName);
      return { fileName, fullPath, mtimeMs: statSync(fullPath).mtimeMs };
    })
    .sort((left, right) => right.mtimeMs - left.mtimeMs);

  return hosts.map((host) => {
    const hostReports = reportFiles.filter((file) => file.fileName.startsWith(`${host.alias}-`));
    // The host score is a hardening score. Package CVE and event reports have
    // different semantics and must not replace it merely because they are newer.
    const reportFile = hostReports.find((file) => readReport(file.fullPath)?.mode === "agentless");
    return {
      ...host,
      lastReport: reportFile ? readReport(reportFile.fullPath) : null,
      reportCount: hostReports.length,
    };
  });
}

export async function GET() {
  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  const reportsPath = getReportsDir(repoRoot);
  const hosts = attachReports(readInventoryHosts(inventoryPath), reportsPath);

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

  if (hosts.some((host) => host.alias === alias)) {
    return NextResponse.json(
      { ok: false, error: "duplicate_alias", message: "Хост с таким alias уже есть в inventory." },
      { status: 409 },
    );
  }

  if (hosts.some((host) => host.address === address)) {
    return NextResponse.json(
      { ok: false, error: "duplicate_address", message: "Хост с таким IP уже есть в inventory." },
      { status: 409 },
    );
  }

  const newLine = hostLine({ alias, address, port, user, become });
  const lines = current.split("\n");
  writeFileSync(inventoryPath, normalizeInventoryText(insertHostLine(lines, group, newLine)));

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

  if (!isSafeAlias(alias) || !isSafeHostAddress(address) || !isSafeSshUser(user)) {
    return NextResponse.json(
      { ok: false, message: "Проверьте alias, IP/hostname и SSH-пользователя." },
      { status: 400 },
    );
  }

  const repoRoot = getRepoRoot();
  const inventoryPath = ensureInventory(repoRoot);
  const current = readFileSync(inventoryPath, "utf8");
  const hosts = readInventoryHosts(inventoryPath);
  const existing = hosts.find((host) => host.alias === alias);
  if (!existing) {
    return NextResponse.json({ ok: false, message: "Хост не найден в inventory." }, { status: 404 });
  }
  if (hosts.some((host) => host.alias !== alias && host.address === address)) {
    return NextResponse.json(
      { ok: false, error: "duplicate_address", message: "Другой хост с таким IP уже есть в inventory." },
      { status: 409 },
    );
  }

  const removed = removeHostLine(current.split("\n"), alias);
  const nextLines = insertHostLine(
    removed.lines,
    group,
    hostLine({ alias, address, port, user, become }),
  );
  writeFileSync(inventoryPath, normalizeInventoryText(nextLines));

  return NextResponse.json({
    ok: true,
    message: "Хост обновлен.",
    host: { alias, address, user, port, become, groups: [group] },
  });
}

export async function DELETE(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alias = typeof body?.alias === "string" ? body.alias.trim() : "";
  if (!isSafeAlias(alias)) {
    return NextResponse.json({ ok: false, message: "Укажите корректный alias." }, { status: 400 });
  }

  const repoRoot = getRepoRoot();
  const inventoryPath = ensureInventory(repoRoot);
  const current = readFileSync(inventoryPath, "utf8");
  const result = removeHostLine(current.split("\n"), alias);
  if (!result.removed) {
    return NextResponse.json({ ok: false, message: "Хост не найден в inventory." }, { status: 404 });
  }
  writeFileSync(inventoryPath, normalizeInventoryText(result.lines));
  return NextResponse.json({ ok: true, message: "Хост удален из inventory." });
}
