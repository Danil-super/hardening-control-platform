import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

type InventoryHost = {
  alias: string;
  address: string;
  user: string | null;
  become: boolean | null;
  groups: string[];
  raw: string;
  lastReport: HostReport | null;
};

type HostReport = {
  path: string;
  fileName: string;
  createdAt: string | null;
  profileId: string | null;
  score: number | null;
  high: number;
  medium: number;
  low: number;
  info: number;
};

function getRepoRoot() {
  return path.resolve(process.cwd(), "..");
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
      become: parseBoolean(values.get("ansible_become")),
      groups: [currentGroup],
      raw: line,
      lastReport: null,
    });
  }

  return hosts;
}

function readReport(reportPath: string): HostReport | null {
  try {
    const content = JSON.parse(readFileSync(reportPath, "utf8")) as {
      createdAt?: string;
      profileId?: string;
      summary?: Partial<Record<"score" | "high" | "medium" | "low" | "info", number>>;
    };
    const summary = content.summary ?? {};
    return {
      path: reportPath,
      fileName: path.basename(reportPath),
      createdAt: content.createdAt ?? null,
      profileId: content.profileId ?? null,
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
    const reportFile = reportFiles.find((file) => file.fileName.startsWith(`${host.alias}-`));
    return {
      ...host,
      lastReport: reportFile ? readReport(reportFile.fullPath) : null,
    };
  });
}

export async function GET() {
  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  const reportsPath = path.join(repoRoot, "ansible", "reports");
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
