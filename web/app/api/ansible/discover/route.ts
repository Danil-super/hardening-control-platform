import { execFile } from "node:child_process";
import net from "node:net";
import { existsSync } from "node:fs";
import { networkInterfaces } from "node:os";
import { buildNetworkSuggestions, ipToInt, listHosts, ipInCidr, parseCidr } from "@/lib/network-discovery";
import path from "node:path";
import { promisify } from "node:util";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const execFileAsync = promisify(execFile);

type DiscoveredHost = {
  ip: string;
  reachable: boolean;
  sshOpen: boolean;
  methods: string[];
  alias: string;
  added: boolean;
};

function getRepoRoot() {
  return path.resolve(process.cwd(), "..");
}

function aliasForIp(ip: string) {
  return `auto_${ip.replaceAll(".", "_")}`;
}

async function detectNetworks(request: Request) {
  let routes = "";
  try {
    routes = (await execFileAsync("ip", ["-o", "-4", "route", "show", "scope", "link"], {
      timeout: 10_000, maxBuffer: 1024 * 1024,
    })).stdout;
  } catch { /* Try the OS interface API when iproute2 is unavailable. */ }
  let interfaces: Array<{ device: string; address: string; cidr: string | null }> = [];
  try {
    interfaces = Object.entries(networkInterfaces()).flatMap(([device, addresses]) =>
      (addresses ?? []).filter((item) => item.family === "IPv4" && !item.internal)
        .map((item) => ({ device, address: item.address, cidr: item.cidr })));
  } catch { /* Restricted runtimes may deny interface enumeration too. */ }
  const url = new URL(request.url);
  return buildNetworkSuggestions({
    routes, inContainer: existsSync("/.dockerenv") || existsSync("/run/.containerenv"),
    targetAddress: url.searchParams.get("address") ?? "", siteHostname: url.searchParams.get("siteAddress") ?? url.hostname,
    interfaces,
  });
}

function checkSsh(ip: string, timeout = 450) {
  return new Promise<boolean>((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    function finish(open: boolean) {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve(open);
    }

    socket.setTimeout(timeout);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect(22, ip);
  });
}

async function checkPing(ip: string) {
  try {
    await execFileAsync("ping", ["-c", "1", "-W", "1", ip], {
      timeout: 1_500,
      maxBuffer: 64 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function readNeighborIps(cidr: string) {
  try {
    const { stdout } = await execFileAsync("ip", ["-4", "neigh", "show"], {
      timeout: 5_000,
      maxBuffer: 1024 * 1024,
    });
    return new Set(
      stdout
        .split("\n")
        .map((line) => {
          const ip = line.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s/)?.[1];
          if (!ip || !ipInCidr(ip, cidr) || /\bFAILED\b|\bINCOMPLETE\b/.test(line)) {
            return null;
          }
          return ip;
        })
        .filter((ip): ip is string => Boolean(ip)),
    );
  } catch {
    return new Set<string>();
  }
}

async function scanLocalHosts(cidr: string) {
  const hosts = listHosts(cidr);
  const foundByIp = new Map<string, DiscoveredHost>();
  const concurrency = 32;
  let index = 0;

  async function worker() {
    while (index < hosts.length) {
      const ip = hosts[index];
      index += 1;
      const [sshOpen, pingOk] = await Promise.all([checkSsh(ip), checkPing(ip)]);
      if (sshOpen || pingOk) {
        foundByIp.set(ip, {
          ip,
          reachable: true,
          sshOpen,
          methods: [sshOpen ? "ssh" : "", pingOk ? "ping" : ""].filter(Boolean),
          alias: aliasForIp(ip),
          added: false,
        });
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, hosts.length) }, () => worker()));
  const neighborIps = await readNeighborIps(cidr);
  for (const ip of neighborIps) {
    const existing = foundByIp.get(ip);
    if (existing) {
      if (!existing.methods.includes("arp")) {
        existing.methods.push("arp");
      }
    } else {
      foundByIp.set(ip, {
        ip,
        reachable: true,
        sshOpen: false,
        methods: ["arp"],
        alias: aliasForIp(ip),
        added: false,
      });
    }
  }

  const found = [...foundByIp.values()];
  return found.sort((left, right) => {
    const leftInt = ipToInt(left.ip) ?? 0;
    const rightInt = ipToInt(right.ip) ?? 0;
    return leftInt - rightInt;
  });
}

function isSafeSshUser(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.-]{1,64}$/.test(value);
}

export async function GET(request: Request) {
  return NextResponse.json(await detectNetworks(request));
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  if (body?.addToInventory) {
    return NextResponse.json({ ok: false, error: "verified_onboarding_required", message: "Добавляйте найденные хосты через мастер подключения с проверкой SSH-ключа и доступа." }, { status: 400 });
  }
  const cidr = typeof body?.cidr === "string" ? body.cidr.trim() : "";
  const parsed = cidr ? parseCidr(cidr) : null;

  if (!cidr || !parsed) {
    return NextResponse.json(
      {
        ok: false,
        error: "bad_cidr",
        message: "Укажите приватную локальную подсеть от /24 до /30, например 192.168.1.0/24.",
      },
      { status: 400 },
    );
  }

  const sshUser = isSafeSshUser(body?.sshUser) ? body.sshUser : process.env.USER || "root";
  const become = typeof body?.become === "boolean" ? body.become : true;
  const hosts = await scanLocalHosts(cidr);
  const sshReady = hosts.filter((host) => host.sshOpen).length;

  return NextResponse.json({
    ok: true,
    cidr,
    scannedHosts: parsed.count,
    sshUser,
    become,
    addToInventory: false,
    found: hosts,
    sshReady,
    added: 0,
    inventoryPath: path.join(getRepoRoot(), "ansible", "inventory.ini"),
  });
}
