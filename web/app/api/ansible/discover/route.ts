import { execFile } from "node:child_process";
import net from "node:net";
import path from "node:path";
import { promisify } from "node:util";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const execFileAsync = promisify(execFile);
const maxHostsPerScan = 254;

type RouteCandidate = {
  cidr: string;
  device?: string;
  source?: string;
};

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

function ipToInt(ip: string) {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function intToIp(value: number) {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ].join(".");
}

function isPrivateIp(ip: string) {
  const parts = ip.split(".").map((part) => Number(part));
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254)
  );
}

function parseCidr(cidr: string) {
  const match = cidr.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!match) {
    return null;
  }
  const base = ipToInt(match[1]);
  const prefix = Number(match[2]);
  if (base === null || !Number.isInteger(prefix) || prefix < 24 || prefix > 30 || !isPrivateIp(match[1])) {
    return null;
  }

  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const network = (base & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const count = Math.max(0, broadcast - network - 1);
  if (count > maxHostsPerScan) {
    return null;
  }
  return { base: match[1], prefix, network, broadcast, count };
}

function listHosts(cidr: string) {
  const parsed = parseCidr(cidr);
  if (!parsed) {
    return [];
  }
  const hosts: string[] = [];
  for (let value = parsed.network + 1; value < parsed.broadcast; value += 1) {
    hosts.push(intToIp(value));
  }
  return hosts;
}

function ipInCidr(ip: string, cidr: string) {
  const parsed = parseCidr(cidr);
  const value = ipToInt(ip);
  return Boolean(parsed && value !== null && value > parsed.network && value < parsed.broadcast);
}

function aliasForIp(ip: string) {
  return `auto_${ip.replaceAll(".", "_")}`;
}

async function detectLocalCidrs(): Promise<RouteCandidate[]> {
  try {
    const { stdout } = await execFileAsync("ip", ["-o", "-4", "route", "show", "scope", "link"], {
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
    });
    const candidates: RouteCandidate[] = [];
    for (const line of stdout.split("\n")) {
      const cidr = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2})\s/)?.[1];
      const device = line.match(/\bdev\s+(\S+)/)?.[1];
      const source = line.match(/\bsrc\s+(\d{1,3}(?:\.\d{1,3}){3})/)?.[1];
      if (!cidr || !source || !isPrivateIp(source)) {
        continue;
      }

      const prefix = Number(cidr.split("/")[1]);
      const safeCidr = prefix < 24 ? `${source.split(".").slice(0, 3).join(".")}.0/24` : cidr;
      if (parseCidr(safeCidr)) {
        candidates.push({ cidr: safeCidr, device, source });
      }
    }
    return candidates;
  } catch {
    return [];
  }
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

export async function GET() {
  const candidates = await detectLocalCidrs();
  return NextResponse.json({
    candidates,
    defaultCidr: candidates[0]?.cidr ?? "",
    maxHostsPerScan,
    message: candidates.length
      ? "Найдены локальные приватные подсети для безопасного сканирования."
      : "Не удалось автоматически определить приватную локальную подсеть.",
  });
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  if (body?.addToInventory) {
    return NextResponse.json({ ok: false, error: "verified_onboarding_required", message: "Добавляйте найденные хосты через мастер подключения с проверкой SSH-ключа и доступа." }, { status: 400 });
  }
  const candidates = await detectLocalCidrs();
  const cidr = typeof body?.cidr === "string" && body.cidr ? body.cidr : candidates[0]?.cidr;
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
