import { execFile } from "node:child_process";
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type HostKeyCandidate = {
  algorithm: string;
  fingerprint: string;
  hostKeyLine: string;
};

function configuredPrivateKeyPath() {
  return process.env.HCP_SSH_PRIVATE_KEY_PATH ?? path.join(os.homedir(), ".ssh", "hcp-control");
}

export function getKnownHostsPath() {
  return process.env.HCP_KNOWN_HOSTS_PATH
    ? path.resolve(process.env.HCP_KNOWN_HOSTS_PATH)
    : path.join(os.homedir(), ".ssh", "known_hosts");
}

export function ansibleSshArgs() {
  return `-o StrictHostKeyChecking=yes -o UserKnownHostsFile=${getKnownHostsPath()}`;
}

function isPublicKey(value: string) {
  return /^(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp\d+|sk-[\w@-]+)\s+[A-Za-z0-9+/=]+(?:\s+.*)?$/.test(value.trim());
}

function fingerprintFromOutput(output: string) {
  const match = output.match(/^\d+\s+(SHA256:[A-Za-z0-9+/=]+)\s+.*\(([^)]+)\)/m);
  return match ? { fingerprint: match[1], algorithm: match[2] } : null;
}

async function fingerprintForKeyLine(keyLine: string) {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), "hcp-host-key-"));
  const keyPath = path.join(tempDir, "key.pub");
  try {
    writeFileSync(keyPath, `${keyLine.trim()}\n`, { mode: 0o600 });
    const result = await execFileAsync("ssh-keygen", ["-lf", keyPath, "-E", "sha256"], {
      timeout: 10_000,
      maxBuffer: 64 * 1024,
    });
    return fingerprintFromOutput(result.stdout);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

export async function getControlPublicKey() {
  const privateKeyPath = configuredPrivateKeyPath();
  if (!existsSync(privateKeyPath)) {
    throw Object.assign(new Error("Ключ узла управления не найден. Создайте его и укажите HCP_SSH_PRIVATE_KEY_PATH."), { code: "control_key_missing" });
  }

  const publicKeyPath = `${privateKeyPath}.pub`;
  let publicKey = existsSync(publicKeyPath) ? readFileSync(publicKeyPath, "utf8").trim() : "";
  if (!isPublicKey(publicKey)) {
    const result = await execFileAsync("ssh-keygen", ["-y", "-f", privateKeyPath], {
      timeout: 10_000,
      maxBuffer: 64 * 1024,
    });
    publicKey = result.stdout.trim();
  }

  if (!isPublicKey(publicKey)) {
    throw Object.assign(new Error("Не удалось получить корректный публичный ключ узла управления."), { code: "control_key_invalid" });
  }

  const fingerprint = await fingerprintForKeyLine(publicKey);
  return { publicKey, fingerprint: fingerprint?.fingerprint ?? null };
}

export function isSafeSshHostAddress(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 253) {
    return false;
  }
  const ipv4 = value.split(".");
  if (ipv4.length === 4 && ipv4.every((part) => /^\d{1,3}$/.test(part))) {
    return ipv4.every((part) => Number(part) <= 255);
  }
  return value.split(".").every((label) => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}

export function normalizeSshPort(value: unknown) {
  const port = typeof value === "string" ? Number(value) : value;
  return typeof port === "number" && Number.isInteger(port) && port > 0 && port <= 65535 ? port : 22;
}

function keyScanError(error: unknown) {
  const result = error as { stdout?: string; stderr?: string; message?: string };
  return result.stderr?.trim() || result.stdout?.trim() || result.message || "Не удалось получить SSH host key.";
}

export async function scanHostKeys(address: string, port: number) {
  let stdout = "";
  try {
    const result = await execFileAsync("ssh-keyscan", ["-T", "8", "-p", String(port), "-t", "ed25519,ecdsa,rsa", address], {
      timeout: 12_000,
      maxBuffer: 128 * 1024,
    });
    stdout = result.stdout;
  } catch (error) {
    throw Object.assign(new Error(keyScanError(error)), { code: "host_key_scan_failed" });
  }

  const keyLines = stdout
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => /^(?:[^\s]+)\s+(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]+/.test(line));
  const candidates = (await Promise.all(keyLines.map(async (hostKeyLine) => {
    const fingerprint = await fingerprintForKeyLine(hostKeyLine);
    return fingerprint ? { ...fingerprint, hostKeyLine } : null;
  }))).filter((candidate): candidate is HostKeyCandidate => Boolean(candidate));

  if (!candidates.length) {
    throw Object.assign(new Error("SSH host key не найден. Проверьте адрес, порт и доступность SSH."), { code: "host_key_not_found" });
  }
  return candidates;
}

function hostPattern(address: string, port: number) {
  return port === 22 ? address : `[${address}]:${port}`;
}

export async function trustHostKey({
  address,
  port,
  expectedFingerprint,
}: {
  address: string;
  port: number;
  expectedFingerprint: string;
}) {
  const candidates = await scanHostKeys(address, port);
  const candidate = candidates.find((item) => item.fingerprint === expectedFingerprint);
  if (!candidate) {
    throw Object.assign(new Error("Указанный fingerprint не совпал с ключом, полученным от сервера. Ключ не сохранён."), { code: "host_key_mismatch" });
  }

  const knownHostsPath = getKnownHostsPath();
  mkdirSync(path.dirname(knownHostsPath), { recursive: true, mode: 0o700 });
  const current = existsSync(knownHostsPath) ? readFileSync(knownHostsPath, "utf8") : "";
  const currentLines = current.split("\n").map((line) => line.trim()).filter(Boolean);
  if (currentLines.includes(candidate.hostKeyLine)) {
    return { fingerprint: candidate.fingerprint, algorithm: candidate.algorithm, alreadyTrusted: true };
  }

  const pattern = hostPattern(address, port);
  const [, candidateType] = candidate.hostKeyLine.split(/\s+/, 3);
  const conflictingKey = currentLines.some((line) => {
    const [hosts, type] = line.split(/\s+/, 3);
    return hosts?.split(",").includes(pattern) && type === candidateType;
  });
  if (conflictingKey) {
    throw Object.assign(new Error("Для этого адреса уже сохранён другой SSH key того же типа. Проверьте ротацию ключа вручную."), { code: "host_key_conflict" });
  }

  appendFileSync(knownHostsPath, `${candidate.hostKeyLine}\n`, { mode: 0o600 });
  chmodSync(knownHostsPath, 0o600);
  return { fingerprint: candidate.fingerprint, algorithm: candidate.algorithm, alreadyTrusted: false };
}
