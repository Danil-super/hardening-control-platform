import { execFile } from "node:child_process";
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import { isIP } from "node:net";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type HostKeyCandidate = {
  algorithm: string;
  fingerprint: string;
  hostKeyLine: string;
};

export function configuredPrivateKeyPath() {
  return process.env.HCP_SSH_PRIVATE_KEY_PATH ?? path.join(os.homedir(), ".ssh", "hcp-control");
}

export function getKnownHostsPath() {
  return process.env.HCP_KNOWN_HOSTS_PATH
    ? path.resolve(process.env.HCP_KNOWN_HOSTS_PATH)
    : path.join(os.homedir(), ".ssh", "known_hosts");
}

export function ansibleSshArgs() {
  // Ansible parses this value with shlex, so a path must remain one argument.
  return `-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${JSON.stringify(getKnownHostsPath())}`;
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

  // Derive from the private key actually used by Ansible: a stale .pub file
  // otherwise makes the onboarding wizard install an unrelated key.
  const result = await execFileAsync("ssh-keygen", ["-y", "-P", "", "-f", privateKeyPath], {
      timeout: 10_000,
      maxBuffer: 64 * 1024,
    });
  const publicKey = result.stdout.trim();

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
  if (isIP(value)) return true;
  if (/^[\d.]+$/.test(value)) return false;
  return value.split(".").every((label) => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}

export function normalizeSshPort(value: unknown) {
  if (value === undefined || value === null) return 22;
  const port = typeof value === "string" ? Number(value) : value;
  return typeof port === "number" && Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

function keyScanError(error: unknown) {
  const result = error as { stdout?: string; stderr?: string; message?: string };
  return result.stderr?.trim() || result.stdout?.trim() || result.message || "Не удалось получить SSH host key.";
}

export async function scanHostKeys(address: string, port: number) {
  if (!isSafeSshHostAddress(address) || normalizeSshPort(port) === null) {
    throw Object.assign(new Error("Некорректный SSH-адрес или порт."), { code: "bad_address" });
  }
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
    .filter((line) => /^(?:[^\s]+)\s+(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]+$/.test(line))
    .map((line) => `${hostPattern(address, port)} ${line.split(/\s+/).slice(1).join(" ")}`);
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

// Read saved trust only. This lookup never contacts a target or trusts a key
// learned from the network; the SSH handshake still verifies the live key.
export async function hasSavedHostKey(address: string, port: number) {
  if (!isSafeSshHostAddress(address) || normalizeSshPort(port) === null) return false;
  const knownHostsPath = getKnownHostsPath();
  if (!existsSync(knownHostsPath)) return false;
  try {
    const result = await execFileAsync("ssh-keygen", ["-F", hostPattern(address, port), "-f", knownHostsPath], { timeout: 10_000, maxBuffer: 128 * 1024 });
    const lines = result.stdout.split("\n").map((line) => line.trim());
    if (lines.some((line) => line.startsWith("@revoked "))) return false;
    return lines.some((line) => !line.startsWith("#") && !line.startsWith("@") && isPublicKey(line.split(/\s+/).slice(1).join(" ")));
  } catch (error) {
    if ((error as { code?: number }).code === 1) return false;
    throw error;
  }
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
  const lockPath = `${knownHostsPath}.hcp-lock`;
  try {
    mkdirSync(lockPath, { mode: 0o700 });
  } catch (error) {
    if ((error as { code?: string }).code === "EEXIST") {
      throw Object.assign(new Error("Сейчас сохраняется другой SSH key. Повторите операцию после её завершения."), { code: "host_key_store_busy" });
    }
    throw error;
  }
  try {
  const current = existsSync(knownHostsPath) ? readFileSync(knownHostsPath, "utf8") : "";
  const pattern = hostPattern(address, port);
  let matchingLines: string[] = [];
  if (existsSync(knownHostsPath)) {
    try {
      const result = await execFileAsync("ssh-keygen", ["-F", pattern, "-f", knownHostsPath], { timeout: 10_000, maxBuffer: 128 * 1024 });
      matchingLines = result.stdout.split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
    } catch (error) {
      if ((error as { code?: number }).code !== 1) throw error;
    }
  }
  const [, candidateType, candidateKey] = candidate.hostKeyLine.split(/\s+/);
  if (matchingLines.some((line) => {
    const [, type, key] = line.split(/\s+/);
    return type === candidateType && key === candidateKey;
  })) {
    return { fingerprint: candidate.fingerprint, algorithm: candidate.algorithm, alreadyTrusted: true };
  }

  const conflictingKey = matchingLines.some((line) => {
    const fields = line.split(/\s+/);
    const type = fields[line.startsWith("@") ? 2 : 1];
    return type === candidateType;
  });
  if (conflictingKey) {
    throw Object.assign(new Error("Для этого адреса уже сохранён другой SSH key того же типа. Проверьте ротацию ключа вручную."), { code: "host_key_conflict" });
  }

  appendFileSync(knownHostsPath, `${current && !current.endsWith("\n") ? "\n" : ""}${candidate.hostKeyLine}\n`, { mode: 0o600 });
  chmodSync(knownHostsPath, 0o600);
  return { fingerprint: candidate.fingerprint, algorithm: candidate.algorithm, alreadyTrusted: false };
  } finally {
    rmSync(lockPath, { recursive: true, force: true });
  }
}
