import { execFile } from "node:child_process";
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import { isIP } from "node:net";
import path from "node:path";
import { promisify } from "node:util";
import { machineIdentityHash, validHostFingerprint, type AssetObservation } from "@/lib/asset-binding";

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

export function ansibleSshArgs(knownHostsPath = getKnownHostsPath(), algorithms?: string) {
  // Ansible parses this value with shlex, so a path must remain one argument.
  return `-F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no -o UserKnownHostsFile=${JSON.stringify(knownHostsPath)}${algorithms ? ` -o HostKeyAlgorithms=${algorithms}` : ""}`;
}

/**
 * Keep options shared by every transfer program separate from a forced TTY.
 * ANSIBLE_SSH_ARGS is also passed to sftp/scp; placing -tt there corrupts
 * their file-transfer protocol.  ANSIBLE_SSH_EXTRA_ARGS targets only ssh,
 * which is the channel where a hardened sudo policy can require a terminal.
 */
export function ansibleSshEnvironment({ useTty = false }: { useTty?: boolean } = {}) {
  return {
    ANSIBLE_SSH_ARGS: ansibleSshArgs(),
    ANSIBLE_SSH_EXTRA_ARGS: useTty ? "-tt" : "",
  };
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

export type TrustedAssetObservation = AssetObservation & { hostKeyLine: string; hostKeyAlgorithms: string };

async function savedHostKeyCandidates(address: string, port: number): Promise<HostKeyCandidate[]> {
  const result = await execFileAsync("ssh-keygen", ["-F", hostPattern(address, port), "-f", getKnownHostsPath()], { timeout: 10_000, maxBuffer: 128 * 1024 });
  const lines = result.stdout.split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
  if (lines.some((line) => line.startsWith("@revoked ")) || lines.length > 16) throw new Error("Unsupported or revoked host-key trust");
  const candidates: HostKeyCandidate[] = [];
  for (const line of lines) {
    if (line.startsWith("@")) continue;
    const fields = line.split(/\s+/);
    const keyLine = `${fields[1]} ${fields[2]}`;
    if (!isPublicKey(keyLine)) continue;
    const fingerprint = await fingerprintForKeyLine(keyLine);
    if (fingerprint) candidates.push({ ...fingerprint, hostKeyLine: `${hostPattern(address, port)} ${keyLine}` });
  }
  if (!candidates.length) throw new Error("Missing trusted host key");
  return candidates;
}

/** The identity is read through an authenticated channel, never ssh-keyscan. */
export async function probeTrustedAssetIdentity(input: { address: string; port: number; user: string; privateKeyPath: string }): Promise<TrustedAssetObservation> {
  if (!isSafeSshHostAddress(input.address) || normalizeSshPort(input.port) === null
      || !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(input.user)) throw new Error("Некорректное SSH-подключение для проверки идентичности.");
  let candidates: HostKeyCandidate[];
  try { candidates = await savedHostKeyCandidates(input.address, input.port); }
  catch { throw Object.assign(new Error("Сначала независимо проверьте и сохраните SSH fingerprint сервера. Идентичность актива не установлена."), { code: "asset_host_key_untrusted" }); }
  const trustDirectory = mkdtempSync(path.join(os.tmpdir(), "hcp-asset-trust-"));
  const trustFile = path.join(trustDirectory, "known_hosts");
  try {
    writeFileSync(trustFile, candidates.map((candidate) => candidate.hostKeyLine).join("\n") + "\n", { mode: 0o600 });
    const result = await execFileAsync("ssh", ["-v", "-F", "/dev/null", "-T", "-p", String(input.port), "-l", input.user, "-i", input.privateKeyPath,
      "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "PreferredAuthentications=publickey",
      "-o", "StrictHostKeyChecking=yes", "-o", `UserKnownHostsFile=${JSON.stringify(trustFile)}`, "-o", "GlobalKnownHostsFile=/dev/null",
      "-o", "UpdateHostKeys=no", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=10",
      "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=1", "--", input.address,
      "LC_ALL=C; export LC_ALL; IFS= read -r hcp_machine_id < /etc/machine-id && printf 'HCP_MACHINE_ID=%s\\n' \"$hcp_machine_id\""], {
      timeout: 25_000, maxBuffer: 64 * 1024, env: { ...process.env, LC_ALL: "C", SSH_ASKPASS_REQUIRE: "never" },
    });
    const ids = [...result.stdout.matchAll(/^HCP_MACHINE_ID=([a-f0-9]{32})\r?$/gm)];
    // This debug line is generated locally by OpenSSH for the negotiated key.
    // A remote banner is prefixed differently and cannot become this line.
    const keys = [...result.stderr.matchAll(/^debug1: Server host key: \S+ (SHA256:[A-Za-z0-9+/=]+)\r?$/gm)];
    if (ids.length !== 1 || keys.length !== 1 || !validHostFingerprint(keys[0][1])) throw new Error("identity_output_invalid");
    const candidate = candidates.find((item) => item.fingerprint === keys[0][1]);
    if (!candidate) throw new Error("Negotiated key not in the captured trust");
    const keyType = candidate.hostKeyLine.split(/\s+/)[1];
    return { machineIdSha256: machineIdentityHash(ids[0][1]), sshHostKeyFingerprint: keys[0][1], observedAt: new Date().toISOString(),
      hostKeyLine: candidate.hostKeyLine, hostKeyAlgorithms: keyType === "ssh-rsa" ? "rsa-sha2-512,rsa-sha2-256" : keyType };
  } catch {
    // Never return SSH stdout/stderr: it contains raw machine-id and paths.
    throw Object.assign(new Error("Не удалось подтвердить machine-id и доверенный SSH host key. Проверьте ключ, доступ и /etc/machine-id через независимую консоль; смена машины или host key требует явной перепривязки."), { code: "asset_identity_unverified" });
  } finally { rmSync(trustDirectory, { recursive: true, force: true }); }
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
