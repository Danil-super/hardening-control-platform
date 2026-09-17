import { createHash, randomUUID } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { configuredPrivateKeyPath, isSafeSshHostAddress, normalizeSshPort } from "@/lib/ssh-access";

export type HostIdentity = { alias: string; address: string; user: string; port: number };
export type HostCredential = HostIdentity & {
  version: 1; id: string; createdAt: string; verifiedAt: string | null;
  publicKey: string | null; fingerprint: string | null;
  // Set only after HCP has proved the persistent non-interactive sudo path.
  // Older credential metadata deliberately has no value and stays compatible
  // once it is already bound to an existing inventory host.
  sudoReadyAt?: string | null;
};
export class HostCredentialError extends Error {
  constructor(message: string, public code: string) { super(message); }
}
export function credentialError(message: string, code = "credential_invalid") {
  return new HostCredentialError(message, code);
}
export function validHostIdentity(value: HostIdentity) {
  return /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value.alias)
    && !["all", "ungrouped", "preflight"].includes(value.alias)
    && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value.user)
    && isSafeSshHostAddress(value.address) && normalizeSshPort(value.port) === value.port;
}
function validOptionalTimestamp(value: unknown) {
  return value === undefined || value === null || (typeof value === "string" && Number.isFinite(Date.parse(value)));
}
export function hostKeysDirectory() {
  return path.join(path.resolve(process.env.HCP_STATE_DIR ?? path.join(process.cwd(), "..", "ansible")), "ssh-host-keys");
}
export function credentialDirectory(id: string) {
  if (!/^[a-f0-9]{64}$/.test(id)) throw credentialError("Некорректный идентификатор SSH-ключа.");
  return path.join(hostKeysDirectory(), id);
}
export function credentialKeyPath(id: string) { return path.join(credentialDirectory(id), "id_ed25519"); }
function sameIdentity(a: HostIdentity, b: HostIdentity) {
  return a.alias === b.alias && a.address.toLowerCase() === b.address.toLowerCase() && a.user === b.user && a.port === b.port;
}
function assertRegularLocation(id: string) {
  for (const directory of [hostKeysDirectory(), credentialDirectory(id)]) {
    const info = lstatSync(directory, { throwIfNoEntry: false });
    if (info && (!info.isDirectory() || info.isSymbolicLink())) throw credentialError("Хранилище SSH-ключа имеет недопустимый тип.");
  }
  for (const file of [credentialKeyPath(id), credentialKeyPath(id) + ".pub", path.join(credentialDirectory(id), "metadata.json")]) {
    const info = lstatSync(file, { throwIfNoEntry: false });
    if (info && (!info.isFile() || info.isSymbolicLink())) throw credentialError("Файл SSH-ключа имеет недопустимый тип.");
  }
}
export function readHostCredential(id: string): HostCredential {
  assertRegularLocation(id);
  let value: HostCredential;
  try { value = JSON.parse(readFileSync(path.join(credentialDirectory(id), "metadata.json"), "utf8")); }
  catch { throw credentialError("Ключ хоста не найден. Восстановите резервную копию или настройте новый доступ.", "credential_missing"); }
  if (value.version !== 1 || value.id !== id || !validHostIdentity(value) || !validOptionalTimestamp(value.sudoReadyAt)) {
    throw credentialError("Метаданные SSH-ключа повреждены.");
  }
  return value;
}
export function validateHostCredential(id: string, identity: HostIdentity, requireVerified = true) {
  const credential = readHostCredential(id);
  if (!sameIdentity(credential, identity)) throw credentialError("Этот ключ относится к другому хосту или пользователю. Настройте отдельный ключ для выбранного подключения.", "credential_identity_mismatch");
  if (requireVerified && (!credential.verifiedAt || !existsSync(credentialKeyPath(id)))) throw credentialError("Вход отдельным ключом ещё не подтверждён. Завершите настройку SSH.", "credential_unverified");
  return credential;
}
function writeMetadata(credential: HostCredential) {
  const directory = credentialDirectory(credential.id);
  const temporary = path.join(directory, `${randomUUID()}.tmp`);
  writeFileSync(temporary, JSON.stringify(credential, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  renameSync(temporary, path.join(directory, "metadata.json"));
}
export function beginHostCredential(identity: HostIdentity, existingId?: string | null) {
  if (!validHostIdentity(identity)) throw credentialError("Проверьте имя хоста, адрес, порт и пользователя SSH.", "bad_identity");
  // Deterministic identity lookup; the actual cryptographic key is random and
  // generated only after successful authentication by the SSH helper.
  const id = existingId || createHash("sha256").update(JSON.stringify([identity.alias, identity.address.toLowerCase(), identity.user, identity.port])).digest("hex");
  assertRegularLocation(id);
  mkdirSync(credentialDirectory(id), { recursive: true, mode: 0o700 });
  chmodSync(hostKeysDirectory(), 0o700); chmodSync(credentialDirectory(id), 0o700);
  const lock = path.join(credentialDirectory(id), ".bootstrap-lock");
  try { mkdirSync(lock, { mode: 0o700 }); }
  catch { throw credentialError("Настройка этого хоста уже выполняется. Дождитесь результата.", "credential_busy"); }
  try {
    let credential: HostCredential;
    if (existsSync(path.join(credentialDirectory(id), "metadata.json"))) credential = validateHostCredential(id, identity, false);
    else {
      if (existingId) throw credentialError("Сохранённый ключ отсутствует. Восстановите его из резервной копии.", "credential_missing");
      credential = { ...identity, version: 1, id, createdAt: new Date().toISOString(), verifiedAt: null, publicKey: null, fingerprint: null, sudoReadyAt: null };
      writeMetadata(credential);
    }
    if (credential.verifiedAt && !existsSync(credentialKeyPath(id))) throw credentialError("Сохранённый приватный ключ отсутствует. Восстановите его из резервной копии; повторная настройка не заменяет ключ автоматически.", "credential_missing");
    return { credential, keyPath: credentialKeyPath(id), release: () => rmSync(lock, { recursive: true, force: true }) };
  } catch (error) { rmSync(lock, { recursive: true, force: true }); throw error; }
}
export function markHostCredentialVerified(id: string, identity: HostIdentity, publicKey: string, fingerprint: string) {
  const current = validateHostCredential(id, identity, false);
  if (!/^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?$/.test(publicKey) || !/^SHA256:[A-Za-z0-9+/=]+$/.test(fingerprint) || !existsSync(credentialKeyPath(id))) throw credentialError("Не удалось подтвердить созданный SSH-ключ.");
  chmodSync(credentialKeyPath(id), 0o600);
  const updated = { ...current, publicKey, fingerprint, verifiedAt: new Date().toISOString() };
  writeMetadata(updated);
  return updated;
}
export function markHostCredentialSudoReady(id: string, identity: HostIdentity) {
  const current = validateHostCredential(id, identity);
  const updated = { ...current, sudoReadyAt: new Date().toISOString() };
  writeMetadata(updated);
  return updated;
}
export function isHostCredentialSudoReady(id: string, identity: HostIdentity) {
  return Boolean(validateHostCredential(id, identity).sudoReadyAt);
}
function savedCredentialId(alias: string) {
  const inventory = path.resolve(process.cwd(), "..", "ansible", "inventory.ini");
  if (!existsSync(inventory)) return null;
  let section = "";
  let id: string | null = null;
  for (const raw of readFileSync(inventory, "utf8").split("\n")) {
    const line = raw.trim();
    if (line.startsWith("[")) { section = line; continue; }
    if (!line || line.startsWith("#") || section.includes(":")) continue;
    const [name, ...tokens] = line.split(/\s+/);
    if (name !== alias) continue;
    const value = tokens.find((token) => token.startsWith("hcp_ssh_credential_id="))?.split("=")[1];
    if (value && id && value !== id) throw credentialError("В inventory указаны разные SSH-ключи для одного хоста.");
    if (value) id = value;
  }
  return id;
}
export function connectionPrivateKey(identity: HostIdentity, credentialId?: unknown) {
  if (credentialId !== undefined && credentialId !== null && credentialId !== "") {
    if (typeof credentialId !== "string") throw credentialError("Некорректный идентификатор SSH-ключа.");
    validateHostCredential(credentialId, identity);
    return credentialKeyPath(credentialId);
  }
  const saved = savedCredentialId(identity.alias);
  if (saved) { validateHostCredential(saved, identity); return credentialKeyPath(saved); }
  return configuredPrivateKeyPath();
}
export function publicCredentialSummary(id: string | null) {
  if (!id) return { credentialId: null, credentialFingerprint: null, credentialPublicKey: null, credentialReady: false };
  try {
    const value = readHostCredential(id);
    return { credentialId: id, credentialFingerprint: value.fingerprint, credentialPublicKey: value.publicKey, credentialReady: Boolean(value.verifiedAt && existsSync(credentialKeyPath(id))) };
  } catch { return { credentialId: id, credentialFingerprint: null, credentialPublicKey: null, credentialReady: false }; }
}

export function deleteHostCredential(id: string, identity: HostIdentity) {
  // Read and validate before removal: an inventory mismatch must never delete
  // another host's key material. A credential directory is intentionally
  // narrow and may contain only files created by this module.
  validateHostCredential(id, identity);
  const directory = credentialDirectory(id);
  const allowed = new Set(["id_ed25519", "id_ed25519.pub", "metadata.json"]);
  for (const name of readdirSync(directory)) {
    if (!allowed.has(name)) throw credentialError("Каталог SSH-ключа содержит неожиданный файл. Удалите доступ вручную после проверки хранилища.", "credential_unexpected_content");
    const info = lstatSync(path.join(directory, name));
    if (!info.isFile() || info.isSymbolicLink()) throw credentialError("Файл SSH-ключа имеет недопустимый тип.");
  }
  rmSync(directory, { recursive: true, force: false, maxRetries: 0 });
}

export function acquireHostCredentialCloseoutLock(id: string) {
  // Keep the lock next to, rather than inside, the credential directory: the
  // final local deletion can remain strict about its known contents.
  credentialDirectory(id);
  const lock = path.join(hostKeysDirectory(), `${id}.decommission-lock`);
  const existing = lstatSync(lock, { throwIfNoEntry: false });
  if (existing) throw credentialError("Завершение работ по этому хосту уже выполняется. Дождитесь результата.", "credential_busy");
  try { mkdirSync(lock, { mode: 0o700 }); }
  catch { throw credentialError("Завершение работ по этому хосту уже выполняется. Дождитесь результата.", "credential_busy"); }
  return () => { try { rmSync(lock, { recursive: true, force: true }); } catch { /* no-op */ } };
}
