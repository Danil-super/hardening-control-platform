import { lstatSync } from "node:fs";
import { appendAuditEvent, claimHostCloseout, getHostCloseout, hasActiveRemediationForHost, latestHostCloseout,
  recordHostCloseoutResult, releaseHostCloseout, type HostCloseoutRecord } from "@/lib/state-store";
import { acquireHostCredentialCloseoutLock, credentialDirectory, credentialKeyPath, deleteHostCredential,
  hasHostCredentialCloseoutLock, hostCredentialSudoMode, releaseInterruptedHostCloseoutLock, validateHostCredential, type HostIdentity } from "@/lib/host-credentials";
import { readInventoryCloseoutHost, removeInventoryCloseoutHost } from "@/lib/inventory-closeout";
import { revokeHostSshAccess } from "@/lib/ssh-revocation";
import { operationOwnerState, type RecoveryAttestation } from "@/lib/operation-owner";

const failure = (message: string, code: string) => Object.assign(new Error(message), { code });
function identityOf(host: HostIdentity): HostIdentity {
  return { alias: host.alias, address: host.address, user: host.user, port: host.port };
}
function assertNoRemediation(alias: string) {
  if (hasActiveRemediationForHost(alias)) throw failure("Сначала завершите изменение или восстановление firewall на хосте.", "host_operation_active");
}
function completeLocal(record: HostCloseoutRecord) {
  const inventory = readInventoryCloseoutHost(record.identity.alias);
  if (inventory && (inventory.credentialId !== record.credentialId || JSON.stringify(identityOf(inventory)) !== JSON.stringify(record.identity))) {
    throw failure("Inventory изменился после начала отзыва; другая запись и ключ не удалены.", "credential_identity_mismatch");
  }
  if (lstatSync(credentialDirectory(record.credentialId), { throwIfNoEntry: false })) deleteHostCredential(record.credentialId, record.identity, record.fingerprint);
  if (inventory) removeInventoryCloseoutHost(record.identity.alias);
  recordHostCloseoutResult(record.credentialId, record.claim!, "completed");
  appendAuditEvent("host_decommission_completed", record.identity.alias, { ...record.identity, credentialId: record.credentialId,
    fingerprint: record.fingerprint, reportsRetained: true, hostTrustRetained: true });
}

export function hostCloseoutStatus(alias: string) {
  const host = readInventoryCloseoutHost(alias);
  const record = host?.credentialId ? getHostCloseout(host.credentialId) : latestHostCloseout(alias);
  const id = host?.credentialId ?? record?.credentialId ?? null;
  const locked = Boolean(id && hasHostCredentialCloseoutLock(id));
  return { credentialId: id, status: record?.status ?? null,
    recoveryVersion: record?.recoveryVersion ?? (id && (record || locked) ? `legacy-closeout:${id}` : null),
    recoveryRequired: Boolean(record && !["not_changed", "completed"].includes(record.status) || locked),
    ownerLive: Boolean(record?.claim && operationOwnerState(record.owner) === "live") };
}

export async function decommissionHost(alias: string) {
  assertNoRemediation(alias);
  const host = readInventoryCloseoutHost(alias);
  if (!host?.credentialId) throw failure("Нет индивидуального ключа в inventory. Общий ключ отзывается вручную.", "credential_missing");
  const identity = identityOf(host);
  const credential = validateHostCredential(host.credentialId, identity);
  if (!credential.publicKey || !credential.fingerprint) throw failure("Нет проверенного публичного ключа.", "credential_unverified");
  if (hasHostCredentialCloseoutLock(host.credentialId)) throw failure("Предыдущий отзыв доступа требует сверки; его блокировка сохранена.", "closeout_recovery_required");
  const record = claimHostCloseout({ credentialId: host.credentialId, identity, fingerprint: credential.fingerprint });
  let release: (() => void) | undefined;
  let remoteStarted = false;
  let remoteComplete = false;
  try {
    release = acquireHostCredentialCloseoutLock(record.credentialId);
    const lockedCredential = validateHostCredential(record.credentialId, identity);
    if (lockedCredential.fingerprint !== record.fingerprint || !lockedCredential.publicKey) throw failure("SSH-ключ изменился после начала отзыва.", "credential_identity_mismatch");
    const sudoMode = hostCredentialSudoMode(record.credentialId, identity);
    remoteStarted = true;
    await revokeHostSshAccess(identity, { keyPath: credentialKeyPath(record.credentialId), publicKey: lockedCredential.publicKey!,
      credentialId: record.credentialId, sudoMode });
    remoteComplete = true;
    recordHostCloseoutResult(record.credentialId, record.claim!, "remote_revoked");
    completeLocal(record);
    return { ok: true, message: "Доступ отозван, локальная пара и строка inventory удалены. Отчёты и журнал сохранены." };
  } catch (error) {
    const remoteEvidence = error && typeof error === "object" && "remoteRevoked" in error && typeof error.remoteRevoked === "boolean" ? error.remoteRevoked : undefined;
    const keyRemoved = remoteComplete || remoteEvidence === true;
    const detail = error instanceof Error ? error.message : "Результат отзыва не подтверждён.";
    const unchanged = !remoteStarted || remoteEvidence === false;
    recordHostCloseoutResult(record.credentialId, record.claim!, remoteComplete ? "remote_revoked" : keyRemoved ? "remote_partial" : unchanged ? "not_changed" : "unknown", detail);
    if (unchanged) throw error;
    throw Object.assign(new Error(keyRemoved ? `Ключ на цели уже отозван. Завершите ручную сверку оставшихся шагов: ${detail}` : `${detail} Перед повтором требуется сверка состояния цели.`),
      { code: "closeout_recovery_required", ...(keyRemoved ? { remoteRevoked: true } : {}), credentialId: record.credentialId });
  } finally {
    release?.();
    releaseHostCloseout(record.credentialId, record.claim!);
  }
}

export function recoverHostCloseout(alias: string, credentialId: string, input: RecoveryAttestation & {
  resolution?: unknown; remoteKeyAbsent?: unknown; sudoRuleResolved?: unknown;
}) {
  assertNoRemediation(alias);
  const previous = getHostCloseout(credentialId);
  const host = readInventoryCloseoutHost(alias);
  if (!previous && !hasHostCredentialCloseoutLock(credentialId)) throw failure("Нет прерванной операции отзыва, ожидающей сверки.", "recovery_not_available");
  if (previous?.identity.alias !== alias && (!host || host.credentialId !== credentialId)) throw failure("Операция не относится к этому хосту.", "credential_identity_mismatch");
  const identity = previous?.identity ?? identityOf(host!);
  const fingerprint = previous?.fingerprint ?? validateHostCredential(credentialId, identity, false).fingerprint;
  if (!fingerprint) throw failure("Не найдена сохранённая идентичность ключа.", "credential_unverified");
  if (!["remote_absent", "not_changed"].includes(String(input.resolution))) throw failure("Укажите проверенный результат отзыва.", "recovery_resolution_invalid");
  if (input.resolution === "remote_absent" && (input.remoteKeyAbsent !== true || input.sudoRuleResolved !== true)) {
    throw failure("Через независимый доступ проверьте отсутствие ключа HCP и состояние его правила sudoers.", "recovery_inspection_required");
  }
  if (input.resolution === "not_changed" && previous && ["remote_revoked", "remote_partial", "completed"].includes(previous.status)) {
    throw failure("Уже зафиксировано удаление ключа. Нельзя объявить эту операцию неизменившей хост.", "recovery_resolution_invalid");
  }
  const record = claimHostCloseout({ credentialId, identity, fingerprint }, input);
  let release: (() => void) | undefined;
  try {
    releaseInterruptedHostCloseoutLock(credentialId);
    release = acquireHostCredentialCloseoutLock(credentialId);
    if (input.resolution === "not_changed") {
      recordHostCloseoutResult(credentialId, record.claim!, "not_changed");
      return { ok: true, completed: false, message: "Отсутствие изменений подтверждено оператором и записано в журнал. Новый отзыв запускается отдельно." };
    }
    recordHostCloseoutResult(credentialId, record.claim!, "remote_revoked");
    completeLocal(record);
    return { ok: true, completed: true, message: "Подтверждённое завершение отзыва записано; локальные данные доступа удалены. Отчёты сохранены." };
  } catch (error) {
    // Preserve the known remote outcome if local cleanup needs another attempt.
    const current = getHostCloseout(credentialId);
    recordHostCloseoutResult(credentialId, record.claim!, current?.status ?? "unknown", error instanceof Error ? error.message : "Не удалось завершить восстановление.");
    throw error;
  } finally { release?.(); releaseHostCloseout(credentialId, record.claim!); }
}
