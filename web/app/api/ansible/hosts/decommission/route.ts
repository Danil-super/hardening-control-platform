import { NextResponse } from "next/server";
import { appendAuditEvent, hasActiveRemediationForHost } from "@/lib/state-store";
import { acquireHostCredentialCloseoutLock, credentialKeyPath, deleteHostCredential, hostCredentialSudoMode, HostCredentialError, validateHostCredential } from "@/lib/host-credentials";
import { readInventoryCloseoutHost, removeInventoryCloseoutHost } from "@/lib/inventory-closeout";
import { revokeHostSshAccess } from "@/lib/ssh-revocation";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function safeAlias(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value) && !["all", "ungrouped"].includes(value);
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alias = body?.alias;
  if (!safeAlias(alias)) return NextResponse.json({ ok: false, message: "Укажите корректный alias хоста." }, { status: 400 });
  if (body?.confirmation !== alias) return NextResponse.json({ ok: false, message: "Для завершения работ введите alias хоста точно как показано." }, { status: 400 });
  if (hasActiveRemediationForHost(alias)) return NextResponse.json({ ok: false, message: "Дождитесь завершения изменения или отката на этом хосте." }, { status: 409 });
  let remoteRevoked = false;
  let release: (() => void) | null = null;
  try {
    const host = readInventoryCloseoutHost(alias);
    if (!host) return NextResponse.json({ ok: false, message: "Хост не найден в inventory." }, { status: 404 });
    if (!host.credentialId) return NextResponse.json({ ok: false, message: "Этот хост использует устаревший или общий ключ. Автоматический отзыв недоступен: удалите соответствующий ключ вручную на цели." }, { status: 409 });
    const identity = { alias: host.alias, address: host.address, port: host.port, user: host.user };
    const credential = validateHostCredential(host.credentialId, identity);
    if (!credential.publicKey || !credential.fingerprint) throw new HostCredentialError("Для этого хоста нет проверенного индивидуального публичного ключа.", "credential_unverified");
    release = acquireHostCredentialCloseoutLock(host.credentialId);
    // Re-read under the lock in case a concurrent host edit changed storage.
    const lockedCredential = validateHostCredential(host.credentialId, identity);
    if (!lockedCredential.publicKey || !lockedCredential.fingerprint) throw new HostCredentialError("Для этого хоста нет проверенного индивидуального публичного ключа.", "credential_unverified");
    appendAuditEvent("host_decommission_started", alias, { alias, address: host.address, port: host.port, user: host.user, credentialId: host.credentialId, fingerprint: credential.fingerprint });
    const sudoMode = hostCredentialSudoMode(host.credentialId, identity);
    await revokeHostSshAccess(identity, { keyPath: credentialKeyPath(host.credentialId), publicKey: lockedCredential.publicKey, credentialId: host.credentialId, sudoMode });
    remoteRevoked = true;
    deleteHostCredential(host.credentialId, identity);
    removeInventoryCloseoutHost(alias);
    appendAuditEvent("host_decommission_completed", alias, { alias, address: host.address, port: host.port, credentialId: host.credentialId, fingerprint: lockedCredential.fingerprint, reportsRetained: true, hostTrustRetained: true });
    return NextResponse.json({ ok: true, message: sudoMode === "on_demand"
      ? "Доступ HCP к хосту отозван: уникальный ключ удалён на цели, локальная пара и строка inventory удалены. HCP не создавала правило sudoers для этого хоста. Отчёты, история и доверенный ключ сервера сохранены."
      : "Доступ HCP к хосту отозван: уникальный ключ и созданное HCP правило sudoers удалены на цели, локальная пара и строка inventory удалены. Отчёты, история и доверенный ключ сервера сохранены." });
  } catch (error) {
    if (error instanceof HostCredentialError && (error as HostCredentialError & { remoteRevoked?: boolean }).remoteRevoked) remoteRevoked = true;
    try { appendAuditEvent("host_decommission_failed", alias, { alias, remoteRevoked, code: error instanceof HostCredentialError ? error.code : "decommission_failed" }); } catch { /* keep the original outcome visible to the operator */ }
    const detail = error instanceof Error ? error.message : "Не удалось завершить работы по хосту.";
    const message = remoteRevoked
      ? `Ключ на цели уже отозван, но локальное завершение не закончено: ${detail} Проверьте inventory и хранилище HCP; отчёты не удалены.`
      : detail;
    return NextResponse.json({ ok: false, message }, { status: 400 });
  } finally { release?.(); }
}
