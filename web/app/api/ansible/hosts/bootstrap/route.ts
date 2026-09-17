import { NextResponse } from "next/server";
import { HostCredentialError, beginHostCredential, markHostCredentialSudoReady, markHostCredentialVerified, validHostIdentity, type HostIdentity } from "@/lib/host-credentials";
import { normalizeSshPort } from "@/lib/ssh-access";
import { credentialTransportAllowed, readCredentialRequest, runSshBootstrap } from "@/lib/ssh-bootstrap";
import { appendIncident } from "@/lib/ansible-control";
import { hasActiveRemediationForHost } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 240;
const response = (body: object, status = 200) => NextResponse.json(body, { status, headers: { "Cache-Control": "no-store" } });
const sudoFailureMessages: Record<string, string> = {
  sudo_elevation_rejected_or_policy: "Вход по отдельному ключу подтверждён, но Astra не приняла одноразовое повышение прав sudo. Проверьте пароль sudo (он может отличаться от SSH) и политику этой учётной записи; пароль не сохранён.",
  sudoers_unavailable: "Вход по отдельному ключу подтверждён, но на Astra недоступны visudo или каталог /etc/sudoers.d. HCP не изменял правила sudo; проверьте конфигурацию этой Astra.",
  sudoers_validation_failed: "Вход по отдельному ключу подтверждён, но Astra не подтвердила синтаксис или действующую конфигурацию sudoers. HCP не оставил неподтверждённое правило.",
  sudoers_rule_conflict: "Вход по отдельному ключу подтверждён, но существующее правило HCP для этого подключения имеет неожиданный вид. Оно не заменено автоматически; проверьте его через доверенную консоль.",
  sudo_rule_not_effective: "Вход по отдельному ключу подтверждён, но после настройки Astra всё ещё не разрешает non-interactive sudo. Проверьте политику sudo, PAM или PARSEC для этой учётной записи.",
  sudo_ansible_probe_failed: "Вход по отдельному ключу подтверждён, но Astra не разрешает тот же non-interactive sudo-запуск, который нужен Ansible для аудита. HCP не запускает аудит до исправления этой политики.",
  sudo_setup_failed: "Вход по отдельному ключу подтверждён, но Astra не разрешила завершить автоматическую настройку sudo. Пароль не сохранён. Повторите подключение; если пароль sudo отличается от SSH, укажите его в дополнительном поле.",
  sudo_check_failed: "Вход по отдельному ключу подтверждён, но Astra всё ещё не разрешает non-interactive sudo. Проверьте политику sudo для этой учётной записи.",
};

export async function POST(request: Request) {
  if (!credentialTransportAllowed(request)) return response({ ok: false, error: "secure_transport_required",
    message: "Для ввода SSH-пароля откройте HCP через HTTPS либо http://127.0.0.1 на самой Ubuntu. Пароли не отправляются через обычный HTTP по сети." }, 400);
  let release: (() => void) | undefined;
  let body: Record<string, unknown> | undefined;
  try {
    body = await readCredentialRequest(request);
    const identity: HostIdentity = { alias: String(body?.alias ?? "").trim(), address: String(body?.address ?? "").trim(),
      user: String(body?.user ?? "").trim(), port: normalizeSshPort(body?.port) ?? 0 };
    if (!validHostIdentity(identity)) return response({ ok: false, message: "Укажите корректные имя хоста, адрес, порт и пользователя SSH." }, 400);
    const password = typeof body?.password === "string" ? body.password : "";
    const sudoPassword = typeof body?.sudoPassword === "string" ? body.sudoPassword : "";
    if ([password, sudoPassword].some((value) => value.length > 1024 || /[\r\n\0]/.test(value))) return response({ ok: false, message: "Пароль должен быть одной строкой длиной до 1024 символов." }, 400);
    const configureSudo = body?.configureSudo === true;
    if (configureSudo && body?.confirmRootAccess !== true) return response({ ok: false, message: "Подтвердите выдачу этой учётной записи полных прав root без пароля." }, 400);
    if (configureSudo && !password && !sudoPassword) return response({ ok: false, message: "Для настройки повышения прав введите пароль администратора Astra." }, 400);
    if (hasActiveRemediationForHost(identity.alias)) return response({ ok: false, message: "Дождитесь завершения изменения или отката на этом хосте." }, 409);
    const existingId = typeof body?.credentialId === "string" ? body.credentialId : null;
    const prepared = beginHostCredential(identity, existingId);
    release = prepared.release;
    const result = await runSshBootstrap(identity, { credentialId: prepared.credential.id, keyPath: prepared.keyPath, password, sudoPassword, configureSudo });
    const credential = markHostCredentialVerified(prepared.credential.id, identity, result.publicKey!, result.fingerprint!);
    if (configureSudo && !result.sudo?.ready) {
      const candidate = result.sudo?.error ?? "sudo_setup_failed";
      const error = candidate in sudoFailureMessages ? candidate : "sudo_setup_failed";
      appendIncident({ action: "ssh-key-enrollment", kind: "system", status: "failed", profileId: "ssh-access", limit: identity.alias,
        message: `Отдельный ключ ${credential.fingerprint} установлен для ${identity.alias}, но автоматическая подготовка sudo не завершилась (${error}).` });
      return response({ ok: false, error, credentialId: credential.id, publicKey: credential.publicKey, fingerprint: credential.fingerprint, sudo: result.sudo,
        message: sudoFailureMessages[error] }, 400);
    }
    if (configureSudo && result.sudo?.ready) markHostCredentialSudoReady(credential.id, identity);
    appendIncident({ action: "ssh-key-enrollment", kind: "system", status: "success", profileId: "ssh-access", limit: identity.alias,
      message: `Отдельный ключ ${credential.fingerprint} установлен для ${identity.alias}; вход проверен. Настройка sudo запрошена: ${configureSudo ? "да" : "нет"}; sudo готово: ${result.sudo?.ready ? "да" : "нет"}.` });
    return response({ ok: true, credentialId: credential.id, publicKey: credential.publicKey, fingerprint: credential.fingerprint,
      sudo: result.sudo, message: result.sudo?.requested && !result.sudo.ready
        ? "Отдельный ключ установлен, вход по нему проверен. Настроить sudo не удалось: проверьте пароль sudo, права учётной записи и политику Astra."
        : "Отдельный ключ установлен, вход по нему проверен. Пароль не сохранён. Выполняется проверка готовности хоста." });
  } catch (error) {
    const failure = error instanceof HostCredentialError ? error : null;
    // Only explicit, sanitized errors from our modules reach the client.
    return response({ ok: false, error: failure?.code ?? "ssh_setup_failed", message: failure ? failure.message : "Не удалось настроить SSH. Пароль не сохранён; повторите попытку после проверки доступа." }, failure?.code === "credential_busy" ? 409 : 400);
  } finally {
    if (body) { delete body.password; delete body.sudoPassword; }
    release?.();
  }
}
