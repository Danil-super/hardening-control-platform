import { spawn } from "node:child_process";
import path from "node:path";
import { getKnownHostsPath } from "@/lib/ssh-access";
import { credentialError, type HostIdentity } from "@/lib/host-credentials";

const messages: Record<string, string> = {
  host_not_trusted: "Для безопасного отзыва доступа в HCP должен сохраняться проверенный ключ SSH-сервера.",
  host_key_changed: "Ключ SSH-сервера изменился. Сначала проверьте подлинность хоста; доступ и локальный ключ не удалены.",
  key_auth_failed: "Хост отклонил отдельный ключ HCP. Доступ и локальный ключ не удалены.",
  ssh_timeout: "Хост не ответил вовремя. Доступ и локальный ключ не удалены.",
  ssh_dependency_missing: "Компонент SSH HCP отсутствует. Пересоберите контейнер из актуального Dockerfile.",
  sudo_required: "Для отзыва ключа нужен SSH-пользователь root или беспарольный sudo. Доступ и локальный ключ не удалены.",
  unsafe_authorized_keys: "Файл authorized_keys имеет небезопасный тип или изменился во время операции. Доступ и локальный ключ не удалены.",
  key_not_present: "Уникальный ключ HCP не найден в authorized_keys. Ничего локально не удалено: проверьте хост вручную.",
  credential_busy: "На хосте уже выполняется операция с ключом. Повторите завершение работ позже.",
  revocation_failed: "Не удалось подтвердить отзыв ключа на хосте. Доступ и локальный ключ не удалены.",
};

export async function revokeHostSshAccess(identity: HostIdentity, input: { keyPath: string; publicKey: string }) {
  return new Promise<void>((resolve, reject) => {
    const script = path.join(process.cwd(), "..", "ansible", "scripts", "hcp-ssh-revoke.py");
    const child = spawn("/usr/bin/python3", [script], { stdio: ["pipe", "pipe", "pipe"] });
    let output = "";
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, 75_000);
    child.stdout.on("data", (chunk) => { output += chunk.toString(); if (output.length > 65536) child.kill("SIGKILL"); });
    child.stderr.on("data", () => { /* remote diagnostics are deliberately not exposed */ });
    child.stdin.on("error", () => {});
    child.on("error", () => { clearTimeout(timer); reject(credentialError(messages.ssh_dependency_missing, "ssh_dependency_missing")); });
    child.on("close", () => {
      clearTimeout(timer);
      if (timedOut) { reject(credentialError(messages.ssh_timeout, "ssh_timeout")); return; }
      try {
        const result = JSON.parse(output) as { ok?: boolean; error?: string; status?: string };
        if (!result.ok || result.status !== "removed") {
          const code = typeof result.error === "string" && result.error in messages ? result.error : "revocation_failed";
          reject(credentialError(messages[code], code));
        } else resolve();
      } catch { reject(credentialError(messages.revocation_failed, "revocation_failed")); }
    });
    child.stdin.end(JSON.stringify({ ...identity, keyPath: input.keyPath, publicKey: input.publicKey, knownHostsPath: getKnownHostsPath() }));
  });
}
