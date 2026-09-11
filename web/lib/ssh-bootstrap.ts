import { spawn } from "node:child_process";
import path from "node:path";
import { getKnownHostsPath } from "@/lib/ssh-access";
import { credentialError, type HostIdentity } from "@/lib/host-credentials";

export function credentialTransportAllowed(request: Request) {
  let origin: URL;
  try { origin = new URL(request.headers.get("origin") ?? ""); } catch { return false; }
  const url = new URL(request.url);
  if (origin.protocol === "https:" && (url.protocol === "https:" ||
    (process.env.HCP_TRUSTED_TLS_PROXY === "true" && request.headers.get("x-forwarded-proto") === "https"))) return true;
  const loopback = (name: string) => ["localhost", "127.0.0.1", "[::1]", "::1"].includes(name);
  // Next's request URL can contain the container bind address (0.0.0.0).
  // Host identifies the browser's authority; proxy.ts independently checks
  // the session and matching Origin before reaching this route.
  let authority: URL;
  try { authority = new URL("http://" + (request.headers.get("host") ?? url.host)); }
  catch { return false; }
  return origin.protocol === "http:" && loopback(origin.hostname) && loopback(authority.hostname);
}
export async function readCredentialRequest(request: Request) {
  const reader = request.body?.getReader();
  if (!reader) throw credentialError("Заполните параметры подключения.", "bad_request");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 16384) { await reader.cancel(); throw credentialError("Слишком большой запрос.", "bad_request"); }
      chunks.push(value);
    }
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("bad request");
    return value as Record<string, unknown>;
  } catch { throw credentialError("Проверьте данные подключения.", "bad_request"); }
}
export const bootstrapMessages: Record<string, string> = {
  host_not_trusted: "Сначала подтвердите ключ сервера по отпечатку из доверенной консоли. Пароль этому серверу не передан.",
  host_key_changed: "Ключ сервера изменился. Сверьте адрес и отпечаток с администратором; пароль не отправлен.",
  password_required: "Для первого подключения укажите пароль пользователя SSH.",
  password_rejected: "Сервер отклонил пароль. Проверьте пользователя и пароль; на Astra должен быть разрешён парольный вход по SSH.",
  key_generation_failed: "Не удалось создать ключ на управляющем сервере. Проверьте свободное место и права хранилища HCP.",
  key_invalid: "Сохранённый ключ повреждён. Восстановите его из резервной копии.",
  key_install_failed: "Вход по паролю выполнен, но публичный ключ не установлен. Проверьте права пользователя на его .ssh/authorized_keys и отсутствие параллельной настройки.",
  key_login_failed: "Публичный ключ установлен, но вход по нему не прошёл. Проверьте PubkeyAuthentication, AuthorizedKeysFile и политику Astra. Повторная попытка использует ту же пару.",
  ssh_dependency_missing: "Компонент парольного SSH отсутствует в HCP. Пересоберите контейнер из обновлённого Dockerfile.",
  ssh_timeout: "Сервер не ответил вовремя. Проверьте доступность SSH; повторная попытка продолжит настройку с тем же ключом.",
  ssh_setup_failed: "Настройка SSH не завершена. Проверьте адрес, порт, доступность SSH и политику Astra. Пароль не сохранён.",
};
export type BootstrapResult = {
  ok: boolean; error?: string; publicKey?: string; fingerprint?: string;
  sudo?: { requested: boolean; ready: boolean; configured: boolean; error?: string };
};
export function runSshBootstrap(identity: HostIdentity, options: {
  credentialId: string; keyPath: string; password: string; sudoPassword: string; configureSudo: boolean;
}): Promise<BootstrapResult> {
  return new Promise((resolve, reject) => {
    const script = path.join(process.cwd(), "..", "ansible", "scripts", "hcp-ssh-bootstrap.py");
    // Use distro Python: Docker installs Paramiko from the distro repositories.
    const child = spawn("/usr/bin/python3", [script], { stdio: ["pipe", "pipe", "pipe"] });
    let output = "";
    let expired = false;
    const timer = setTimeout(() => { expired = true; child.kill("SIGKILL"); }, 180_000);
    child.stdout.on("data", (chunk) => { output += chunk.toString(); if (output.length > 65536) child.kill("SIGKILL"); });
    child.stderr.on("data", () => { /* Never echo a subprocess exception or remote content into logs. */ });
    child.stdin.on("error", () => {});
    child.on("error", () => { clearTimeout(timer); reject(credentialError(bootstrapMessages.ssh_dependency_missing, "ssh_dependency_missing")); });
    child.on("close", () => {
      clearTimeout(timer);
      if (expired) { reject(credentialError(bootstrapMessages.ssh_timeout, "ssh_timeout")); return; }
      try {
        const result = JSON.parse(output);
        if (!result.ok) {
          const code = typeof result.error === "string" && result.error in bootstrapMessages ? result.error : "ssh_setup_failed";
          reject(credentialError(bootstrapMessages[code], code));
        } else resolve(result);
      } catch { reject(credentialError(bootstrapMessages.ssh_setup_failed, "ssh_setup_failed")); }
    });
    // Secrets exist only in this request and anonymous pipes. No environment
    // variable, command-line argument, temporary file or report contains them.
    child.stdin.end(JSON.stringify({ ...identity, ...options, knownHostsPath: getKnownHostsPath() }));
  });
}
