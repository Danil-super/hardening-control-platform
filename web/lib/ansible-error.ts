export function firewallAccessProblem(text: string): string | null {
  if (/ufw\.lock/i.test(text) && /PermissionError|Permission denied|отказано в доступе/i.test(text)) {
    return "UFW не может открыть /run/ufw.lock: ОС отказала в доступе. На Astra проверьте мандатный уровень целостности административного сеанса: одного sudo может быть недостаточно. Нужен разрешённый контекст управления firewall; отключать защиту или обходить UFW через nftables не требуется.";
  }
  return null;
}

/** Surface Ansible's actual failure; command arguments are not a diagnosis. */
export function ansibleFailureMessage(error: unknown): string {
  const details = error && typeof error === "object" ? error as { stdout?: unknown; stderr?: unknown; message?: unknown } : {};
  const stdout = typeof details.stdout === "string" ? details.stdout : "";
  const stderr = typeof details.stderr === "string" ? details.stderr : "";
  const access = firewallAccessProblem(stdout + "\n" + stderr);
  if (access) return access;
  for (const line of stdout.split("\n")) {
    const failure = /(?:FAILED!|UNREACHABLE!)\s*=>\s*(\{.*\})/.exec(line);
    if (!failure) continue;
    try {
      const payload = JSON.parse(failure[1]);
      try {
        const helper = JSON.parse(payload.stdout ?? "null");
        if (helper?.ok === false && typeof helper.error === "string") return helper.error.slice(0, 1200);
      } catch { /* A regular Ansible failure need not contain a helper result. */ }
      for (const message of [payload.msg, payload.stderr]) {
        if (typeof message === "string" && message.trim()) return message.trim().slice(0, 1200);
      }
    } catch { /* Keep the stderr fallback for another callback format. */ }
  }
  if (stderr.trim()) return stderr.trim().slice(0, 1200);
  if (typeof details.message === "string" && !details.message.startsWith("Command failed:")) return details.message.slice(0, 1200);
  return "Ansible не выполнил операцию. Откройте технические данные результата: там указана причина отказа на хосте.";
}
