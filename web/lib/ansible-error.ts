export function firewallAccessProblem(text: string): string | null {
  if (/ufw\.lock/i.test(text) && /PermissionError|Permission denied|отказано в доступе/i.test(text)) {
    return "UFW не может открыть /run/ufw.lock: ОС отказала в доступе. На Astra проверьте мандатный уровень целостности административного сеанса: одного sudo может быть недостаточно. Нужен разрешённый контекст управления firewall; отключать защиту или обходить UFW через nftables не требуется.";
  }
  return null;
}

export type AnsibleExecutionOutcome = "not_started" | "completed" | "unknown";

/** A local child exit alone does not prove that its remote command stopped. */
export function classifyAnsibleExecutionError(error: unknown, spawned: boolean): AnsibleExecutionOutcome {
  if (!spawned) return "not_started";
  const details = error && typeof error === "object"
    ? error as { code?: unknown; killed?: unknown; signal?: unknown; stdout?: unknown; stderr?: unknown }
    : {};
  if (details.killed || details.signal || details.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return "unknown";
  const stdout = typeof details.stdout === "string" ? details.stdout : "";
  const stderr = typeof details.stderr === "string" ? details.stderr : "";
  // Ansible can also finish normally after losing SSH while the helper is
  // still running. Native backend timeouts have the same uncertainty.
  if (/UNREACHABLE!|connection (?:reset|closed|timed out)|broken pipe|timed? ?out|TimeoutExpired|TimeoutException/i.test(stdout + "\n" + stderr)) return "unknown";
  let completedFailures = 0;
  for (const line of stdout.split("\n")) {
    const failure = /FAILED!\s*=>\s*(\{.*\})/.exec(line);
    if (line.includes("FAILED!") && !failure) return "unknown";
    if (!failure) continue;
    try {
      const payload = JSON.parse(failure[1]);
      const helper = payload.stdout ? JSON.parse(payload.stdout) : null;
      if (helper?.outcomeUnknown === true) return "unknown";
      // The command module can report a killed/crashed remote Python helper
      // as FAILED (not UNREACHABLE). Its descendants may still be executing.
      // A FAILED response without rc also occurs when Ansible's task timer
      // interrupts its action plugin. Its final recap does not establish that
      // the remote command stopped. Require the native helper's exit evidence.
      if (!Number.isSafeInteger(payload.rc) || payload.rc < 0 || typeof helper?.ok !== "boolean") return "unknown";
      completedFailures++;
    } catch { return "unknown"; }
  }
  // With the default Ansible callback, a completed task failure has rc=2
  // and a final recap. Do not infer completion from a crash, partial output,
  // an unfamiliar callback or an unreachable target.
  const recap = stdout.split(/^PLAY RECAP \*+\s*$/m).at(-1) ?? "";
  const hosts = [...recap.matchAll(/^\S+\s+:\s+ok=\d+\s+changed=\d+\s+unreachable=(\d+)\s+failed=(\d+)\b.*$/gm)];
  if (details.code === 2 && completedFailures > 0 && recap !== stdout && hosts.length && hosts.every((host) => host[1] === "0")) return "completed";
  return "unknown";
}

/** Missing execution evidence must not release a mutating operation's lock. */
export function ansibleOutcomeIsUnknown(error: unknown) {
  const outcome = error && typeof error === "object" ? (error as { remoteOutcome?: unknown }).remoteOutcome : undefined;
  return outcome !== "not_started" && outcome !== "completed";
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
