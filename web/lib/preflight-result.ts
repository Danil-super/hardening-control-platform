export type PreflightCheck = {
  ok: boolean;
  state: "passed" | "failed" | "skipped" | "disabled";
  message: string;
  details?: string;
};

type Probe = { ok: boolean; stdout: string; stderr: string };

export function explainConnectionFailure(stage: "ssh" | "python" | "sudo", details: string) {
  if (stage === "ssh") {
    if (/REMOTE HOST IDENTIFICATION HAS CHANGED|host key.*changed/i.test(details)) {
      return "Ключ сервера изменился. Сверьте его с администратором Astra; сохранённое доверие автоматически не заменяется.";
    }
    if (/No .* host key is known|Host key verification failed/i.test(details)) {
      return "Ключ сервера не подтверждён. В форме добавления найдите «Подтверждение сервера», вставьте отпечаток из доверенной консоли Astra и нажмите «Подтвердить сервер».";
    }
    if (/Permission denied.*publickey|Authentication failed/i.test(details)) {
      return "SSH не принял ключ платформы. Проверьте пользователя в форме и его authorized_keys на Astra.";
    }
    if (/Connection refused|timed out|No route to host|unreachable/i.test(details)) {
      return "Нет SSH-подключения. Проверьте адрес, порт и доступность Astra из контейнера HCP.";
    }
    return "SSH-подключение не установлено. Откройте технические подробности и сверяйтесь с единой инструкцией.";
  }
  if (stage === "sudo") {
    if (/Missing sudo password|a password is required|no password was provided/i.test(details)) {
      return "sudo требует пароль. Администратор Astra должен настроить доступ для пользователя SSH по инструкции в блоке «Первое подключение по SSH». Затем повторите проверку.";
    }
    if (/not in the sudoers|not allowed to execute|not allowed to run sudo/i.test(details)) {
      return "Пользователю SSH не разрешён этот запуск через sudo. Права на Astra должен настроить её администратор.";
    }
    if (/sudo(?::|[^\n]*:)\s*(?:command )?not found|sudo: command not found/i.test(details)) {
      return "sudo не найден на Astra. Администратор должен установить его и настроить права пользователя SSH.";
    }
    return "Не удалось выполнить модуль Ansible с правами root. Проверьте sudoers, PAM и политику доступа Astra по техническим подробностям.";
  }
  return "Не удалось выполнить модуль Ansible через /usr/bin/python3. Проверьте версию Python, доступ и подробности ошибки.";
}

function failed(stage: "ssh" | "python" | "sudo", probe: Probe): PreflightCheck {
  const details = [probe.stderr, probe.stdout].filter(Boolean).join("\n");
  return { ok: false, state: "failed", message: explainConnectionFailure(stage, details), details: details.slice(0, 16000) };
}

const skipped = (message: string): PreflightCheck => ({ ok: false, state: "skipped", message });
const passed = (message: string): PreflightCheck => ({ ok: true, state: "passed", message });

/** Dependent checks cannot appear to fail or pass when they never ran. */
export function summarizePreflight({ ssh, setup, sudo, become, os, pythonMessage }: {
  ssh: Probe; setup: Probe; sudo: Probe; become: boolean; os: string | null; pythonMessage: string;
}) {
  const checks = {
    ssh: ssh.ok ? passed("SSH-подключение установлено.") : failed("ssh", ssh),
    python: !ssh.ok ? skipped("Сначала требуется рабочее SSH-подключение.")
      : setup.ok ? passed(pythonMessage) : failed("python", setup),
    sudo: !become ? { ok: true, state: "disabled", message: "Повышение прав отключено. Используются права пользователя SSH." } as PreflightCheck
      : !ssh.ok || !setup.ok ? skipped("Сначала должны пройти SSH и проверка Python.")
      : sudo.ok ? passed("Модуль Ansible выполнен с правами root без ввода пароля.") : failed("sudo", sudo),
    os: !setup.ok ? skipped("ОС будет определена после проверки SSH и Python.")
      : os ? passed(os) : skipped("Ansible не вернул название ОС."),
  };
  const ok = ssh.ok && setup.ok && (!become || sudo.ok);
  return {
    ok,
    message: ok ? become ? "Подключение и повышение прав проверены. Можно сохранить хост."
      : "Подключение проверено без sudo. Доступ к данным ограничен правами пользователя SSH."
      : [checks.ssh, checks.python, checks.sudo].find((check) => check.state === "failed")?.message ?? "Проверка подключения не завершена.",
    checks,
  };
}
