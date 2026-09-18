import { execFile } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { NextResponse } from "next/server";
import { getRepoRoot } from "@/lib/ansible-control";
import { ansibleSshArgs, configuredPrivateKeyPath, isSafeSshHostAddress, normalizeSshPort } from "@/lib/ssh-access";
import { assessHostReadiness, assessTargetPython, type HostReadiness } from "@/lib/host-readiness";
import { connectionPrivateKey, hostCredentialSudoMode, HostCredentialError, isHostCredentialSudoReady } from "@/lib/host-credentials";
import { readInventoryCloseoutHost } from "@/lib/inventory-closeout";
import { summarizePreflight } from "@/lib/preflight-result";
import { credentialTransportAllowed } from "@/lib/ssh-bootstrap";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const execFileAsync = promisify(execFile);

function isSafeAlias(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value) && !["all", "ungrouped", "preflight"].includes(value);
}

function isSafeSshUser(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value);
}

function redactSecret(value: string | undefined, secret: string) {
  return secret && value ? value.split(secret).join("[скрыто]") : value ?? "";
}

async function runAnsible(args: string[], inventoryPath: string, stage: string, becomePassword = "") {
  const resultDir = path.join(path.dirname(inventoryPath), stage);
  let secretDirectory = "";
  try {
    const secretArgs: string[] = [];
    if (becomePassword) {
      secretDirectory = mkdtempSync(path.join(path.dirname(inventoryPath), "hcp-become-"));
      chmodSync(secretDirectory, 0o700);
      const secretFile = path.join(secretDirectory, "vars.json");
      // Ansible reads this protected file only for the running child process.
      // The sudo password never appears in argv, an environment variable,
      // reports, inventory or HCP persistent state.
      writeFileSync(secretFile, JSON.stringify({ ansible_become_password: becomePassword }), { mode: 0o600 });
      secretArgs.push("--extra-vars", `@${secretFile}`);
    }
    const result = await execFileAsync("ansible", ["-i", inventoryPath, ...secretArgs, "--tree", resultDir, ...args], {
      cwd: getRepoRoot(),
      timeout: 60_000,
      maxBuffer: 1024 * 1024 * 4,
      // Some hardened Astra policies require a terminal for sudo.  Request a
      // TTY only for the password-bearing elevated step; SSH/key/Python
      // probes stay non-interactive.
      env: { ...process.env, ANSIBLE_FORCE_COLOR: "false", ANSIBLE_PIPELINING: "False", ANSIBLE_SSH_ARGS: `${ansibleSshArgs()}${becomePassword ? " -tt" : ""}`, ANSIBLE_PRIVATE_KEY_FILE: configuredPrivateKeyPath() },
    });
    const data = JSON.parse(readFileSync(path.join(resultDir, args[0]), "utf8"));
    return { ok: data.failed !== true && data.unreachable !== true, stdout: redactSecret(result.stdout, becomePassword), stderr: redactSecret(result.stderr, becomePassword), data };
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string };
    return {
      ok: false,
      stdout: redactSecret(output.stdout, becomePassword),
      stderr: redactSecret(output.stderr ?? output.message, becomePassword),
      data: null,
    };
  } finally {
    if (secretDirectory) rmSync(secretDirectory, { recursive: true, force: true });
  }
}

function sameInventoryConnection(host: { alias: string; address: string; user: string; port: number; credentialId: string | null }, identity: {
  alias: string; address: string; user: string; port: number; credentialId: string | null;
}) {
  return host.alias === identity.alias && host.address.toLowerCase() === identity.address.toLowerCase()
    && host.user === identity.user && host.port === identity.port && host.credentialId === identity.credentialId;
}

function incompleteSudoResponse() {
  return NextResponse.json({ ok: false, error: "sudo_setup_incomplete",
    message: "SSH-ключ создан, но HCP ещё не подтвердил постоянные права администратора. Введите пароль в форме подключения и нажмите «Подключить хост»; Ansible-проверка не запускалась." }, { status: 409 });
}

function sudoPasswordRequiredResponse() {
  return NextResponse.json({ ok: false, error: "sudo_password_required",
    message: "Для этого хоста Astra разрешает sudo по паролю. Введите пароль sudo для разовой проверки; HCP не сохраняет его и не меняет sudoers." }, { status: 409 });
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alias = typeof body?.alias === "string" ? body.alias.trim() : "";
  const address = typeof body?.address === "string" ? body.address.trim() : "";
  const user = typeof body?.user === "string" ? body.user.trim() : "";
  const port = normalizeSshPort(body?.port);
  const become = typeof body?.become === "boolean" ? body.become : true;
  const credentialId = typeof body?.credentialId === "string" && body.credentialId ? body.credentialId : null;
  const sudoPassword = typeof body?.sudoPassword === "string" ? body.sudoPassword : "";

  if (typeof body?.sudoPassword !== "undefined" && (typeof body?.sudoPassword !== "string" || sudoPassword.length > 1024 || /[\r\n\0]/.test(sudoPassword))) {
    return NextResponse.json({ ok: false, message: "Пароль sudo должен быть одной строкой длиной до 1024 символов." }, { status: 400 });
  }
  if (sudoPassword && !credentialTransportAllowed(request)) {
    return NextResponse.json({ ok: false, error: "secure_transport_required",
      message: "Для пароля sudo откройте HCP через HTTPS либо http://127.0.0.1 на управляющей Ubuntu. Пароль не отправляется через обычный HTTP по сети." }, { status: 400 });
  }
  if (body && typeof body === "object") delete body.sudoPassword;

  if (!isSafeAlias(alias) || !isSafeSshHostAddress(address) || !isSafeSshUser(user) || port === null) {
    return NextResponse.json(
      { ok: false, message: "Проверьте alias, IP/hostname, SSH-порт и пользователя." },
      { status: 400 },
    );
  }

  // This is enforced server-side as well as in the browser.  A cached old UI
  // or direct request must never jump from an SSH-only credential straight to
  // an Ansible `sudo -n` attempt.  Existing inventory hosts remain compatible
  // with credentials created before this status was recorded.
  let resolvedCredentialId = credentialId;
  let onDemandSudo = false;
  if (become && user !== "root") {
    try {
      const inventoryHost = readInventoryCloseoutHost(alias);
      if (inventoryHost) {
        // Existing connections can be checked by older callers that do not
        // send the credential id.  In that case bind the request to the
        // already saved id before comparing it.  An explicitly supplied
        // foreign id still produces a conflict and can never select another
        // host's key.
        const comparedCredentialId = credentialId ?? inventoryHost.credentialId;
        if (!sameInventoryConnection(inventoryHost, { alias, address, user, port, credentialId: comparedCredentialId })) {
          return NextResponse.json({ ok: false, error: "inventory_connection_mismatch",
            message: "Сохранённое подключение с таким именем отличается от введённых данных. Откройте его через «Настроить» или укажите другой alias." }, { status: 409 });
        }
        resolvedCredentialId = comparedCredentialId;
      }
      const identity = { alias, address, user, port };
      const mode = resolvedCredentialId ? hostCredentialSudoMode(resolvedCredentialId, identity) : null;
      onDemandSudo = mode === "on_demand";
      // New hosts must have proved either their passwordless path or the
      // one-time-password path.  Previously saved inventory connections keep
      // their historic behaviour if their old metadata has no such marker.
      if (!inventoryHost && (!resolvedCredentialId || (!onDemandSudo && !isHostCredentialSudoReady(resolvedCredentialId, identity)))) {
        return incompleteSudoResponse();
      }
      if (onDemandSudo && !sudoPassword) return sudoPasswordRequiredResponse();
    } catch (error) {
      if (error instanceof HostCredentialError) return incompleteSudoResponse();
      return NextResponse.json({ ok: false, error: "inventory_state_invalid",
        message: "Не удалось безопасно подтвердить состояние подключения. Проверьте inventory и повторите настройку хоста." }, { status: 409 });
    }
  }

  let sshKeyPath: string;
  try { sshKeyPath = connectionPrivateKey({ alias, address, user, port }, resolvedCredentialId); }
  catch (error) { return NextResponse.json({ ok: false, message: error instanceof HostCredentialError ? error.message : "Ключ подключения недоступен." }, { status: 400 }); }
  if (!existsSync(sshKeyPath)) {
    return NextResponse.json({ ok: false, message: "SSH-ключ не найден. Подключите этот хост по паролю через форму выше." }, { status: 400 });
  }
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "hcp-inventory-"));
  const inventoryPath = path.join(tmpDir, "inventory.json");
  writeFileSync(
    inventoryPath,
    JSON.stringify({ all: { hosts: { [alias]: {
      ansible_host: address, ansible_port: port, ansible_user: user, ansible_become: false,
      ansible_python_interpreter: "/usr/bin/python3", ansible_ssh_private_key_file: sshKeyPath,
    } } } }),
    { mode: 0o600 },
  );

  try {
    const ssh = await runAnsible([alias, "-m", "raw", "-a", "true"], inventoryPath, "ssh");
    // raw needs no target Python: diagnose old or missing runtimes before
    // transferring Ansible modules which may use unsupported syntax.
    const pythonProbe = ssh.ok
      ? await runAnsible([alias, "-m", "raw", "-a", '/usr/bin/python3 -c "import sys; print(\'HCP_PYTHON=%s.%s.%s\' % sys.version_info[:3])"'], inventoryPath, "python-version")
      : null;
    const targetPython = pythonProbe?.ok ? pythonProbe.data?.stdout?.match(/^HCP_PYTHON=(\d+\.\d+\.\d+)\r?$/m)?.[1] ?? null : null;
    let coreVersion: string | null = null;
    try {
      const version = await execFileAsync("ansible", ["--version"], { cwd: getRepoRoot(), timeout: 10_000, maxBuffer: 65536 });
      coreVersion = version.stdout.match(/^ansible\s+\[core\s+(\d+\.\d+\.\d+)/)?.[1] ?? null;
    } catch { /* Actual setup below remains the authority for unknown versions. */ }
    const pythonCompatibility = assessTargetPython(targetPython, coreVersion);
    const setup = ssh.ok && pythonCompatibility.compatible !== false
      ? await runAnsible([alias, "-m", "setup", "-a", "filter=ansible_distribution*,ansible_python*"], inventoryPath, "setup")
      : { ok: false, stdout: "", stderr: ssh.ok ? pythonCompatibility.message : "Сначала требуется SSH-подключение.", data: null };
    // Test a real elevated Python module, not only a whitelisted `sudo id`.
    const sudo = setup.ok && become
      ? await runAnsible([alias, "-b", "-e", "ansible_become=true", "-m", "command", "-a", "id -u"], inventoryPath, "sudo", onDemandSudo ? sudoPassword : "")
      : { ok: !become, stdout: become ? "" : "skipped", stderr: "", data: null };
    if (become && sudo.ok && sudo.data?.stdout?.trim() !== "0") sudo.ok = false;

    const facts = setup.data?.ansible_facts ?? {};
    let readiness: HostReadiness | null = null;
    let readinessError: string | null = ssh.ok && pythonCompatibility.compatible === false ? pythonCompatibility.message : null;
    if (setup.ok && sudo.ok) {
      try {
        const source = readFileSync(path.join(getRepoRoot(), "ansible/scripts/hcp-host-readiness.py"), "utf8");
        const probe = await runAnsible([alias, ...(become ? ["-b", "-e", "ansible_become=true"] : []),
          "-m", "command", "-a", JSON.stringify({ argv: ["/usr/bin/python3", "-c", source] })], inventoryPath, "readiness", onDemandSudo ? sudoPassword : "");
        if (!probe.ok) throw new Error("Не удалось собрать сведения о готовности. Проверьте доступ к системным командам на хосте.");
        readiness = assessHostReadiness(JSON.parse(probe.data.stdout));
      } catch (error) {
        readinessError = error instanceof Error ? error.message : "Проверка готовности не завершена.";
      }
    }

    const os = readiness?.os ?? ([facts.ansible_distribution, facts.ansible_distribution_version].filter(Boolean).join(" ") || null);
    return NextResponse.json({
      ...summarizePreflight({ ssh, setup, sudo, become, os,
        pythonMessage: `Python ${targetPython}: модуль Ansible выполнен (${facts.ansible_python?.executable ?? "/usr/bin/python3"}).` }),
      facts: {
        os,
        python: facts.ansible_python?.executable ?? null,
        pythonVersion: targetPython,
        ansibleCoreVersion: coreVersion,
      },
      readiness,
      readinessError,
      sudoMode: onDemandSudo ? "on_demand" : null,
    });
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}
