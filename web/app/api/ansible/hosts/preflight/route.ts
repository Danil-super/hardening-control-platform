import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { NextResponse } from "next/server";
import { getRepoRoot } from "@/lib/ansible-control";
import { ansibleSshArgs, configuredPrivateKeyPath, isSafeSshHostAddress, normalizeSshPort } from "@/lib/ssh-access";
import { assessHostReadiness, type HostReadiness } from "@/lib/host-readiness";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const execFileAsync = promisify(execFile);

function isSafeAlias(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value) && !["all", "ungrouped", "preflight"].includes(value);
}

function isSafeSshUser(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value);
}

async function runAnsible(args: string[], inventoryPath: string, stage: string) {
  const resultDir = path.join(path.dirname(inventoryPath), stage);
  try {
    const result = await execFileAsync("ansible", ["-i", inventoryPath, "--tree", resultDir, ...args], {
      cwd: getRepoRoot(),
      timeout: 60_000,
      maxBuffer: 1024 * 1024 * 4,
      env: { ...process.env, ANSIBLE_FORCE_COLOR: "false", ANSIBLE_SSH_ARGS: ansibleSshArgs(), ANSIBLE_PRIVATE_KEY_FILE: configuredPrivateKeyPath() },
    });
    const data = JSON.parse(readFileSync(path.join(resultDir, args[0]), "utf8"));
    return { ok: data.failed !== true && data.unreachable !== true, stdout: result.stdout, stderr: result.stderr, data };
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string };
    return {
      ok: false,
      stdout: output.stdout ?? "",
      stderr: output.stderr ?? output.message ?? "",
      data: null,
    };
  }
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alias = typeof body?.alias === "string" ? body.alias.trim() : "";
  const address = typeof body?.address === "string" ? body.address.trim() : "";
  const user = typeof body?.user === "string" ? body.user.trim() : "";
  const port = normalizeSshPort(body?.port);
  const become = typeof body?.become === "boolean" ? body.become : true;

  if (!isSafeAlias(alias) || !isSafeSshHostAddress(address) || !isSafeSshUser(user) || port === null) {
    return NextResponse.json(
      { ok: false, message: "Проверьте alias, IP/hostname, SSH-порт и пользователя." },
      { status: 400 },
    );
  }

  const sshKeyPath = configuredPrivateKeyPath();
  if (!existsSync(sshKeyPath)) {
    return NextResponse.json({ ok: false, message: "Ключ узла управления не найден. Настройте HCP_SSH_PRIVATE_KEY_PATH." }, { status: 400 });
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
    const setup = ssh.ok
      ? await runAnsible([alias, "-m", "setup", "-a", "filter=ansible_distribution*,ansible_python*"], inventoryPath, "setup")
      : { ok: false, stdout: "", stderr: "SSH ping failed.", data: null };
    const sudo = ssh.ok && become
      ? await runAnsible([alias, "-b", "-e", "ansible_become=true", "-m", "command", "-a", "id -u"], inventoryPath, "sudo")
      : { ok: !become, stdout: become ? "" : "skipped", stderr: "", data: null };
    if (become && sudo.ok && sudo.data?.stdout?.trim() !== "0") sudo.ok = false;

    const facts = setup.data?.ansible_facts ?? {};
    let readiness: HostReadiness | null = null;
    let readinessError: string | null = null;
    if (setup.ok && sudo.ok) {
      try {
        const source = readFileSync(path.join(getRepoRoot(), "ansible/scripts/hcp-host-readiness.py"), "utf8");
        const probe = await runAnsible([alias, ...(become ? ["-b", "-e", "ansible_become=true"] : []),
          "-m", "command", "-a", JSON.stringify({ argv: ["/usr/bin/python3", "-c", source] })], inventoryPath, "readiness");
        if (!probe.ok) throw new Error("Не удалось собрать сведения о готовности. Проверьте доступ к системным командам на хосте.");
        readiness = assessHostReadiness(JSON.parse(probe.data.stdout));
      } catch (error) {
        readinessError = error instanceof Error ? error.message : "Проверка готовности не завершена.";
      }
    }

    return NextResponse.json({
      ok: ssh.ok && setup.ok && sudo.ok,
      checks: {
        ssh: { ok: ssh.ok, message: ssh.ok ? "SSH OK" : ssh.stderr || ssh.stdout },
        python: { ok: setup.ok, message: setup.ok ? facts.ansible_python?.executable ?? "Python OK" : setup.stderr || setup.stdout },
        sudo: { ok: sudo.ok, message: become ? (sudo.ok ? "Доступ root подтверждён" : sudo.stderr || sudo.stdout) : "sudo отключён" },
      },
      facts: {
        os: readiness?.os ?? ([facts.ansible_distribution, facts.ansible_distribution_version].filter(Boolean).join(" ") || null),
        python: facts.ansible_python?.executable ?? null,
      },
      readiness,
      readinessError,
    });
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}
