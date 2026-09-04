import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { NextResponse } from "next/server";
import { getRepoRoot } from "@/lib/ansible-control";
import { ansibleSshArgs } from "@/lib/ssh-access";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const execFileAsync = promisify(execFile);

function isSafeAlias(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.-]{1,64}$/.test(value);
}

function isSafeSshUser(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.-]{1,64}$/.test(value);
}

function isSafeHostAddress(value: unknown): value is string {
  return typeof value === "string" && /^(?:[a-zA-Z0-9.-]{1,253}|\d{1,3}(?:\.\d{1,3}){3})$/.test(value);
}

function normalizePort(value: unknown) {
  const port = typeof value === "string" ? Number(value) : value;
  return typeof port === "number" && Number.isInteger(port) && port > 0 && port <= 65535 ? port : 22;
}

async function runAnsible(args: string[], inventoryPath: string) {
  try {
    const result = await execFileAsync("ansible", ["-i", inventoryPath, ...args], {
      cwd: getRepoRoot(),
      timeout: 45_000,
      maxBuffer: 1024 * 1024 * 4,
      env: { ...process.env, ANSIBLE_FORCE_COLOR: "false", ANSIBLE_SSH_ARGS: ansibleSshArgs() },
    });
    return { ok: true, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string };
    return {
      ok: false,
      stdout: output.stdout ?? "",
      stderr: output.stderr ?? output.message ?? "",
    };
  }
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alias = typeof body?.alias === "string" ? body.alias.trim() : "";
  const address = typeof body?.address === "string" ? body.address.trim() : "";
  const user = typeof body?.user === "string" ? body.user.trim() : "";
  const port = normalizePort(body?.port);
  const become = typeof body?.become === "boolean" ? body.become : true;

  if (!isSafeAlias(alias) || !isSafeHostAddress(address) || !isSafeSshUser(user)) {
    return NextResponse.json(
      { ok: false, message: "Проверьте alias, IP/hostname и SSH-пользователя." },
      { status: 400 },
    );
  }

  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "hcp-inventory-"));
  const inventoryPath = path.join(tmpDir, "inventory.ini");
  const sshKeyPath = process.env.HCP_SSH_PRIVATE_KEY_PATH ?? path.join(os.homedir(), ".ssh", "hcp-control");
  const sshKeyOption = existsSync(sshKeyPath) ? ` ansible_ssh_private_key_file=${sshKeyPath}` : "";
  writeFileSync(
    inventoryPath,
    `[preflight]\n${alias} ansible_host=${address} ansible_port=${port} ansible_user=${user} ansible_become=${become ? "true" : "false"} ansible_python_interpreter=/usr/bin/python3${sshKeyOption}\n`,
  );

  try {
    const ssh = await runAnsible([alias, "-m", "ping"], inventoryPath);
    const setup = ssh.ok
      ? await runAnsible([alias, "-m", "setup", "-a", "filter=ansible_distribution*,ansible_python*"], inventoryPath)
      : { ok: false, stdout: "", stderr: "SSH ping failed." };
    const sudo = ssh.ok && become
      ? await runAnsible([alias, "-b", "-m", "command", "-a", "whoami"], inventoryPath)
      : { ok: !become, stdout: become ? "" : "skipped", stderr: "" };

    const osMatch = setup.stdout.match(/"ansible_distribution":\s*"([^"]+)"/);
    const versionMatch = setup.stdout.match(/"ansible_distribution_version":\s*"([^"]+)"/);
    const pythonMatch = setup.stdout.match(/"executable":\s*"([^"]+)"/);

    return NextResponse.json({
      ok: ssh.ok && setup.ok && sudo.ok,
      checks: {
        ssh: { ok: ssh.ok, message: ssh.ok ? "SSH OK" : ssh.stderr || ssh.stdout },
        python: { ok: setup.ok, message: setup.ok ? pythonMatch?.[1] ?? "Python OK" : setup.stderr || setup.stdout },
        sudo: { ok: sudo.ok, message: become ? (sudo.ok ? sudo.stdout.trim() || "sudo OK" : sudo.stderr || sudo.stdout) : "sudo disabled" },
      },
      facts: {
        os: [osMatch?.[1], versionMatch?.[1]].filter(Boolean).join(" ") || null,
        python: pythonMatch?.[1] ?? null,
      },
    });
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}
