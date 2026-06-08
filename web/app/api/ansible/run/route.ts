import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const execFileAsync = promisify(execFile);

const playbooks = {
  ping: { file: "ping.yml", timeout: 120_000 },
  collectFacts: { file: "collect-facts.yml", timeout: 240_000 },
  agentlessAudit: { file: "agentless-audit.yml", timeout: 600_000 },
  closeDangerousPorts: { file: "close-dangerous-ports.yml", timeout: 240_000, response: true },
} as const;

const profileIds = new Set(["basic_linux", "ssh_security", "web_server", "docker_host"]);

type PlaybookAction = keyof typeof playbooks;

function getRepoRoot() {
  return path.resolve(process.cwd(), "..");
}

function isPlaybookAction(value: unknown): value is PlaybookAction {
  return typeof value === "string" && value in playbooks;
}

function isSafeLimit(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.:-]+(,[a-zA-Z0-9_.:-]+)*$/.test(value);
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const action = body?.action;
  const profileId = typeof body?.profileId === "string" && profileIds.has(body.profileId) ? body.profileId : "basic_linux";
  const limit = body?.limit;
  const confirmResponse = body?.confirmResponse === true;

  if (!isPlaybookAction(action)) {
    return NextResponse.json(
      { ok: false, error: "unsupported_action", message: "Неподдерживаемый playbook." },
      { status: 400 },
    );
  }

  if (limit && !isSafeLimit(limit)) {
    return NextResponse.json(
      { ok: false, error: "bad_limit", message: "Limit может содержать только имена хостов/групп без пробелов." },
      { status: 400 },
    );
  }

  const selected = playbooks[action];
  if ("response" in selected && selected.response && !limit) {
    return NextResponse.json(
      {
        ok: false,
        error: "limit_required",
        message: "Для response-playbook выберите конкретный хост или группу в поле Limit.",
      },
      { status: 400 },
    );
  }

  if ("response" in selected && selected.response && !confirmResponse) {
    return NextResponse.json(
      {
        ok: false,
        error: "confirmation_required",
        message: "Response-playbook требует явного подтверждения администратора.",
      },
      { status: 400 },
    );
  }

  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  if (!existsSync(inventoryPath)) {
    return NextResponse.json(
      {
        ok: false,
        error: "inventory_missing",
        message: "Создайте ansible/inventory.ini из ansible/inventory.example.ini.",
      },
      { status: 400 },
    );
  }

  const playbookPath = path.join(repoRoot, "ansible", "playbooks", selected.file);
  const args = ["-i", inventoryPath, playbookPath, "-e", `audit_profile=${profileId}`];
  if (limit) {
    args.push("--limit", limit);
  }

  try {
    const { stdout, stderr } = await execFileAsync("ansible-playbook", args, {
      cwd: repoRoot,
      timeout: selected.timeout,
      maxBuffer: 1024 * 1024 * 8,
      env: { ...process.env, ANSIBLE_FORCE_COLOR: "false" },
    });

    return NextResponse.json({
      ok: true,
      action,
      profileId,
      limit: limit || null,
      command: `ansible-playbook ${args.join(" ")}`,
      stdout,
      stderr,
    });
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string };
    return NextResponse.json(
      {
        ok: false,
        action,
        profileId,
        limit: limit || null,
        command: `ansible-playbook ${args.join(" ")}`,
        message: output.message ?? "Playbook завершился с ошибкой.",
        stdout: output.stdout ?? "",
        stderr: output.stderr ?? "",
      },
      { status: 500 },
    );
  }
}
