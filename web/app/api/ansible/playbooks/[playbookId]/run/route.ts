import { NextResponse } from "next/server";
import { customPlaybookCapabilities, customPlaybooksEnabled, getRegisteredPlaybook, runRegisteredPlaybook } from "@/lib/playbook-registry";
import { POST as runManagedPlaybook } from "@/app/api/ansible/run/route";
import { credentialTransportAllowed } from "@/lib/ssh-bootstrap";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ playbookId: string }> },
) {
  const { playbookId } = await params;
  const body = await request.json().catch(() => ({}));
  if (!body || typeof body !== "object" || Array.isArray(body)) return NextResponse.json({ ok: false, message: "Укажите параметры запуска объектом JSON." }, { status: 400 });
  const playbook = getRegisteredPlaybook(decodeURIComponent(playbookId));
  if (!playbook) {
    return NextResponse.json({ ok: false, message: "Playbook не найден." }, { status: 404 });
  }
  if (playbook.source === "custom" && !customPlaybooksEnabled()) {
    return NextResponse.json({ ok: false, message: customPlaybookCapabilities().reason }, { status: 403 });
  }
  if (playbook.source === "builtin") {
    // Keep a single execution path for target validation, SSH configuration,
    // explicit scanner consent, policy snapshots and incomplete reports.
    return runManagedPlaybook(new Request(request.url, {
      method: "POST",
      headers: request.headers,
      body: JSON.stringify({ ...body, action: playbook.id }),
    }));
  }

  const sudoPassword = typeof body?.sudoPassword === "string" ? body.sudoPassword : "";
  if (body?.sudoPassword !== undefined && (typeof body.sudoPassword !== "string" || sudoPassword.length > 1024 || /[\r\n\0]/.test(sudoPassword))) {
    return NextResponse.json({ ok: false, message: "Некорректный пароль sudo." }, { status: 400 });
  }
  if (sudoPassword && !credentialTransportAllowed(request)) return NextResponse.json({ ok: false, message: "Для пароля sudo используйте HTTPS либо localhost." }, { status: 400 });
  delete body.sudoPassword;

  try {
    const { stdout, stderr, command } = await runRegisteredPlaybook({
      playbook,
      limit: typeof body?.limit === "string" ? body.limit.trim() : undefined,
      variables: body?.variables && typeof body.variables === "object" ? body.variables : {},
      becomePassword: sudoPassword || undefined,
    });
    return NextResponse.json({ ok: true, stdout, stderr, command });
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string };
    return NextResponse.json(
      {
        ok: false,
        message: output.message ?? "Playbook завершился с ошибкой.",
        stdout: output.stdout ?? "",
        stderr: output.stderr ?? "",
      },
      { status: 400 },
    );
  }
}
