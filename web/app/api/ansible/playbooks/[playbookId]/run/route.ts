import { NextResponse } from "next/server";
import { customPlaybooksEnabled, getRegisteredPlaybook, runRegisteredPlaybook } from "@/lib/playbook-registry";
import { POST as runManagedPlaybook } from "@/app/api/ansible/run/route";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ playbookId: string }> },
) {
  const { playbookId } = await params;
  const body = await request.json().catch(() => ({}));
  const playbook = getRegisteredPlaybook(decodeURIComponent(playbookId));
  if (!playbook) {
    return NextResponse.json({ ok: false, message: "Playbook не найден." }, { status: 404 });
  }
  if (playbook.source === "custom" && !customPlaybooksEnabled()) {
    return NextResponse.json({ ok: false, message: "Запуск пользовательских playbook отключен в production режиме." }, { status: 403 });
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

  try {
    const { stdout, stderr, command } = await runRegisteredPlaybook({
      playbook,
      limit: typeof body?.limit === "string" ? body.limit.trim() : undefined,
      variables: body?.variables && typeof body.variables === "object" ? body.variables : {},
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
