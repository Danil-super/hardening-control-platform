import { NextResponse } from "next/server";
import { rollbackRemediation } from "@/lib/remediation";
import { credentialTransportAllowed } from "@/lib/ssh-bootstrap";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ transactionId: string }> },
) {
  const { transactionId } = await params;
  const body = await request.json().catch(() => ({}));
  const confirmedHost = typeof body?.confirmedHost === "string" ? body.confirmedHost.trim() : "";
  const sudoPassword = typeof body?.sudoPassword === "string" ? body.sudoPassword : "";
  if (typeof body?.sudoPassword !== "undefined" && (typeof body?.sudoPassword !== "string" || sudoPassword.length > 1024 || /[\r\n\0]/.test(sudoPassword))) {
    return NextResponse.json({ ok: false, message: "Пароль sudo должен быть одной строкой длиной до 1024 символов." }, { status: 400 });
  }
  if (sudoPassword && !credentialTransportAllowed(request)) {
    return NextResponse.json({ ok: false, error: "secure_transport_required",
      message: "Для пароля sudo откройте HCP через HTTPS либо http://127.0.0.1 на управляющей Ubuntu." }, { status: 400 });
  }
  if (body && typeof body === "object") delete body.sudoPassword;
  try {
    const rollback = await rollbackRemediation(decodeURIComponent(transactionId), confirmedHost, sudoPassword || undefined);
    return NextResponse.json({
      ok: true,
      transaction: rollback.transaction,
      command: rollback.result.command,
      stdout: rollback.result.stdout,
      stderr: rollback.result.stderr,
      message: "Откат выполнен. Запустите повторный аудит, чтобы зафиксировать состояние после отката.",
    });
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string };
    return NextResponse.json(
      {
        ok: false,
        message: output.message ?? "Откат завершился с ошибкой.",
        stdout: output.stdout ?? "",
        stderr: output.stderr ?? "",
      },
      { status: 400 },
    );
  }
}
