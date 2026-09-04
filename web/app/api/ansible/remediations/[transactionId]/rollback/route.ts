import { NextResponse } from "next/server";
import { rollbackRemediation } from "@/lib/remediation";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ transactionId: string }> },
) {
  const { transactionId } = await params;
  const body = await request.json().catch(() => ({}));
  const confirmedHost = typeof body?.confirmedHost === "string" ? body.confirmedHost.trim() : "";
  try {
    const rollback = await rollbackRemediation(decodeURIComponent(transactionId), confirmedHost);
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
