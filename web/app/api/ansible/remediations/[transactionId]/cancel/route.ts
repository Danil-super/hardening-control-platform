import { NextResponse } from "next/server";
import { cancelRemediationTransaction } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request, { params }: { params: Promise<{ transactionId: string }> }) {
  try {
    const { transactionId } = await params;
    const body = await request.json();
    const confirmedHost = typeof body?.confirmedHost === "string" ? body.confirmedHost.trim() : "";
    const transaction = cancelRemediationTransaction(transactionId, confirmedHost);
    return NextResponse.json({ ok: true, transaction, message: "Операция отменена. Изменения firewall не выполнялись; журнал действий сохранён." });
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "cancel_failed";
    return NextResponse.json({ ok: false, error: code, message: error instanceof Error ? error.message : "Не удалось отменить операцию." },
      { status: code === "transaction_not_found" ? 404 : code === "cancel_not_available" ? 409 : 400 });
  }
}
