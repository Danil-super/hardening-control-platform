import { NextResponse } from "next/server";
import { reconcileRemediationTransaction } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request, { params }: { params: Promise<{ transactionId: string }> }) {
  try {
    const { transactionId } = await params;
    const text = await request.text();
    if (text.length > 8192) throw new Error("Слишком большой протокол восстановления.");
    const body = JSON.parse(text);
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Укажите результат независимой проверки хоста.");
    const transaction = reconcileRemediationTransaction(transactionId, body);
    return NextResponse.json({ ok: true, transaction, message: transaction.status === "recovery_ready"
      ? "Сверка записана. Хост остаётся заблокированным для новых изменений; выполните откат проверенной копии."
      : "Результат сверки записан в журнал контроллера. Незавершённая блокировка HCP на целевом хосте снимается успешным завершением helper rollback после независимой проверки. Запустите повторный аудит хоста." });
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "recovery_failed";
    return NextResponse.json({ ok: false, error: code, message: error instanceof Error ? error.message : "Не удалось зарегистрировать восстановление." },
      { status: ["operation_owner_live", "recovery_not_available", "recovery_version_stale", "newer_remediation_exists"].includes(code) ? 409 : 400 });
  }
}
