import { NextResponse } from "next/server";
import { applyArchive, archivePreview, type ArchiveAction, type ArchiveTarget } from "@/lib/archive";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function selection(target: unknown, action: unknown): { target: ArchiveTarget; action: ArchiveAction } {
  if (target !== "reports" && target !== "journal" || action !== "archive" && action !== "restore") throw new Error("Выберите корректную операцию очистки.");
  return { target, action };
}

function failure(error: unknown) {
  const code = error && typeof error === "object" && "code" in error ? error.code : "archive_failed";
  return NextResponse.json({ ok: false, error: code, message: error instanceof Error ? error.message : "Не удалось обработать архив." }, { status: code === "operation_in_progress" || code === "archive_preview_changed" ? 409 : 400 });
}

export async function GET(request: Request) {
  try {
    const query = new URL(request.url).searchParams;
    const { target, action } = selection(query.get("target"), query.get("action"));
    const { records: _records, ...preview } = archivePreview(target, action);
    return NextResponse.json({ ok: true, preview });
  } catch (error) { return failure(error); }
}

export async function POST(request: Request) {
  try {
    const text = await request.text();
    if (Buffer.byteLength(text, "utf8") > 4096) throw new Error("Подтверждение очистки слишком велико.");
    const body = JSON.parse(text);
    const { target, action } = selection(body?.target, body?.action);
    if (body.confirmation !== `${action}:${target}` || typeof body.token !== "string" || !/^[a-f0-9]{64}$/.test(body.token)) throw new Error("Подтвердите операцию после предварительного просмотра.");
    const changed = applyArchive(target, action, body.token);
    return NextResponse.json({ ok: true, changed, message: action === "archive" ? `Активный список очищен: ${changed} записей перенесено в архив. Доказательства сохранены.` : `Из архива возвращено записей: ${changed}.` });
  } catch (error) { return failure(error); }
}
