import { NextResponse } from "next/server";
import {
  approveDebianTrackerSelection, fetchDebianTrackerCandidate,
  getDebianTrackerManagementStatus, DebianTrackerManagementError,
} from "@/lib/debian-tracker-management";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
// Node/Docker deployment: downloading the fixed official full feed can take
// 60 seconds plus bounded JSON schema validation.
export const maxDuration = 120;

function failure(error: unknown) {
  if (error instanceof DebianTrackerManagementError) {
    const status = error.code === "busy" || error.code === "conflict" || error.code === "stale" ||
      error.code === "offline" || error.code === "not_imported" ? 409 :
      error.code === "integrity" ? 422 : 400;
    return NextResponse.json({ ok: false, code: error.code, message: error.message }, { status });
  }
  // Never leak disk paths, source data, cookies or transport internals.
  return NextResponse.json({ ok: false, message: "Не удалось завершить операцию с Debian Security Tracker. Проверьте журнал контроллера и сетевое подключение." }, { status: 502 });
}
async function smallBody(request: Request): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 512) throw new DebianTrackerManagementError("invalid", "Слишком большой запрос.");
  const text = await request.text();
  if (Buffer.byteLength(text, "utf8") > 512) throw new DebianTrackerManagementError("invalid", "Слишком большой запрос.");
  const value: unknown = JSON.parse(text || "{}");
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new DebianTrackerManagementError("invalid", "Некорректный запрос.");
  }
  return value as Record<string, unknown>;
}

export function GET() {
  try { return NextResponse.json(getDebianTrackerManagementStatus()); }
  catch (error) { return failure(error); }
}

export async function POST(request: Request) {
  try {
    const body = await smallBody(request);
    // A pin may be supplied by an operator, but URL, path, force-refresh and
    // arbitrary transport options are never accepted from the browser.
    if (Object.keys(body).some(key => key !== "expectedSha256")
      || (body.expectedSha256 !== undefined && typeof body.expectedSha256 !== "string")) {
      throw new DebianTrackerManagementError("invalid", "Разрешена только контрольная сумма SHA-256; URL источника фиксирован.");
    }
    const result = await fetchDebianTrackerCandidate({
      expectedSha256: body.expectedSha256 as string | undefined,
    });
    return NextResponse.json({ ...result, message: "Снимок загружен на управляющий сервер. Для использования при CVE-аудите подтвердите выбор отдельно." });
  } catch (error) { return failure(error); }
}

export async function PATCH(request: Request) {
  try {
    const body = await smallBody(request);
    if (body.approved !== true
      || Object.keys(body).some(key => !["approved", "selectedSha256", "expectedSha256"].includes(key))
      || !(body.selectedSha256 === null || typeof body.selectedSha256 === "string")
      || !(body.expectedSha256 === null || typeof body.expectedSha256 === "string")) {
      throw new DebianTrackerManagementError("invalid", "Требуется явное подтверждение выбора и ожидаемая текущая версия.");
    }
    const result = approveDebianTrackerSelection({
      selectedSha256: body.selectedSha256 as string | null,
      expectedSha256: body.expectedSha256 as string | null,
    });
    return NextResponse.json({ ...result, message: body.selectedSha256 === null
      ? "Предварительная сверка Debian отключена. Исходный Trivy-аудит продолжает работать."
      : "Новый снимок выбран для предварительной сверки Debian CVE. Подлинность бюллетеней не подтверждена." });
  } catch (error) { return failure(error); }
}
