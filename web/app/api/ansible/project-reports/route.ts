import { NextResponse } from "next/server";
import { createProjectReport, listProjectReports } from "@/lib/project-report";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function failure(error: unknown, status = 400) {
  return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Не удалось подготовить итоговый отчёт." }, { status });
}

async function requestBody(request: Request) {
  const reader = request.body?.getReader();
  if (!reader) throw new Error("Заполните сведения для итогового отчёта.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 16_384) { await reader.cancel(); throw new Error("Сведения для итогового отчёта слишком велики."); }
    chunks.push(value);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed as { hostAlias?: unknown; subject?: unknown };
  } catch { throw new Error("Проверьте сведения для итогового отчёта."); }
}

export async function GET(request: Request) {
  try {
    const hostAlias = new URL(request.url).searchParams.get("hostAlias") ?? undefined;
    if (hostAlias !== undefined && !/^[A-Za-z0-9_.:-]{1,96}$/.test(hostAlias)) return failure(new Error("Выберите корректный хост."));
    return NextResponse.json({ ok: true, reports: listProjectReports(hostAlias) });
  } catch (error) { return failure(error); }
}

export async function POST(request: Request) {
  try {
    const body = await requestBody(request);
    if (!body.subject || typeof body.subject !== "object" || Array.isArray(body.subject)) throw new Error("Заполните сведения для итогового отчёта.");
    const report = await createProjectReport({ hostAlias: body.hostAlias, subject: body.subject as Record<string, string> });
    return NextResponse.json({ ok: true, report, downloadUrl: `/api/ansible/project-reports/${encodeURIComponent(report.id)}`, message: "Итоговый PDF сформирован и его хеш зафиксирован в журнале HCP." });
  } catch (error) { return failure(error); }
}
