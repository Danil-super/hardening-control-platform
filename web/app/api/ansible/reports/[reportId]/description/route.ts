import { NextResponse } from "next/server";
import { lstatSync } from "node:fs";
import path from "node:path";
import { fileNameFromReportId, getReportsDir, readAnsibleReport } from "@/lib/ansible-reports";
import { translateDescription } from "@/lib/description-translation";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 120;

// Keep only small prose projections. An OVAL source can exceed 300 MB; do not
// parse its complete evidence tree again for every expanded row.
type TextField = "title" | "description" | "recommendation";
type FindingText = Record<TextField, string>;
const descriptions = new Map<string, { signature: string; values: Map<string, FindingText> }>();
function findingDescription(reportId: string, findingId: string, field: TextField) {
  const filename = fileNameFromReportId(reportId);
  if (!filename) return null;
  const info = lstatSync(path.join(getReportsDir(), filename), { throwIfNoEntry: false });
  if (!info?.isFile() || info.isSymbolicLink()) return null;
  const signature = `${info.ino}:${info.size}:${info.mtimeMs}:${info.ctimeMs}`;
  const cached = descriptions.get(reportId);
  if (cached?.signature === signature) return cached.values.get(findingId)?.[field] ?? null;
  const report = readAnsibleReport(reportId);
  if (!report) return null;
  const text = report.findings.find((item) => item.id === findingId)?.[field] ?? null;
  const size = report.findings.reduce((total, item) => total + Buffer.byteLength(item.title) + Buffer.byteLength(item.description) + Buffer.byteLength(item.recommendation), 0);
  if (size <= 8 * 1024 * 1024) {
    if (descriptions.size >= 3) descriptions.delete(descriptions.keys().next().value!);
    descriptions.set(reportId, { signature, values: new Map(report.findings.map((item) => [item.id, { title: item.title, description: item.description, recommendation: item.recommendation }])) });
  }
  return text;
}

export async function GET(request: Request, { params }: { params: Promise<{ reportId: string }> }) {
  const { reportId } = await params;
  const query = new URL(request.url).searchParams;
  const findingId = query.get("findingId");
  const field = query.get("field") ?? "description";
  if (!["title", "description", "recommendation"].includes(field)) {
    return NextResponse.json({ ok: false, message: "Для перевода доступны название, описание и рекомендация." }, { status: 400 });
  }
  if (!/^[A-Za-z0-9_.:-]{1,180}$/.test(reportId) || !findingId || findingId.length > 240) {
    return NextResponse.json({ ok: false, message: "Укажите существующую запись отчёта." }, { status: 400 });
  }
  try {
    const text = findingDescription(reportId, findingId, field as TextField);
    if (text === null) return NextResponse.json({ ok: false, message: "Запись отчёта не найдена." }, { status: 404 });
    const translation = await translateDescription(text);
    return NextResponse.json({ ok: true, translation }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Перевод недоступен. Оригинал сохранён." }, { status: 503 });
  }
}
