import { existsSync, unlinkSync } from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";
import { fileNameFromReportId, getReportsDir, readAnsibleReport } from "@/lib/ansible-reports";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ reportId: string }> },
) {
  const { reportId } = await params;
  const report = readAnsibleReport(decodeURIComponent(reportId));

  if (!report) {
    return NextResponse.json(
      { ok: false, error: "report_not_found", message: "Отчет не найден." },
      { status: 404 },
    );
  }

  return NextResponse.json({ ok: true, report });
}

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ reportId: string }> },
) {
  const { reportId } = await params;
  const fileName = fileNameFromReportId(decodeURIComponent(reportId));
  if (!fileName) {
    return NextResponse.json(
      { ok: false, error: "bad_report_id", message: "Некорректный идентификатор отчёта." },
      { status: 400 },
    );
  }

  const reportsDir = path.resolve(getReportsDir());
  const reportPath = path.resolve(reportsDir, fileName);
  if (!reportPath.startsWith(`${reportsDir}${path.sep}`) || !existsSync(reportPath)) {
    return NextResponse.json(
      { ok: false, error: "report_not_found", message: "Отчёт уже удалён или не найден." },
      { status: 404 },
    );
  }

  unlinkSync(reportPath);
  return NextResponse.json({ ok: true, reportId: fileName.replace(/\.json$/i, "") });
}
