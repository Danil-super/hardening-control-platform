import { NextResponse } from "next/server";
import { readAnsibleReport } from "@/lib/ansible-reports";

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
