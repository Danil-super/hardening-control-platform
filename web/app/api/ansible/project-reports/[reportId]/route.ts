import { NextResponse } from "next/server";
import { readProjectReportPdf } from "@/lib/project-report";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(_request: Request, { params }: { params: Promise<{ reportId: string }> }) {
  try {
    const { reportId } = await params;
    const result = readProjectReportPdf(reportId);
    if (!result) return NextResponse.json({ ok: false, message: "Итоговый отчёт не найден." }, { status: 404 });
    return new NextResponse(new Uint8Array(result.pdf), { headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename=\"hcp-final-report-${result.record.id}.pdf\"`,
      "Content-Length": String(result.pdf.length),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    } });
  } catch {
    return NextResponse.json({ ok: false, message: "Не удалось проверить целостность итогового отчёта." }, { status: 500 });
  }
}
