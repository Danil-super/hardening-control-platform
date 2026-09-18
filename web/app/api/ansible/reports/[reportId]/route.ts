import { NextResponse } from "next/server";
import { deleteAnsibleReport, listAnsibleReportDependents, readAnsibleReport, targetAliasFromReport } from "@/lib/ansible-reports";
import { listProjectReportSourceReferences } from "@/lib/project-report";
import { appendAuditEvent, listStoredReportReferences } from "@/lib/state-store";

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

async function deleteRequestBody(request: Request) {
  const body = await request.text();
  if (Buffer.byteLength(body, "utf8") > 1024) throw new Error("Подтверждение удаления слишком велико.");
  try {
    const parsed = JSON.parse(body);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed as { confirmReportId?: unknown };
  } catch {
    throw new Error("Подтвердите удаление отчёта.");
  }
}

function decodedReportId(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error("Идентификатор отчёта имеет недопустимый формат.");
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ reportId: string }> },
) {
  try {
    const { reportId: rawReportId } = await params;
    const reportId = decodedReportId(rawReportId);
    const body = await deleteRequestBody(request);
    if (body.confirmReportId !== reportId) {
      return NextResponse.json({ ok: false, error: "delete_confirmation_required", message: "Подтвердите удаление именно выбранного отчёта." }, { status: 400 });
    }

    const report = readAnsibleReport(reportId);
    if (!report) {
      return NextResponse.json({ ok: false, error: "report_not_found", message: "Отчёт не найден." }, { status: 404 });
    }
    const dependents = listAnsibleReportDependents(reportId);
    const storedReferences = listStoredReportReferences(reportId);
    const finalReportReferences = listProjectReportSourceReferences(reportId, targetAliasFromReport(report));
    if (dependents.length || storedReferences.length || finalReportReferences.length) {
      return NextResponse.json({
        ok: false,
        error: "report_is_referenced",
        message: "Этот отчёт используется в сохранённой цепочке аудита, плане устранения, операции изменения или итоговом PDF. Сначала удалите зависимый тест либо завершите работу с планом; журнал действий не изменяется.",
      }, { status: 409 });
    }

    const deleted = deleteAnsibleReport(reportId);
    if (!deleted) {
      return NextResponse.json({ ok: false, error: "report_not_found", message: "Отчёт не найден." }, { status: 404 });
    }
    appendAuditEvent("ansible_report_deleted", reportId, {
      hostAlias: deleted.hostAlias,
      mode: deleted.mode,
      sbomRemoved: deleted.sbomRemoved,
    });
    return NextResponse.json({
      ok: true,
      message: deleted.sbomRemoved
        ? "Отчёт и связанный с ним неиспользуемый SBOM удалены. Журнал действий сохранён."
        : "Отчёт удалён. Журнал действий сохранён.",
    });
  } catch (error) {
    return NextResponse.json({ ok: false, error: "report_delete_failed", message: error instanceof Error ? error.message : "Не удалось удалить отчёт." }, { status: 400 });
  }
}
