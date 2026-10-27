import { NextResponse } from "next/server";
import { deleteAnsibleReport, listAnsibleReports, listAnsibleReportDependents, readAnsibleReport, targetAliasFromReport } from "@/lib/ansible-reports";
import { listProjectReportSourceReferences } from "@/lib/project-report";
import { appendAuditEvent, getProjectReportRecord, getRemediationPlanItem, listStoredReportReferences } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function deletionStatus(reportId: string, hostAlias: string) {
  const references = [
    ...listAnsibleReportDependents(reportId).map((item) => ({
      id: item.id, kind: "report", label: `Последующий тест · ${item.mode}`,
      description: "Этот тест использует выбранный отчёт как исходные данные. Сначала удалите последующий тест, если он больше не нужен.",
      href: `/reports/agentless/${encodeURIComponent(item.id)}`,
    })),
    ...Array.from(new Map(listStoredReportReferences(reportId).map((item) => [item.id, item])).values()).map((item) => {
      if (item.kind === "remediation") return {
        id: item.id, kind: "remediation", label: "Операция изменения хоста",
        description: "Отчёт сохранён как исходная или контрольная проверка изменения. История изменений и её доказательства защищены от удаления.",
        href: "/hosts#recent-remediations",
      };
      const plan = getRemediationPlanItem(item.id);
      return {
        id: item.id, kind: "plan", label: `Пункт плана · ${plan?.title ?? "Сохранённое решение"}`,
        description: plan?.canDeleteDraft ? "Этот пункт использует находки или результаты проверки отчёта. Ненужный черновой пункт можно удалить в плане работ." : "Этот пункт использует отчёт как доказательство согласованного решения. Он и его исходные отчёты защищены от удаления.",
        href: `/remediation-plan?host=${encodeURIComponent(item.hostAlias)}#${encodeURIComponent(item.id)}`,
      };
    }),
    ...listProjectReportSourceReferences(reportId, hostAlias).map((item) => {
      const pdf = getProjectReportRecord(item.id);
      const date = pdf ? new Date(pdf.createdAt).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" }) : "дата неизвестна";
      return {
        id: item.id, kind: "pdf", label: `Итоговый PDF · ${pdf?.subject.projectName ?? "Сохранённый экспорт"}`,
        description: `${pdf ? `Заказчик: ${pdf.subject.clientName}. Создан: ${date} (МСК). ` : ""}${item.snapshotReadable ? "Этот отчёт включён в перечень исходных данных PDF. Исходники сохранённых экспортов защищены от удаления." : "Снимок этого PDF не удалось проверить. Пока связь с исходным отчётом не проверена, удаление заблокировано."}`,
        href: `/project-reports?host=${encodeURIComponent(hostAlias)}&report=${encodeURIComponent(item.id)}#${encodeURIComponent(item.id)}`,
      };
    }),
  ];
  return {
    canDelete: references.length === 0, references,
    message: !references.length ? "Отчёт не используется в других записях и может быть удалён."
      : references.every((item) => item.kind === "pdf") ? `Отчёт используется в сохранённых итоговых PDF (${references.length}). Их исходные данные защищены от удаления.`
        : "Отчёт используется в других записях. Ниже указаны причины запрета и ссылки на эти записи.",
  };
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ reportId: string }> },
) {
  const { reportId } = await params;
  if (new URL(request.url).searchParams.get("dependencies") === "1") {
    try {
      const id = decodedReportId(reportId);
      const summary = listAnsibleReports("all").find((item) => item.id === id);
      if (!summary) return NextResponse.json({ ok: false, error: "report_not_found", message: "Отчёт не найден." }, { status: 404 });
      return NextResponse.json({ ok: true, ...deletionStatus(id, targetAliasFromReport(summary)) });
    } catch {
      return NextResponse.json({ ok: false, message: "Не удалось проверить использование отчёта. Удаление не выполнено." }, { status: 400 });
    }
  }
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
    const usage = deletionStatus(reportId, targetAliasFromReport(report));
    if (!usage.canDelete) {
      return NextResponse.json({
        ok: false,
        error: "report_is_referenced",
        ...usage,
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
