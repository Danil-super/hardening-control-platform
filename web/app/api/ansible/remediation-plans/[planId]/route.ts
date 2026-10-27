import { NextResponse } from "next/server";
import { advanceRemediationPlanItem, planItemDetail } from "@/lib/remediation-plan";
import { deleteDraftRemediationPlanItem } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function failure(error: unknown, status = 400) {
  return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Не удалось обновить пункт плана." }, { status });
}

export async function GET(_request: Request, { params }: { params: Promise<{ planId: string }> }) {
  const { planId } = await params;
  const detail = planItemDetail(planId);
  return detail ? NextResponse.json({ ok: true, ...detail }) : failure(new Error("Пункт плана не найден."), 404);
}

export async function PATCH(request: Request, { params }: { params: Promise<{ planId: string }> }) {
  try {
    const { planId } = await params;
    const body = await request.json();
    const item = advanceRemediationPlanItem({ id: planId, status: body?.status, note: body?.note, owner: body?.owner,
      dueAt: body?.dueAt, approvalReference: body?.approvalReference, verificationReportId: body?.verificationReportId,
      riskAcceptedUntil: body?.riskAcceptedUntil });
    const detail = planItemDetail(item?.id ?? planId);
    return NextResponse.json({ ok: true, ...detail, message: "Статус пункта плана обновлён и зафиксирован в журнале." });
  } catch (error) { return failure(error); }
}

export async function DELETE(request: Request, { params }: { params: Promise<{ planId: string }> }) {
  try {
    const { planId } = await params;
    const body = await request.json();
    if (body?.confirmPlanId !== planId) return failure(new Error("Подтвердите удаление именно выбранного пункта плана."));
    deleteDraftRemediationPlanItem(planId);
    return NextResponse.json({ ok: true, message: "Черновой пункт удалён. Его содержимое и история сохранены в журнале действий." });
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "plan_delete_failed";
    return failure(error, code === "plan_not_found" ? 404 : code === "plan_delete_not_available" ? 409 : 400);
  }
}
