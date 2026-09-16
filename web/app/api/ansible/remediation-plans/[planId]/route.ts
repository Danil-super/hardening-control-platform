import { NextResponse } from "next/server";
import { advanceRemediationPlanItem, planItemDetail } from "@/lib/remediation-plan";

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
