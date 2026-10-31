import { NextResponse } from "next/server";
import { appendIncident, profileIds } from "@/lib/ansible-control";
import { isScheduledLimit, runScheduledInventoryAudit } from "@/lib/scheduled-audit";
import { isScheduledRequestAuthorized, isScheduledRunId } from "@/lib/scheduled-auth";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!isScheduledRequestAuthorized(request)) {
    return NextResponse.json({ ok: false, message: "Недействительный ключ планировщика." }, { status: 401 });
  }
  const body = await request.json().catch(() => ({}));
  const profileId = body?.profileId ?? "basic_linux";
  if (!isScheduledRunId(body?.reportRunId) || !isScheduledLimit(body?.limit) || !profileIds.has(profileId)) {
    return NextResponse.json({ ok: false, message: "Некорректные параметры планового системного аудита." }, { status: 400 });
  }
  try {
    const results = await runScheduledInventoryAudit({ action: "agentlessAudit", profileId, limit: body.limit });
    const partial = results.some((result) => result.partial);
    appendIncident({ action: "scheduledAgentlessAudit", kind: "audit", status: partial ? "partial" : "success", profileId,
      limit: body.limit, runId: body.reportRunId,
      message: `Плановый системный аудит: ${results.filter((result) => !result.partial).length}/${results.length} полных проверок.` });
    return NextResponse.json({ ok: !partial, partial, reportRunId: body.reportRunId, results }, { status: partial ? 207 : 200 });
  } catch (error) {
    return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Ошибка планового системного аудита." }, { status: 400 });
  }
}
