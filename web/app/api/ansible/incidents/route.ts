import { NextResponse } from "next/server";
import { readIncidents } from "@/lib/ansible-control";
import { verifyAuditChain } from "@/lib/state-store";

import { incidentDisplayStatus } from "@/lib/incident-status";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const incidents = readIncidents(new URL(request.url).searchParams.get("view") === "archive" ? "archive" : "active");
  const summary = incidents.reduce(
    (result, incident) => {
      result.total += 1;
      result[incidentDisplayStatus(incident)] += 1;
      result[incident.kind] += 1;
      return result;
    },
    { total: 0, success: 0, partial: 0, failed: 0, audit: 0, response: 0, system: 0 },
  );

  return NextResponse.json({
    ok: true,
    incidents,
    summary,
    integrity: verifyAuditChain(),
  });
}

export async function DELETE() {
  return NextResponse.json(
    {
      ok: false,
      error: "audit_log_append_only",
      message: "Журнал аудита неизменяем: записи нельзя удалить через панель.",
    },
    { status: 405 },
  );
}
