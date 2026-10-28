import { NextResponse } from "next/server";
import { appendIncident } from "@/lib/ansible-control";
import { refreshDependencyTrack } from "@/lib/dependency-track";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const hostAlias = typeof body?.hostAlias === "string" ? body.hostAlias.trim() : "";
  const reportId = typeof body?.reportId === "string" ? body.reportId.trim() : "";
  try {
    const result = await refreshDependencyTrack({ hostAlias, reportId });
    if (result.status === "complete" && !result.reused) {
      appendIncident({ action: "dependencyTrackRefresh", kind: "audit", status: "partial", profileId: "dependency-track",
        limit: hostAlias, message: result.message });
    }
    return NextResponse.json({ ok: true, ...result });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Не удалось получить результат Dependency-Track.";
    return NextResponse.json({ ok: false, status: "error", partial: true, message }, { status: 400 });
  }
}
