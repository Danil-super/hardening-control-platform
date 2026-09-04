import { NextResponse } from "next/server";
import { appendIncident } from "@/lib/ansible-control";
import { syncDependencyTrack } from "@/lib/dependency-track";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const hostAlias = typeof body?.hostAlias === "string" ? body.hostAlias.trim() : "";
  const vulnerabilityReportId = typeof body?.vulnerabilityReportId === "string" ? body.vulnerabilityReportId.trim() : "";
  try {
    const result = await syncDependencyTrack({ hostAlias, vulnerabilityReportId });
    appendIncident({
      action: "dependencyTrackSync",
      kind: "audit",
      status: result.configured ? "success" : "failed",
      profileId: "dependency-track",
      limit: hostAlias || null,
      message: result.message,
    });
    return NextResponse.json({ ok: true, ...result });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Не удалось передать SBOM в Dependency-Track.";
    appendIncident({ action: "dependencyTrackSync", kind: "audit", status: "failed", profileId: "dependency-track", limit: hostAlias || null, message });
    return NextResponse.json({ ok: false, message }, { status: 400 });
  }
}
