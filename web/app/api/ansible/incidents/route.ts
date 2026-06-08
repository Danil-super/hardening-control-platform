import { NextResponse } from "next/server";
import { readIncidents } from "@/lib/ansible-control";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  const incidents = readIncidents();
  const summary = incidents.reduce(
    (result, incident) => {
      result.total += 1;
      result[incident.status] += 1;
      result[incident.kind] += 1;
      return result;
    },
    { total: 0, success: 0, failed: 0, audit: 0, response: 0, system: 0 },
  );

  return NextResponse.json({
    ok: true,
    incidents,
    summary,
  });
}
