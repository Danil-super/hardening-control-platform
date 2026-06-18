import { NextResponse } from "next/server";
import { getReportsDir, listAnsibleReports } from "@/lib/ansible-reports";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  const reports = listAnsibleReports();
  const auditReports = reports.filter((report) => report.findingsCount > 0);
  const eventReports = reports.filter((report) => report.mode === "events" || report.eventsCount > 0);
  const scores = auditReports
    .map((report) => report.score)
    .filter((score): score is number => typeof score === "number");

  return NextResponse.json({
    ok: true,
    reportsPath: getReportsDir(),
    reports,
    summary: {
      total: reports.length,
      audit: auditReports.length,
      events: eventReports.length,
      averageScore: scores.length
        ? Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length)
        : null,
      high: auditReports.reduce((sum, report) => sum + report.high, 0),
      medium: auditReports.reduce((sum, report) => sum + report.medium, 0),
    },
  });
}
