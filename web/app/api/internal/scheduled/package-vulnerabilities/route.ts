import { NextResponse } from "next/server";
import { appendIncident } from "@/lib/ansible-control";
import { listAnsibleReports, targetAliasFromReport } from "@/lib/ansible-reports";
import { isScheduledRequestAuthorized, isScheduledRunId } from "@/lib/scheduled-auth";
import { syncDependencyTrack } from "@/lib/dependency-track";
import { scanPackageInventory } from "@/lib/vulnerability-scan";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!isScheduledRequestAuthorized(request)) {
    return NextResponse.json({ ok: false, message: "Недействительный ключ планировщика." }, { status: 401 });
  }
  const body = await request.json().catch(() => ({}));
  if (!isScheduledRunId(body?.reportRunId)) {
    return NextResponse.json({ ok: false, message: "Некорректный reportRunId планировщика." }, { status: 400 });
  }

  const packageReports = listAnsibleReports().filter((report) => (
    report.mode === "packages" && report.reportTimeValid && report.id.endsWith(`-packages-${body.reportRunId}`)
  ));
  if (!packageReports.length) {
    return NextResponse.json({ ok: false, message: "Новые отчёты инвентаря пакетов не найдены." }, { status: 409 });
  }

  const results: Array<{ hostAlias: string; vulnerabilityReportId?: string; dependencyTrack?: string; partial?: boolean; error?: string }> = [];
  for (const packageReport of packageReports) {
    const hostAlias = targetAliasFromReport(packageReport);
    try {
      const scan = await scanPackageInventory({ reportId: packageReport.id, hostAlias });
      const sbomFile = (scan.report as { vulnerabilityScan?: { sbomFile?: unknown } }).vulnerabilityScan?.sbomFile;
      let dependencyTrack: string | undefined;
      if (typeof sbomFile === "string" && scan.reportId) {
        try {
          dependencyTrack = (await syncDependencyTrack({ hostAlias, vulnerabilityReportId: scan.reportId })).message;
        } catch (error) {
          dependencyTrack = `Не передан: ${error instanceof Error ? error.message : "неизвестная ошибка"}`;
        }
      }
      const partial = Boolean((scan.report as { vulnerabilityScan?: { partial?: boolean } }).vulnerabilityScan?.partial);
      results.push({ hostAlias, vulnerabilityReportId: scan.reportId, dependencyTrack, partial });
    } catch (error) {
      results.push({ hostAlias, error: error instanceof Error ? error.message : "неизвестная ошибка" });
    }
  }

  const failed = results.filter((result) => result.error || result.partial);
  appendIncident({
    action: "scheduledPackageVulnerabilityScan",
    kind: "audit",
    status: failed.length ? "failed" : "success",
    profileId: "cve_packages",
    limit: null,
    message: `Плановая проверка пакетов: ${results.length - failed.length}/${results.length} хостов обработано.`,
  });
  return NextResponse.json({ ok: failed.length === 0, reportRunId: body.reportRunId, results }, { status: failed.length ? 207 : 200 });
}
