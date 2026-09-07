import { timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { appendIncident } from "@/lib/ansible-control";
import { listAnsibleReports, targetAliasFromReportFileName } from "@/lib/ansible-reports";
import { syncDependencyTrack } from "@/lib/dependency-track";
import { scanPackageInventory } from "@/lib/vulnerability-scan";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function isAuthorized(request: Request) {
  const expected = process.env.HCP_SCHEDULE_API_KEY?.trim();
  const received = request.headers.get("x-hcp-schedule-key")?.trim();
  if (!expected || !received || expected.length !== received.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(expected), Buffer.from(received));
}

function safeRunId(value: unknown): value is string {
  return typeof value === "string" && /^schedule-[A-Za-z0-9_.:-]{8,120}$/.test(value);
}

export async function POST(request: Request) {
  if (!isAuthorized(request)) {
    return NextResponse.json({ ok: false, message: "Недействительный ключ планировщика." }, { status: 401 });
  }
  const body = await request.json().catch(() => ({}));
  if (!safeRunId(body?.reportRunId)) {
    return NextResponse.json({ ok: false, message: "Некорректный reportRunId планировщика." }, { status: 400 });
  }

  const packageReports = listAnsibleReports().filter((report) => (
    report.mode === "packages" && report.id.endsWith(`-packages-${body.reportRunId}`)
  ));
  if (!packageReports.length) {
    return NextResponse.json({ ok: false, message: "Новые отчёты инвентаря пакетов не найдены." }, { status: 409 });
  }

  const results: Array<{ hostAlias: string; vulnerabilityReportId?: string; dependencyTrack?: string; error?: string }> = [];
  for (const packageReport of packageReports) {
    const hostAlias = targetAliasFromReportFileName(packageReport.fileName, packageReport.profileId, packageReport.mode);
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
      results.push({ hostAlias, vulnerabilityReportId: scan.reportId, dependencyTrack });
    } catch (error) {
      results.push({ hostAlias, error: error instanceof Error ? error.message : "неизвестная ошибка" });
    }
  }

  const failed = results.filter((result) => result.error);
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
