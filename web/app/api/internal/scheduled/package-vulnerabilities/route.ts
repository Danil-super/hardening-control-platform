import { NextResponse } from "next/server";
import { appendIncident } from "@/lib/ansible-control";
import { isScheduledRequestAuthorized, isScheduledRunId } from "@/lib/scheduled-auth";
import { isScheduledLimit, runScheduledInventoryAudit, type ScheduledAuditResult } from "@/lib/scheduled-audit";
import { syncDependencyTrack } from "@/lib/dependency-track";
import { scanPackageInventory } from "@/lib/vulnerability-scan";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!isScheduledRequestAuthorized(request)) {
    return NextResponse.json({ ok: false, message: "Недействительный ключ планировщика." }, { status: 401 });
  }
  const body = await request.json().catch(() => ({}));
  if (!isScheduledRunId(body?.reportRunId) || !isScheduledLimit(body?.limit)) {
    return NextResponse.json({ ok: false, message: "Некорректные параметры плановой проверки пакетов." }, { status: 400 });
  }

  let inventories: ScheduledAuditResult[];
  try {
    inventories = await runScheduledInventoryAudit({ action: "packageInventory", profileId: "basic_linux", limit: body.limit });
  } catch (error) {
    return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Ошибка плановой инвентаризации пакетов." }, { status: 400 });
  }

  const results: Array<{ hostAlias: string; packageReportId?: string; vulnerabilityReportId?: string; dependencyTrack?: string;
    dependencyTrackStatus?: "accepted" | "skipped" | "failed"; partial: boolean; warnings?: string[]; error?: string; errorCode?: string }> = [];
  for (const inventory of inventories) {
    const { hostAlias, reportId: packageReportId } = inventory;
    if (inventory.error || !packageReportId) {
      results.push({ hostAlias, packageReportId, partial: true, warnings: inventory.warnings, errorCode: inventory.errorCode,
        error: inventory.error ?? "Не получен новый инвентарь пакетов." });
      continue;
    }
    try {
      const scan = await scanPackageInventory({ reportId: packageReportId, hostAlias });
      let dependencyTrack: string;
      let dependencyTrackStatus: "accepted" | "skipped" | "failed";
      try {
        // The adapter distinguishes an optional, unconfigured integration from
        // a configured delivery that failed (including a missing saved SBOM).
        const delivery = await syncDependencyTrack({ hostAlias, vulnerabilityReportId: scan.reportId });
        dependencyTrack = delivery.message;
        dependencyTrackStatus = delivery.configured ? "accepted" : "skipped";
      } catch (error) {
        dependencyTrack = `Не передан: ${error instanceof Error ? error.message : "неизвестная ошибка"}`;
        dependencyTrackStatus = "failed";
      }
      const partial = inventory.partial || Boolean((scan.report as { vulnerabilityScan?: { partial?: boolean } }).vulnerabilityScan?.partial)
        || dependencyTrackStatus === "failed";
      results.push({ hostAlias, packageReportId, vulnerabilityReportId: scan.reportId, dependencyTrack, dependencyTrackStatus, partial, warnings: inventory.warnings });
    } catch (error) {
      results.push({ hostAlias, packageReportId, partial: true, warnings: inventory.warnings, error: error instanceof Error ? error.message : "неизвестная ошибка" });
    }
  }

  const failed = results.filter((result) => result.error || result.partial);
  appendIncident({
    action: "scheduledPackageVulnerabilityScan",
    kind: "audit",
    status: failed.length ? "failed" : "success",
    profileId: "cve_packages",
    limit: body.limit,
    runId: body.reportRunId,
    message: `Плановая проверка пакетов: ${results.length - failed.length}/${results.length} хостов обработано.`,
  });
  return NextResponse.json({ ok: failed.length === 0, partial: failed.length > 0, reportRunId: body.reportRunId, results }, { status: failed.length ? 207 : 200 });
}
