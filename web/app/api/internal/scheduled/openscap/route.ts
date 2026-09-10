import { NextResponse } from "next/server";
import { appendIncident, reportIdForRun, runAnsiblePlaybook } from "@/lib/ansible-control";
import { inspectAuditReports } from "@/lib/audit-result";
import { getInventoryTargetHosts } from "@/lib/inventory";
import { applyOpenScapExceptions, resolveOpenScapPolicyForHost } from "@/lib/openscap-policy";
import { isScheduledRequestAuthorized, isScheduledRunId } from "@/lib/scheduled-auth";
import { listOpenScapExceptions } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!isScheduledRequestAuthorized(request)) return NextResponse.json({ ok: false, message: "Недействительный ключ планировщика." }, { status: 401 });
  const body = await request.json().catch(() => ({}));
  if (!isScheduledRunId(body?.reportRunId) || typeof body?.limit !== "string") {
    return NextResponse.json({ ok: false, message: "Некорректные параметры планового OpenSCAP-аудита." }, { status: 400 });
  }
  try {
    const hosts = getInventoryTargetHosts(body.limit).filter((host) => host.groups.includes("linux_hosts"));
    if (!hosts.length) throw new Error("В выбранной цели нет хостов linux_hosts.");
    // Resolve every profile before any scan so an ambiguous group cannot
    // produce a partially applied configuration across the scheduled fleet.
    const selections = hosts.map((host) => ({ hostAlias: host.alias, resolved: resolveOpenScapPolicyForHost(host.alias) }));
    const exceptions = listOpenScapExceptions();
    const results = [];
    for (const { hostAlias, resolved } of selections) {
      try {
        const result = await runAnsiblePlaybook({
          action: "openScapAudit", profileId: "basic_linux", limit: hostAlias,
          extraVars: resolved.policy ? {
            hcp_openscap_datastream: resolved.policy.datastream,
            hcp_openscap_profile: resolved.policy.profile,
            hcp_openscap_policy_group: resolved.policy.groupName,
          } : {},
        });
        const reportId = reportIdForRun({ action: "openScapAudit", profileId: "basic_linux", limit: hostAlias, reportRunId: result.reportRunId });
        if (!reportId) throw new Error("Не получен идентификатор отчёта OpenSCAP.");
        const annotation = applyOpenScapExceptions({ hostAlias, reportId, resolved, exceptions });
        const outcome = inspectAuditReports({ action: "openScapAudit", profileId: "basic_linux", limit: hostAlias, reportRunId: result.reportRunId });
        results.push({ hostAlias, reportId, policyGroup: resolved.policy?.groupName ?? "environment", exceptionsApplied: annotation.applied, partial: outcome.partial, warnings: outcome.warnings });
      } catch (error) {
        results.push({ hostAlias, partial: true, error: error instanceof Error ? error.message : "Неизвестная ошибка OpenSCAP." });
      }
    }
    const partial = results.some((result) => result.partial);
    appendIncident({ action: "scheduledOpenScapAudit", kind: "audit", status: partial ? "failed" : "success", profileId: "openscap", limit: body.limit,
      message: `Плановый OpenSCAP: ${results.filter((result) => !result.partial).length}/${results.length} полных проверок.`, runId: body.reportRunId });
    return NextResponse.json({ ok: !partial, partial, reportRunId: body.reportRunId, results }, { status: partial ? 207 : 200 });
  } catch (error) {
    return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Ошибка планового OpenSCAP." }, { status: 400 });
  }
}
