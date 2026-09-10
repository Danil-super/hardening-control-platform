import { readAnsibleReport } from "@/lib/ansible-reports";
import { reportIdForRun, type PlaybookAction } from "@/lib/ansible-control";
import { getInventoryTargetHosts } from "@/lib/inventory";

export function inspectAuditReports({ action, profileId, limit, reportRunId }: {
  action: PlaybookAction; profileId: string; limit?: string; reportRunId: string | null;
}) {
  const reportIds: string[] = [];
  const warnings: string[] = [];
  const hosts = new Set((limit || "linux_hosts").split(",").flatMap((target) => getInventoryTargetHosts(target))
    .filter((host) => host.groups.includes("linux_hosts")).map((host) => host.alias));
  for (const alias of hosts) {
    const reportId = reportIdForRun({ action, profileId, limit: alias, reportRunId });
    if (!reportId) continue;
    const report = readAnsibleReport(reportId);
    if (!report) { warnings.push(`${alias}: ожидаемый отчёт не создан или повреждён.`); continue; }
    reportIds.push(reportId);
    if (report.partial || !report.reportTimeValid) {
      warnings.push(`${alias}: проверка неполная; ограничения указаны в отчёте.`);
    }
  }
  return { reportIds, partial: warnings.length > 0, warnings };
}
