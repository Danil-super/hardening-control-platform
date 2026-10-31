import { reportIdForRun, runAnsiblePlaybook } from "@/lib/ansible-control";
import { readAnsibleReport, targetAliasFromReport } from "@/lib/ansible-reports";
import { auditReportLimitations } from "@/lib/audit-result";
import { getInventoryTargetHosts } from "@/lib/inventory";

export type ScheduledAuditResult = {
  hostAlias: string;
  reportId?: string;
  partial: boolean;
  warnings: string[];
  error?: string;
  errorCode?: string;
};

export function isScheduledLimit(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(value);
}

/** Scheduled collection uses the same authenticated execution and publication
 * path as a manual audit. Run hosts separately so each selects its compatible
 * Ansible runtime, and retain an explicit result for every requested host. */
export async function runScheduledInventoryAudit({ action, profileId, limit }: {
  action: "agentlessAudit" | "packageInventory";
  profileId: string;
  limit: string;
}): Promise<ScheduledAuditResult[]> {
  if (!isScheduledLimit(limit)) throw new Error("Укажите один точный alias хоста или группы inventory.");
  const aliases = [...new Set(getInventoryTargetHosts(limit)
    .filter((host) => host.groups.includes("linux_hosts")).map((host) => host.alias))];
  if (!aliases.length) throw new Error("В выбранной цели нет хостов linux_hosts; проверка не запущена.");

  const results: ScheduledAuditResult[] = [];
  for (const hostAlias of aliases) {
    let reportId: string | undefined;
    try {
      // Never accept a one-time sudo password or caller-supplied extra vars in
      // this path. The common runner rejects on-demand sudo before execution.
      const execution = await runAnsiblePlaybook({ action, profileId, limit: hostAlias });
      reportId = reportIdForRun({ action, profileId, limit: hostAlias, reportRunId: execution.reportRunId }) ?? undefined;
      const report = reportId ? readAnsibleReport(reportId) : null;
      if (!report) throw new Error("Ожидаемый отчёт не создан или повреждён.");
      if (report.mode !== (action === "packageInventory" ? "packages" : "agentless") || targetAliasFromReport(report) !== hostAlias) {
        throw new Error("Опубликованный отчёт не соответствует выбранному хосту или типу проверки.");
      }
      const partial = report.partial || !report.reportTimeValid || report.available === false;
      const warnings = partial ? auditReportLimitations(report.raw) : [];
      if (partial && !warnings.length) warnings.push("Проверка неполная; ограничения указаны в отчёте.");
      results.push({ hostAlias, reportId, partial, warnings });
    } catch (error) {
      const code = error instanceof Error ? (error as Error & { code?: unknown }).code : undefined;
      results.push({ hostAlias, ...(reportId ? { reportId } : {}), partial: true, warnings: [],
        ...(typeof code === "string" ? { errorCode: code } : {}),
        error: error instanceof Error ? error.message : "Неизвестная ошибка планового аудита." });
    }
  }
  return results;
}
