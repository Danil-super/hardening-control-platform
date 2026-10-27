import { readAnsibleReport } from "@/lib/ansible-reports";
import { reportIdForRun, type PlaybookAction } from "@/lib/ansible-control";
import { getInventoryTargetHosts } from "@/lib/inventory";

export function auditReportLimitations(raw: unknown): string[] {
  if (!raw || typeof raw !== "object") return [];
  const report = raw as { scanner?: { partialReasons?: unknown; reason?: unknown; error?: unknown; ruleResultCounts?: unknown }; findings?: unknown };
  const reasons = report.scanner?.partialReasons;
  const explicit = Array.isArray(reasons) ? reasons.filter((reason): reason is string => typeof reason === "string" && Boolean(reason.trim())) : [];
  if (!explicit.length) {
    for (const value of [report.scanner?.reason, report.scanner?.error]) {
      if (typeof value === "string" && value.trim()) explicit.push(value);
    }
  }
  const counts = report.scanner?.ruleResultCounts;
  if (!explicit.length && counts && typeof counts === "object") {
    const selected = Object.entries(counts).filter(([state, count]) => state !== "notselected" && typeof count === "number" && count > 0);
    if (selected.length === 1 && selected[0][0] === "notapplicable") {
      explicit.push(`OpenSCAP отметил все выбранные правила (${selected[0][1]}) как неприменимые. Проверьте соответствие профиля ОС и определение платформы CPE; настройки хоста не оценены.`);
    }
  }
  if (!explicit.length && Array.isArray(report.findings)) {
    for (const finding of report.findings) {
      if (finding && /^openscap_(prerequisite_missing|arf_unreadable|no_rule_results|incomplete)$/.test(finding.id)
          && typeof finding.description === "string" && finding.description.trim()) explicit.push(finding.description);
    }
  }
  return Array.from(new Set(explicit.map((reason) => reason.trim().slice(0, 2000)))).slice(0, 3);
}

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
      const detail = auditReportLimitations(report.raw).join(" ");
      warnings.push(`${alias}: ${report.available === false ? "сканер не выполнил проверку. " : ""}${detail || "проверка неполная; ограничения указаны в отчёте."}`);
    }
  }
  return { reportIds, partial: warnings.length > 0, warnings };
}
