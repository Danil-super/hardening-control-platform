import { buildHostCorrelation } from "@/lib/audit-correlation";
import { hashAnsibleReport, readAnsibleReport } from "@/lib/ansible-reports";
import { assertPlanVerification, resolvePlanSeverity } from "@/lib/remediation-plan-evidence";
import { planObservationState } from "@/lib/remediation-plan-observations";
import {
  createRemediationPlanItem,
  getRemediationPlanItem,
  listRemediationPlanHistory,
  listRemediationPlanItems,
  transitionRemediationPlanItem,
  type RemediationPlanStatus,
} from "@/lib/state-store";

function safeAlias(value: unknown) {
  return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,96}$/.test(value);
}

function safeFindingKey(value: unknown) {
  return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,160}$/.test(value);
}

export function remediationPlanForHost(hostAlias: string) {
  if (!safeAlias(hostAlias)) throw new Error("Укажите корректный alias хоста.");
  const correlation = buildHostCorrelation(hostAlias);
  const current = new Map(correlation?.findings.map((finding) => [finding.id, finding]));
  return { items: listRemediationPlanItems(hostAlias).map((item) => ({ ...resolvePlanSeverity(item),
    ...planObservationState(item, current.get(item.findingKey)) })), correlation };
}

export function addCorrelatedFindingToPlan(hostAlias: string, findingKey: string) {
  if (!safeAlias(hostAlias) || !safeFindingKey(findingKey)) throw new Error("Укажите корректный хост и находку.");
  const correlation = buildHostCorrelation(hostAlias);
  const finding = correlation?.findings.find((item) => item.id === findingKey);
  if (!finding || !finding.sources.length) throw new Error("Свежая находка не найдена. Повторите аудит и откройте обновлённую сводку хоста.");
  const checksums = new Map<string, string>();
  const evidence = finding.sources.map((source) => {
    let checksum = checksums.get(source.reportId);
    if (!checksum) {
      const report = readAnsibleReport(source.reportId);
      checksum = hashAnsibleReport(source.reportId) ?? undefined;
      if (!report || !checksum) throw new Error("Один из исходных отчётов больше недоступен. Повторите аудит перед созданием плана.");
      checksums.set(source.reportId, checksum);
    }
    return {
      reportId: source.reportId,
      findingId: source.findingId,
      source: source.source,
      mode: source.mode,
      createdAt: source.createdAt,
      evidence: source.evidence,
      reportSha256: checksum,
    };
  });
  return createRemediationPlanItem({
    hostAlias,
    findingKey,
    title: finding.title,
    category: finding.category,
    risk: finding.risk,
    severityUnknown: finding.severityUnknown,
    severityAssessment: finding.severityAssessment ?? null,
    description: finding.description,
    recommendation: finding.recommendation,
    evidence,
  });
}

export function advanceRemediationPlanItem(input: {
  id: string; status: RemediationPlanStatus; note?: unknown; owner?: unknown; dueAt?: unknown; approvalReference?: unknown;
  verificationReportId?: unknown; riskAcceptedUntil?: unknown;
}) {
  const current = getRemediationPlanItem(input.id);
  if (!current) throw new Error("Пункт плана устранения не найден.");
  if (input.status === "confirmed") {
    if (typeof input.verificationReportId !== "string") throw new Error("Для подтверждения выберите повторный отчёт.");
    const report = readAnsibleReport(input.verificationReportId);
    if (!report) throw new Error("Повторный отчёт не найден.");
    assertPlanVerification(current, report);
  }
  return transitionRemediationPlanItem(input.id, { ...input, expectedUpdatedAt: current.updatedAt });
}

export function planItemDetail(id: string) {
  const item = getRemediationPlanItem(id);
  if (!item) return null;
  const current = buildHostCorrelation(item.hostAlias)?.findings.find((finding) => finding.id === item.findingKey);
  return { item: { ...resolvePlanSeverity(item), ...planObservationState(item, current) }, history: listRemediationPlanHistory(id) };
}
