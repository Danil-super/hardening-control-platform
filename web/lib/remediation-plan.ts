import { buildHostCorrelation } from "@/lib/audit-correlation";
import { hashAnsibleReport, readAnsibleReport, reportTimestamp } from "@/lib/ansible-reports";
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
  return { items: listRemediationPlanItems(hostAlias), correlation: buildHostCorrelation(hostAlias) };
}

export function addCorrelatedFindingToPlan(hostAlias: string, findingKey: string) {
  if (!safeAlias(hostAlias) || !safeFindingKey(findingKey)) throw new Error("Укажите корректный хост и находку.");
  const correlation = buildHostCorrelation(hostAlias);
  const finding = correlation?.findings.find((item) => item.id === findingKey);
  if (!finding || !finding.sources.length) throw new Error("Свежая находка не найдена. Повторите аудит и откройте обновлённую сводку хоста.");
  const evidence = finding.sources.map((source) => {
    const report = readAnsibleReport(source.reportId);
    const checksum = hashAnsibleReport(source.reportId);
    if (!report || !checksum) throw new Error("Один из исходных отчётов больше недоступен. Повторите аудит перед созданием плана.");
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
    if (!report || report.inventoryHost !== current.hostAlias && report.host !== current.hostAlias) {
      throw new Error("Повторный отчёт не относится к этому хосту.");
    }
    if (report.partial || !report.available || !report.reportTimeValid || reportTimestamp(report) <= Date.parse(current.updatedAt)) {
      throw new Error("Для подтверждения нужен полный свежий отчёт, созданный после выполнения меры.");
    }
  }
  return transitionRemediationPlanItem(input.id, input);
}

export function planItemDetail(id: string) {
  const item = getRemediationPlanItem(id);
  return item ? { item, history: listRemediationPlanHistory(id) } : null;
}
