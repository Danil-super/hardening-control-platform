import { correlationMaxAgeHours } from "@/lib/audit-correlation";
import { hashAnsibleReport, listAnsibleReports, readAnsibleReport, reportScopesCompatible, reportTimestamp, targetAliasFromReport, type AnsibleReportDetail } from "@/lib/ansible-reports";
import type { PlanEvidence, RemediationPlanItem } from "@/lib/state-store";
import type { Finding } from "@/types";

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function originalEvidence(item: RemediationPlanItem, evidence: PlanEvidence) {
  const report = readAnsibleReport(evidence.reportId);
  if (!report || targetAliasFromReport(report) !== item.hostAlias || hashAnsibleReport(evidence.reportId) !== evidence.reportSha256) return null;
  const finding = report.findings.find((candidate) => candidate.id === evidence.findingId && candidate.source === evidence.source);
  return finding ? { report, finding } : null;
}

/** Legacy records may only recover their rating from the exact original bytes. */
export function resolvePlanSeverity(item: RemediationPlanItem): RemediationPlanItem {
  if (item.severityOrigin !== "unknown_legacy") return item;
  const sources = item.evidence.map((evidence) => originalEvidence(item, evidence));
  if (!sources.length || sources.some((source) => !source)) return item;
  const findings = sources.flatMap((source) => source ? [source.finding] : []);
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  const assessment = findings.flatMap((finding) => finding.severityAssessment ? [finding.severityAssessment] : [])
    .sort((left, right) => order[right.level] - order[left.level])[0] ?? null;
  return { ...item, severityOrigin: "source_evidence", severityAssessment: assessment,
    severityUnknown: findings.every((finding) => finding.risk === "info") && findings.some((finding) => finding.severityUnknown === true) };
}

function cvePackage(finding: Finding) {
  const cve = `${finding.title}\n${finding.evidence ?? ""}`.match(/\bCVE-\d{4}-\d{4,8}\b/i)?.[0]?.toUpperCase();
  const packageName = finding.evidence?.match(/(?:^|;\s*)package=([^;\s]+)/)?.[1];
  return cve && packageName ? `${cve}\0${packageName}` : null;
}

function correspondingFindings(report: AnsibleReportDetail, original: Finding) {
  const component = original.source === "trivy" ? cvePackage(original) : null;
  return report.findings.filter((finding) => finding.source === original.source
    && (finding.id === original.id || component !== null && cvePackage(finding) === component));
}

function ovalDefinitionResolved(report: AnsibleReportDetail, original: Finding) {
  if (report.mode !== "astra-oval" || original.source !== "openscap" || original.status !== "failed") return false;
  const scanner = record(record(report.raw).scanner);
  if (scanner.evaluationPerformed !== true || !Array.isArray(scanner.definitionResults)) return false;
  const definitions = scanner.definitionResults.map(record).filter((definition) => definition.id === original.id);
  return definitions.length === 1 && definitions[0].class === "vulnerability" && definitions[0].result === "false"
    && ["astra_named", "not_verified"].includes(String(record(definitions[0].platformApplicability).status));
}

/** Absence is evidence only when the adapter proved coverage of a new full inventory. */
function trivyAbsenceResolved(item: RemediationPlanItem, report: AnsibleReportDetail, original: Finding) {
  if (report.mode !== "vulnerabilities" || original.source !== "trivy" || !cvePackage(original)) return false;
  const scan = record(record(report.raw).vulnerabilityScan);
  const coverage = record(scan.coverage);
  if (scan.provider !== "Trivy" || scan.partial === true || coverage.complete !== true
    || record(scan.databaseFreshness).status !== "fresh" || typeof scan.sourcePackageReportId !== "string") return false;
  const inventory = readAnsibleReport(scan.sourcePackageReportId);
  if (!inventory || inventory.mode !== "packages" || targetAliasFromReport(inventory) !== item.hostAlias
    || !inventory.available || inventory.partial || !inventory.reportTimeValid
    || reportTimestamp(inventory) <= Date.parse(item.updatedAt) || reportTimestamp(inventory) > reportTimestamp(report)) return false;
  const raw = record(inventory.raw);
  const packages = raw.packages;
  const metadata = record(raw.packageInventory);
  if (!Array.isArray(packages) || !packages.length || metadata.error || metadata.packageCount !== packages.length
    || !packages.every((value) => typeof record(value).name === "string" && Boolean(record(value).name)
      && typeof record(value).version === "string" && Boolean(record(value).version))) return false;
  return Number.isInteger(coverage.inventoryPackages) && Number(coverage.inventoryPackages) > 0
    && coverage.scannedPackages === coverage.inventoryPackages && scan.checkedPackages === coverage.scannedPackages;
}

export function assertPlanVerification(item: RemediationPlanItem, report: AnsibleReportDetail) {
  if (targetAliasFromReport(report) !== item.hostAlias) throw new Error("Повторный отчёт не относится к этому хосту.");
  const timestamp = reportTimestamp(report);
  if (report.partial || !report.available || !report.reportTimeValid || !report.createdAt
    || timestamp <= Date.parse(item.updatedAt) || timestamp < Date.now() - correlationMaxAgeHours() * 3_600_000) {
    throw new Error("Для подтверждения нужен полный свежий отчёт, созданный после выполнения меры.");
  }
  if (["facts", "events", "packages", "dependency-track"].includes(report.mode)) {
    throw new Error("Этот отчёт не проверяет устранение исходной находки.");
  }
  if (listAnsibleReports("all").some((candidate) => targetAliasFromReport(candidate) === item.hostAlias
    && reportScopesCompatible(candidate, report) && reportTimestamp(candidate) > timestamp)) {
    throw new Error("Есть более новый отчёт той же области. Для подтверждения используйте последнее наблюдение.");
  }

  const candidates = item.evidence.map((evidence) => originalEvidence(item, evidence))
    .filter((source) => source !== null && reportScopesCompatible(source.report, report));
  if (!candidates.length) {
    throw new Error("Не подтверждено совпадение исходного контроля, профиля и содержимого проверки. Нужен повторный отчёт той же области и неизменённое исходное доказательство.");
  }
  for (const source of candidates) {
    if (!source) continue;
    const corresponding = correspondingFindings(report, source.finding);
    if (corresponding.some((finding) => finding.status === "failed" || finding.status === "manual")) {
      throw new Error("Повторный отчёт всё ещё обнаруживает исходную проблему или требует ручной проверки. Подтверждение устранения отклонено.");
    }
    const resolved = corresponding.length
      ? corresponding.every((finding) => ["passed", "fixed"].includes(finding.status) && finding.profileId === source.finding.profileId)
      : ovalDefinitionResolved(report, source.finding) || trivyAbsenceResolved(item, report, source.finding);
    if (!resolved) {
      throw new Error("Повторный отчёт не содержит доказанного успешного результата исходного контроля для каждого исходного объекта. Исчезновение строки без подтверждённого охвата не доказывает исправление; оставьте пункт выполненным до проверяемого повторного аудита.");
    }
  }
}
