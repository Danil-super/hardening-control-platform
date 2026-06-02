import { getFindingsByProfile } from "@/data/findings";
import { getProfile } from "@/data/profiles";
import { getRemediationsForFindings, remediations } from "@/data/remediations";
import type { AuditReport, BackupRecord, BeforeAfterReport, Finding } from "@/types";
import { buildSummary } from "@/lib/scoring";

export const auditSteps = [
  "Подготовка профиля",
  "Запуск демо-проверок",
  "Нормализация найденных проблем",
  "Расчет оценки защищенности",
  "Генерация отчета",
];

export const remediationSteps = [
  "Резервная копия создана",
  "Исправления применены",
  "Проверка пройдена",
  "Повторный аудит завершен",
];

function slugify(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function formatBackupTimestamp(date: Date) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function formatBackupName(profileId: string, remediationTitle: string, index: number, date: Date) {
  const humanDate = date.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
  return `Резервная копия ${index + 1}: ${remediationTitle} · ${profileId} · ${humanDate}`;
}

export function createAuditReport(profileId: string, findings?: Finding[]): AuditReport {
  const profile = getProfile(profileId);
  const reportFindings = findings ?? getFindingsByProfile(profileId);

  return {
    id: `audit_${profileId}_${Date.now()}`,
    createdAt: new Date().toISOString(),
    profileId: profile?.id ?? profileId,
    mode: "demo",
    summary: buildSummary(reportFindings),
    findings: reportFindings,
  };
}

export function createBeforeAfterReport(
  profileId: string,
  remediationIds: string[],
): BeforeAfterReport {
  const before = createAuditReport(profileId);
  const selectedRemediations = remediations.filter((remediation) =>
    remediationIds.includes(remediation.id),
  );
  const fixableFindingIds = new Set(selectedRemediations.flatMap((remediation) => remediation.findingIds));
  const createdAt = new Date();
  const now = createdAt.toISOString();

  const afterFindings = before.findings.map((finding) => {
    if (fixableFindingIds.has(finding.id)) {
      return { ...finding, status: "fixed" as const };
    }
    return finding;
  });

  const backups: BackupRecord[] = selectedRemediations.map((remediation, index) => ({
    id: `backup-${profileId}-${slugify(remediation.id)}-${formatBackupTimestamp(createdAt)}-${String(index + 1).padStart(2, "0")}`,
    name: formatBackupName(profileId, remediation.title, index, createdAt),
    description: remediation.backupRequired
      ? `Снимок затронутых файлов перед действием: ${remediation.title}.`
      : `Журнал действия без файлового снимка: ${remediation.title}.`,
    createdAt: now,
    remediationId: remediation.id,
    targetFiles: remediation.targetFiles,
    status: remediation.backupRequired ? "created" : "skipped",
    rollbackAvailable: remediation.rollbackAvailable,
  }));

  const after = createAuditReport(profileId, afterFindings);
  const fixedFindings = afterFindings.filter((finding) => finding.status === "fixed");
  const remainingFindings = afterFindings.filter(
    (finding) => finding.status !== "fixed" && finding.status !== "passed",
  );
  const manualFindings = remainingFindings.filter((finding) => !finding.remediationAvailable);

  return {
    before,
    after,
    appliedRemediations: selectedRemediations,
    backups,
    fixedFindings,
    remainingFindings,
    manualFindings,
  };
}

export function getAvailableRemediationsForProfile(profileId: string) {
  const findings = getFindingsByProfile(profileId);
  return getRemediationsForFindings(findings.map((finding) => finding.id));
}
