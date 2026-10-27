import { createHash } from "node:crypto";
import { listAnsibleReports } from "@/lib/ansible-reports";
import { archiveIncidentIds, listProjectReportRecords, setRecordArchive, type ArchiveRecord } from "@/lib/state-store";

export type ArchiveTarget = "reports" | "journal";
export type ArchiveAction = "archive" | "restore";

export function archivePreview(target: ArchiveTarget, action: ArchiveAction) {
  if (!["reports", "journal"].includes(target) || !["archive", "restore"].includes(action)) throw new Error("Выберите корректную операцию очистки.");
  const view = action === "archive" ? "active" : "archive";
  const records: ArchiveRecord[] = target === "journal"
    ? archiveIncidentIds(view).map((id) => ({ kind: "incident", id }))
    : [...listAnsibleReports(view).map((item) => ({ kind: "report" as const, id: item.id })),
      ...listProjectReportRecords(undefined, view).map((item) => ({ kind: "pdf" as const, id: item.id }))];
  records.sort((a, b) => `${a.kind}:${a.id}`.localeCompare(`${b.kind}:${b.id}`));
  const token = createHash("sha256").update(JSON.stringify({ target, action, records })).digest("hex");
  return { target, action, total: records.length, reports: records.filter((item) => item.kind === "report").length,
    pdf: records.filter((item) => item.kind === "pdf").length, journal: records.filter((item) => item.kind === "incident").length, token, records };
}

export function applyArchive(target: ArchiveTarget, action: ArchiveAction, token: string) {
  const preview = archivePreview(target, action);
  if (preview.token !== token) throw Object.assign(new Error("Список изменился. Откройте предварительный просмотр ещё раз перед подтверждением."), { code: "archive_preview_changed" });
  return setRecordArchive(preview.records, action);
}
