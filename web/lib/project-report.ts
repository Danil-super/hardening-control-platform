import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { buildHostCorrelation } from "@/lib/audit-correlation";
import { hashAnsibleReport, listAnsibleReports, targetAliasFromReport } from "@/lib/ansible-reports";
import { resolvePlanSeverity } from "@/lib/remediation-plan-evidence";
import { hasActivePlanDecision, planObservationState } from "@/lib/remediation-plan-observations";
import { getHcpStateDirectory, getArchivedRecordIds, createProjectReportRecord, getProjectReportRecord, listProjectReportRecords, listRemediationPlanItems, listRemediationTransactions, verifyAuditChain, withReportEvidenceLock, type ArchiveView, type ProjectReportRecord } from "@/lib/state-store";

export type ProjectReportSubject = { clientName: string; projectName: string; period: string; specialist: string };
export type ProjectReportSourceReference = { id: string; hostAlias: string; snapshotReadable: boolean };

type SourceManifestEntry = { id: string; mode: string; profileId: string | null; createdAt: string | null; partial: boolean; available: boolean; reportTimeValid: boolean; sha256: string | null;
  scanScope: string | null; portCoverage: string | null; coverageComplete: boolean | null };

function safeAlias(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,96}$/.test(value);
}

function subjectText(value: unknown, field: string, maximum: number) {
  if (typeof value !== "string") throw new Error(`Укажите поле «${field}».`);
  const text = value.trim();
  if (text.length < 2 || text.length > maximum || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)) throw new Error(`Поле «${field}» должно содержать от 2 до ${maximum} символов.`);
  return text;
}

function normalizeSubject(input: Partial<ProjectReportSubject>): ProjectReportSubject {
  return {
    clientName: subjectText(input.clientName, "заказчик", 200),
    projectName: subjectText(input.projectName, "проект", 200),
    period: subjectText(input.period, "период работ", 120),
    specialist: subjectText(input.specialist, "специалист", 200),
  };
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}

function sha256(value: string | Buffer) {
  return createHash("sha256").update(value).digest("hex");
}

function projectReportsDirectory() {
  const directory = path.join(getHcpStateDirectory(), "project-reports");
  if (!existsSync(directory)) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Хранилище итоговых отчётов имеет недопустимый тип.");
  chmodSync(directory, 0o700);
  return directory;
}

function safeProjectPath(fileName: string) {
  if (!/^project-report-[a-f0-9-]{36}\.(?:pdf|json)$/.test(fileName)) throw new Error("Некорректное имя итогового отчёта.");
  return path.join(projectReportsDirectory(), fileName);
}

function writeSecure(pathname: string, content: string | Buffer) {
  const temporary = `${pathname}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, content, { mode: 0o600, flag: "wx" });
    chmodSync(temporary, 0o600);
    renameSync(temporary, pathname);
  } finally {
    if (existsSync(temporary)) rmSync(temporary, { force: true });
  }
}

function runPdfRenderer(snapshot: Record<string, unknown>): Promise<Buffer> {
  const input = Buffer.from(JSON.stringify(snapshot), "utf8");
  // A complete 30,000-definition OVAL audit can produce thousands of CVEs.
  // Raw scanner trees never enter this bounded, projected snapshot.
  if (input.length > 32 * 1024 * 1024) return Promise.reject(new Error("Снимок отчёта превышает допустимый размер (32 МБ)."));
  return new Promise((resolve, reject) => {
    const script = path.join(process.cwd(), "..", "ansible", "scripts", "hcp-final-report-pdf.py");
    const child = spawn("/usr/bin/python3", [script], { stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    let size = 0;
    let stopped = false;
    const timer = setTimeout(() => { stopped = true; child.kill("SIGKILL"); }, 120_000);
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > 12 * 1024 * 1024) { stopped = true; child.kill("SIGKILL"); return; }
      chunks.push(chunk);
    });
    child.stderr.on("data", () => { /* renderer diagnostics may contain paths; never return or log them */ });
    child.on("error", () => { clearTimeout(timer); reject(new Error("Средство формирования PDF недоступно. Пересоберите HCP из актуального Dockerfile.")); });
    child.on("close", (code) => {
      clearTimeout(timer);
      const output = Buffer.concat(chunks);
      if (stopped || code !== 0 || !output.subarray(0, 5).equals(Buffer.from("%PDF-"))) {
        reject(new Error("Не удалось безопасно сформировать итоговый PDF-отчёт."));
      } else resolve(output);
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}

function evidenceSnapshot(value: { reportId: string; findingId: string; source: string; mode: string; createdAt: string | null; evidence: string; reportSha256: string }) {
  return { reportId: value.reportId, findingId: value.findingId, source: value.source, mode: value.mode, createdAt: value.createdAt,
    evidence: value.evidence, reportSha256: value.reportSha256 };
}

export function listProjectReports(hostAlias?: string, view: ArchiveView = "active") {
  return listProjectReportRecords(hostAlias, view);
}

/**
 * A final PDF contains an immutable snapshot of its source report manifest.
 * Do not let raw source evidence disappear while that manifest references it.
 */
export function listProjectReportSourceReferences(reportId: string, hostAlias: string): ProjectReportSourceReference[] {
  if (!/^[A-Za-z0-9_.:-]{1,180}$/.test(reportId) || !safeAlias(hostAlias)) return [];
  const references: ProjectReportSourceReference[] = [];
  for (const projectReport of listProjectReportRecords(hostAlias, "all")) {
    const snapshotFileName = projectReport.fileName.replace(/\.pdf$/, ".json");
    try {
      const snapshotPath = safeProjectPath(snapshotFileName);
      const info = lstatSync(snapshotPath, { throwIfNoEntry: false });
      if (!info || !info.isFile() || info.isSymbolicLink()) {
        references.push({ id: projectReport.id, hostAlias: projectReport.hostAlias, snapshotReadable: false });
        continue;
      }
      const snapshot = JSON.parse(readFileSync(snapshotPath, "utf8")) as { sourceManifest?: unknown };
      const sourceManifest = Array.isArray(snapshot.sourceManifest) ? snapshot.sourceManifest : [];
      if (sourceManifest.some((source) => source && typeof source === "object" && !Array.isArray(source) && (source as Record<string, unknown>).id === reportId)) {
        references.push({ id: projectReport.id, hostAlias: projectReport.hostAlias, snapshotReadable: true });
      }
    } catch {
      // A broken final-report snapshot is itself a retention reason until an
      // operator investigates it; deleting raw evidence would make it worse.
      references.push({ id: projectReport.id, hostAlias: projectReport.hostAlias, snapshotReadable: false });
    }
  }
  return references;
}

export async function createProjectReport(input: { hostAlias: unknown; subject: Partial<ProjectReportSubject> }) {
  if (!safeAlias(input.hostAlias)) throw new Error("Выберите корректный целевой хост.");
  const hostAlias = input.hostAlias;
  const subject = normalizeSubject(input.subject);
  const createdAt = new Date().toISOString();
  const planItems = listRemediationPlanItems(hostAlias).map(resolvePlanSeverity);
  // Filter in SQLite before any limit. Final exports include all history for
  // this host; the overall snapshot/PDF size guards fail explicitly if too big.
  const storedTransactions = listRemediationTransactions(null, hostAlias);
  const requiredSources = new Set([...planItems.flatMap((item) => [...item.evidence.map((source) => source.reportId), item.verificationReportId]),
    ...storedTransactions.flatMap((item) => [item.preAuditReportId, item.postAuditReportId])]);
  const archived = getArchivedRecordIds("report");
  const reports = listAnsibleReports("all").filter((report) => targetAliasFromReport(report) === hostAlias && (!archived.has(report.id) || requiredSources.has(report.id)));
  if (!reports.length) throw new Error("Для итогового отчёта нужен хотя бы один сохранённый отчёт этого хоста.");
  const sourceManifest: SourceManifestEntry[] = reports.map((report) => ({
    id: report.id, mode: report.mode, profileId: report.profileId, createdAt: report.createdAt, partial: report.partial,
    available: report.available, reportTimeValid: report.reportTimeValid, sha256: hashAnsibleReport(report.id),
    scanScope: report.scanScope ?? null, portCoverage: report.portCoverage ?? null, coverageComplete: report.coverageComplete ?? null,
  })).sort((left, right) => left.id.localeCompare(right.id));
  const sourceManifestSha256 = sha256(canonical({ version: 1, hostAlias, sourceManifest }));
  const correlation = buildHostCorrelation(hostAlias);
  const now = Date.parse(createdAt);
  const current = new Map(correlation?.findings.map((finding) => [finding.id, finding]));
  const activeKeys = new Set(planItems.filter((item) => hasActivePlanDecision(item, now)).map((item) => item.findingKey));
  const findings = planItems.map((item) => ({
    id: item.id, findingKey: item.findingKey, title: item.title, category: item.category, risk: item.risk, status: item.status,
    severityUnknown: item.severityUnknown,
    severityAssessment: item.severityAssessment,
    severityOrigin: item.severityOrigin,
    description: item.description, recommendation: item.recommendation, owner: item.owner, dueAt: item.dueAt,
    approvalReference: item.approvalReference, implementationNote: item.implementationNote, verificationReportId: item.verificationReportId,
    riskAcceptedUntil: item.riskAcceptedUntil, evidence: item.evidence.map(evidenceSnapshot), createdAt: item.createdAt, updatedAt: item.updatedAt,
    ...planObservationState(item, current.get(item.findingKey), now),
  }));
  const recurringKeys = new Set(findings.filter((item) => item.currentObservation?.recurring).map((item) => item.findingKey));
  const unplannedFindings = (correlation?.findings ?? []).filter((item) => !activeKeys.has(item.id)).map((item) => ({
    id: item.id, title: item.title, category: item.category, risk: item.risk, description: item.description.slice(0, 1200),
    status: item.status, severityUnknown: item.severityUnknown, severityAssessment: item.severityAssessment ?? null,
    recurring: recurringKeys.has(item.id),
    recommendation: item.recommendation.slice(0, 1200), sources: item.sources.map((source) => ({ reportId: source.reportId, findingId: source.findingId, mode: source.mode, source: source.source })),
  }));
  const coverage = correlation?.coverage ?? [];
  const transactions = storedTransactions.map((item) => ({
    id: item.id, createdAt: item.createdAt, updatedAt: item.updatedAt, action: item.action, profileId: item.profileId, status: item.status,
    reason: item.reason, preAuditReportId: item.preAuditReportId, postAuditReportId: item.postAuditReportId,
  }));
  const id = `project_report_${randomUUID()}`;
  const fileName = `project-report-${id.slice("project_report_".length)}.pdf`;
  const snapshotFileName = fileName.replace(/\.pdf$/, ".json");
  const snapshot: Record<string, unknown> = {
    version: 1, id, createdAt, hostAlias, subject, scope: { auditModes: Array.from(new Set(reports.map((report) => report.mode))).sort() },
    coverage, lostCoverage: correlation?.lostCoverage ?? [], findings, unplannedFindings, transactions, integrity: verifyAuditChain(), sourceManifest, sourceManifestSha256,
  };
  const pdf = await runPdfRenderer(snapshot);
  const pdfSha256 = sha256(pdf);
  const snapshotText = canonical({ ...snapshot, pdfSha256 });
  const snapshotSha256 = sha256(snapshotText);
  const pdfPath = safeProjectPath(fileName);
  const snapshotPath = safeProjectPath(snapshotFileName);
  try {
    return withReportEvidenceLock(() => {
      // Rendering is asynchronous. An operator may delete or replace a source
      // while Python is working; never publish a manifest of vanished evidence.
      for (const source of sourceManifest) {
        if (!source.sha256 || hashAnsibleReport(source.id) !== source.sha256) {
          throw new Error("Исходный отчёт изменился или был удалён во время формирования PDF. Обновите данные и повторите экспорт.");
        }
      }
      writeSecure(pdfPath, pdf);
      writeSecure(snapshotPath, snapshotText + "\n");
      const record = createProjectReportRecord({ id, createdAt, hostAlias, fileName, pdfSha256, snapshotSha256, sourceManifestSha256, subject });
      if (!record) throw new Error("Не удалось зафиксировать экспорт в журнале HCP.");
      return record;
    });
  } catch (error) {
    for (const pathname of [pdfPath, snapshotPath]) if (existsSync(pathname)) rmSync(pathname, { force: true });
    throw error;
  }
}

export function readProjectReportPdf(id: string): { record: ProjectReportRecord; pdf: Buffer } | null {
  const record = getProjectReportRecord(id);
  if (!record) return null;
  const pathname = safeProjectPath(record.fileName);
  const info = lstatSync(pathname, { throwIfNoEntry: false });
  if (!info || !info.isFile() || info.isSymbolicLink()) throw new Error("Файл итогового отчёта недоступен или имеет недопустимый тип.");
  const pdf = readFileSync(pathname);
  if (!pdf.subarray(0, 5).equals(Buffer.from("%PDF-")) || sha256(pdf) !== record.pdfSha256) {
    throw new Error("Контрольная сумма итогового отчёта не совпадает. Не передавайте этот файл заказчику до проверки хранилища.");
  }
  return { record, pdf };
}
