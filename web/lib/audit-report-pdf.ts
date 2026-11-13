import { createHash } from "node:crypto";
import { readAnsibleReport, type AnsibleReportDetail } from "@/lib/ansible-reports";
import { readNativeReportFile } from "@/lib/native-report-storage";
import { runPdfRenderer } from "@/lib/project-report";
import { withReportEvidenceLock } from "@/lib/state-store";
import { auditReportLimitations } from "@/lib/audit-result";

const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const text = (value: unknown) => typeof value === "string" || typeof value === "number" ? String(value) : "";

export function auditPdfSnapshot(report: AnsibleReportDetail, sourceSha256: string) {
  const raw = record(report.raw);
  const scanner = record(raw.scanner);
  const inventory = record(raw.packageInventory);
  const packages = Array.isArray(raw.packages) ? raw.packages : inventory.packages;
  return {
    kind: "audit", id: report.id, hostAlias: report.inventoryHost ?? report.host,
    hostname: report.hostname, os: report.os, mode: report.mode, profileId: report.profileId,
    createdAt: report.createdAt, exportedAt: new Date().toISOString(), sourceSha256,
    partial: report.partial, available: report.available, reportTimeValid: report.reportTimeValid,
    assetBinding: report.assetBinding?.status === "verified" ? { version: 1, status: "verified", assetId: report.assetBinding.assetId, generation: report.assetBinding.generation }
      : report.assetBinding?.status === "unknown" ? { version: 1, status: "unknown", reason: "unauthenticated_network_scan" } : null,
    assetBindingInvalid: report.assetBindingInvalid === true, contentId: report.contentId ?? null, scanScope: report.scanScope ?? null,
    score: report.mode === "lynis" ? report.score : null,
    limitations: auditReportLimitations(raw),
    findings: report.findings.map(item => ({ id: item.id, title: item.title, category: item.category,
      risk: item.risk, severityUnknown: item.severityUnknown, severityAssessment: item.severityAssessment ? { level: item.severityAssessment.level, source: item.severityAssessment.source } : undefined,
      lynisKind: item.lynis?.kind,
      status: item.status, source: item.source, description: item.description, recommendation: item.recommendation })),
    events: report.events.map(item => ({ source: text(item.source), message: text(item.message) })),
    facts: report.mode === "facts" ? Object.fromEntries(["kernel", "architecture", "memoryMb", "processorCount", "virtualizationType", "virtualizationRole"].map(key => [key, text(raw[key])])) : {},
    packages: report.mode === "packages" && Array.isArray(packages) ? packages.map(record).map(item => ({ name: text(item.name), version: text(item.version), architecture: text(item.arch) || text(item.architecture) })) : [],
    scanner: { name: text(scanner.name), version: text(scanner.version) },
  };
}

export async function renderAuditReportPdf(reportId: string) {
  const snapshot = withReportEvidenceLock(() => {
    const report = readAnsibleReport(reportId);
    if (!report) return null;
    const original = readNativeReportFile(report.path, 64 * 1024 * 1024);
    if (JSON.stringify(JSON.parse(original.toString("utf8"))) !== JSON.stringify(report.raw)) throw new Error("report_changed");
    return auditPdfSnapshot(report, createHash("sha256").update(original).digest("hex"));
  });
  if (!snapshot) return null;
  return { pdf: await runPdfRenderer(snapshot), id: snapshot.id, sourceSha256: snapshot.sourceSha256 };
}
