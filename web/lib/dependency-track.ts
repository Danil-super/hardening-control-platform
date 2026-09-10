import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { getReportsDir } from "@/lib/ansible-reports";
import { getStateDir } from "@/lib/ansible-control";
import type { Finding } from "@/types";

type VulnerabilityReport = {
  inventoryHost?: string;
  hostname?: string;
  mode?: string;
  os?: string;
  vulnerabilityScan?: {
    sbomFile?: unknown;
    sourcePackageReportId?: unknown;
  };
};

function safeReportId(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_.:-]{1,160}$/.test(value);
}

function configuration() {
  const baseUrl = process.env.HCP_DEPENDENCY_TRACK_URL?.trim();
  const apiKey = process.env.HCP_DEPENDENCY_TRACK_API_KEY?.trim();
  if (!baseUrl || !apiKey) {
    return { configured: false as const };
  }
  try {
    const url = new URL(baseUrl);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || url.search || url.hash) throw new Error("protocol");
    return { configured: true as const, baseUrl: url.toString().replace(/\/$/, ""), apiKey };
  } catch {
    throw new Error("HCP_DEPENDENCY_TRACK_URL должен быть корректным HTTP(S) URL.");
  }
}

function readVulnerabilityReport(reportId: string) {
  const reportPath = path.join(getReportsDir(), `${reportId}.json`);
  if (!reportPath.startsWith(getReportsDir() + path.sep) || !existsSync(reportPath)) {
    throw new Error("CVE-отчёт для передачи в Dependency-Track не найден.");
  }
  const report = JSON.parse(readFileSync(reportPath, "utf8")) as VulnerabilityReport;
  const sbomFile = typeof report.vulnerabilityScan?.sbomFile === "string" ? report.vulnerabilityScan.sbomFile : "";
  if (!safeReportId(sbomFile)) {
    throw new Error("В CVE-отчёте нет CycloneDX SBOM. Запустите проверку пакетов через Trivy.");
  }
  const sbomPath = path.join(getStateDir(), "sbom", sbomFile);
  const sbomDir = path.join(getStateDir(), "sbom");
  if (!sbomPath.startsWith(sbomDir + path.sep) || !existsSync(sbomPath)) {
    throw new Error("Сохранённый CycloneDX SBOM не найден. Повторите CVE-аудит пакетов.");
  }
  return { report, sbomFile, sbomPath };
}

function summary(findings: Finding[]) {
  const failed = findings.filter((item) => item.status === "failed");
  return {
    score: null,
    high: failed.filter((item) => item.risk === "high").length,
    medium: failed.filter((item) => item.risk === "medium").length,
    low: failed.filter((item) => item.risk === "low").length,
    info: findings.filter((item) => item.risk === "info").length,
    total: findings.length,
  };
}

export async function syncDependencyTrack({ hostAlias, vulnerabilityReportId }: { hostAlias: string; vulnerabilityReportId: string }) {
  if (!safeReportId(hostAlias) || !safeReportId(vulnerabilityReportId)) {
    throw new Error("Укажите корректный alias хоста и идентификатор CVE-отчёта.");
  }
  const settings = configuration();
  if (!settings.configured) {
    return {
      configured: false,
      message: "Dependency-Track не настроен: SBOM сохранён локально, передача не выполнялась.",
    };
  }
  const { report, sbomFile, sbomPath } = readVulnerabilityReport(vulnerabilityReportId);
  if (report.inventoryHost !== hostAlias || report.mode !== "vulnerabilities") {
    throw new Error("CVE-отчёт не принадлежит выбранному хосту. Сначала выполните CVE-аудит этого хоста.");
  }
  const sbom = readFileSync(sbomPath);
  const document = JSON.parse(sbom.toString("utf8")) as { bomFormat?: string; components?: unknown[] };
  if (document.bomFormat !== "CycloneDX" || !Array.isArray(document.components) || document.components.length === 0) {
    throw new Error("SBOM не содержит компонентов CycloneDX для анализа. Повторите сбор пакетов хоста.");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45_000);
  let response: Response;
  let responseText: string;
  try {
    response = await fetch(`${settings.baseUrl}/api/v1/bom`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-Api-Key": settings.apiKey },
      body: JSON.stringify({
        projectName: hostAlias,
        projectVersion: report.os || "inventory",
        autoCreate: true,
        bom: sbom.toString("base64"),
      }),
      signal: controller.signal,
      redirect: "error",
    });
    responseText = await response.text();
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    throw new Error(`Dependency-Track вернул ${response.status}: ${responseText.slice(0, 240)}`);
  }
  let token: string;
  try {
    const payload = JSON.parse(responseText) as { token?: unknown };
    if (typeof payload.token !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(payload.token)) {
      throw new Error("missing token");
    }
    token = payload.token;
  } catch {
    throw new Error("Dependency-Track не вернул токен обработки SBOM. Проверьте URL API-сервера и ответ сервиса.");
  }

  const runId = `run-${new Date().toISOString().replace(/[-:.]/g, "")}-${randomUUID().slice(0, 8)}`;
  const reportId = `${hostAlias}-dependency-track-${runId}`;
  const findings: Finding[] = [{
    id: "dependency_track_sbom_uploaded",
    profileId: "dependency-track",
    title: "CycloneDX SBOM передан в Dependency-Track",
    category: "Компоненты и CVE",
    risk: "info",
    status: "manual",
    source: "dependency_track",
    description: "Dependency-Track принял SBOM в очередь. Завершение анализа и отсутствие уязвимостей этим ответом не подтверждены.",
    recommendation: "Откройте проект хоста в Dependency-Track после завершения обработки и используйте его verdict как независимое доказательство по компонентам.",
    remediationAvailable: false,
    evidence: `sourceCveReport=${vulnerabilityReportId}; sbom=${sbomFile}; processingToken=${token}`,
  }];
  const output = {
    schemaVersion: 1,
    action: "dependencyTrackSync",
    runId,
    inventoryHost: hostAlias,
    createdAt: new Date().toISOString(),
    hostname: hostAlias,
    os: report.os ?? null,
    profileId: "dependency-track",
    mode: "dependency-track",
    scanner: { source: "dependency_track", endpoint: settings.baseUrl, sbomFile, sourceCveReport: vulnerabilityReportId, processingToken: token, analysisStatus: "pending", partial: true },
    summary: summary(findings),
    findings,
    events: [],
  };
  writeFileSync(path.join(getReportsDir(), `${reportId}.json`), JSON.stringify(output, null, 2), { mode: 0o600 });
  return { configured: true, reportId, message: "SBOM передан в Dependency-Track. Его анализ выполняется асинхронно." };
}
