import { createHash, randomUUID } from "node:crypto";
import { closeSync, constants, existsSync, fstatSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { getReportsDir } from "@/lib/ansible-reports";
import { getStateDir } from "@/lib/ansible-control";
import { withReportEvidenceLock } from "@/lib/state-store";
import type { Finding } from "@/types";

type Json = Record<string, unknown>;
type Component = { group: string; name: string; version: string; purl: string; cpe: string };
type Binding = {
  version: 1; hostAlias: string; sourceCveReport: string; sourceReportSha256: string;
  sbomFile: string; sbomSha256: string; componentManifestSha256: string; componentCount: number;
  endpointId: string; projectName: string; projectVersion: string; processingToken: string;
  uploadedAt: string; serverUploadTime: number | null;
};
type Settings = { configured: true; baseUrl: string; apiKey: string };
const MAX_BYTES = 32 * 1024 * 1024;
const MAX_ITEMS = 30_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const SOURCE_LIMITATION = "Полнота и успешность синхронизации источников уязвимостей Dependency-Track не подтверждены этим API-ответом. Отсутствие находок не подтверждает отсутствие CVE.";
const digest = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const record = (value: unknown): Json => value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};
const text = (value: unknown, maximum = 16_000) => typeof value === "string" ? value.slice(0, maximum) : "";
const safeReportId = (value: unknown): value is string => typeof value === "string" && /^[a-zA-Z0-9_.:-]{1,160}$/.test(value);

function configuration() {
  const baseUrl = process.env.HCP_DEPENDENCY_TRACK_URL?.trim();
  const apiKey = process.env.HCP_DEPENDENCY_TRACK_API_KEY?.trim();
  if (!baseUrl || !apiKey) return { configured: false as const };
  try {
    const url = new URL(baseUrl);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error("url");
    return { configured: true as const, baseUrl: url.toString().replace(/\/$/, ""), apiKey };
  } catch { throw new Error("HCP_DEPENDENCY_TRACK_URL должен быть корректным HTTP(S) URL."); }
}

function readFile(file: string) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > MAX_BYTES) throw new Error("Исходник должен быть обычным файлом не больше 32 МиБ.");
    const bytes = readFileSync(fd);
    if (bytes.length > MAX_BYTES) throw new Error("Исходник превысил 32 МиБ во время чтения.");
    return bytes;
  } finally { closeSync(fd); }
}

function readRawReport(reportId: string) {
  if (!safeReportId(reportId)) throw new Error("Некорректный идентификатор отчёта.");
  const bytes = readFile(path.join(getReportsDir(), `${reportId}.json`));
  return { raw: record(JSON.parse(bytes.toString("utf8"))), sha256: digest(bytes) };
}

function component(value: unknown): Component {
  const row = record(value);
  if (typeof row.name !== "string" || !row.name || typeof row.version !== "string" || !row.version
      || ["group", "purl", "cpe"].some((key) => row[key] != null && typeof row[key] !== "string")
      || ["group", "name", "version", "purl", "cpe"].some((key) => typeof row[key] === "string" && (row[key].length > 8192 || row[key].includes("\0")))) {
    throw new Error("Компонент SBOM/Dependency-Track имеет неполную или неподдерживаемую идентичность.");
  }
  return { group: text(row.group), name: row.name, version: row.version, purl: text(row.purl), cpe: text(row.cpe) };
}

function componentKey(row: Component) { return JSON.stringify([row.group, row.name, row.version, row.purl, row.cpe]); }
function manifest(rows: unknown[]) {
  if (!rows.length || rows.length > MAX_ITEMS) throw new Error("SBOM не содержит компонентов либо превышает предел 30 000 компонентов.");
  const keys = rows.map((row) => componentKey(component(row))).sort();
  if (new Set(keys).size !== keys.length) throw new Error("Повторяющиеся идентичности компонентов не позволяют однозначно проверить импорт SBOM.");
  return { sha256: digest(JSON.stringify(keys)), count: keys.length };
}

function source(hostAlias: string, reportId: string) {
  const { raw, sha256 } = readRawReport(reportId);
  if (raw.inventoryHost !== hostAlias || raw.mode !== "vulnerabilities") throw new Error("CVE-отчёт не принадлежит выбранному хосту. Сначала выполните CVE-аудит этого хоста.");
  const sbomFile = record(raw.vulnerabilityScan).sbomFile;
  if (!safeReportId(sbomFile)) throw new Error("В CVE-отчёте нет CycloneDX SBOM. Запустите проверку пакетов через Trivy.");
  const bytes = readFile(path.join(getStateDir(), "sbom", sbomFile));
  const document = record(JSON.parse(bytes.toString("utf8")));
  if (document.bomFormat !== "CycloneDX" || !Array.isArray(document.components) || !document.components.length) throw new Error("SBOM не содержит компонентов CycloneDX для анализа. Повторите сбор пакетов хоста.");
  if (document.components.some((item) => Array.isArray(record(item).components) && (record(item).components as unknown[]).length)) throw new Error("Вложенные компоненты SBOM пока не поддерживаются проверяемым импортом Dependency-Track.");
  return { report: raw, sourceSha256: sha256, bytes, sbomFile, sbomSha256: digest(bytes), manifest: manifest(document.components) };
}

/** No upstream response bodies are surfaced in errors: proxies may echo credentials. */
async function request(settings: Settings, endpoint: string, signal: AbortSignal, init?: RequestInit) {
  let response: Response;
  try {
    response = await fetch(`${settings.baseUrl}${endpoint}`, { ...init, signal, redirect: "error", cache: "no-store",
      headers: { "Accept": "application/json", "Content-Type": "application/json", "X-Api-Key": settings.apiKey } });
  } catch { throw new Error("Не удалось получить ответ Dependency-Track: сеть, перенаправление или таймаут."); }
  if (!response.ok) throw new Error(`Dependency-Track вернул HTTP ${response.status}. Проверьте доступность API и разрешения ключа.`);
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Dependency-Track вернул пустой ответ API.");
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_BYTES) { await reader.cancel(); throw new Error("Ответ Dependency-Track превышает 32 МиБ; импорт не завершён."); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  let data: unknown;
  try { data = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new Error("Dependency-Track вернул некорректный JSON API."); }
  return { data, headers: response.headers, byteLength: size };
}

async function list(settings: Settings, endpoint: string, signal: AbortSignal, identity: (row: Json) => string) {
  const rows: Json[] = []; const seen = new Set<string>(); let expected: number | null = null; let receivedBytes = 0;
  for (let page = 1; page <= 301; page++) {
    const { data, headers, byteLength } = await request(settings, `${endpoint}${endpoint.includes("?") ? "&" : "?"}pageNumber=${page}&pageSize=1000`, signal);
    receivedBytes += byteLength;
    if (receivedBytes > MAX_BYTES) throw new Error("Полный список Dependency-Track превышает 32 МиБ. Импорт не завершён.");
    const count = headers.get("x-total-count");
    if (count === null || !/^\d+$/.test(count)) throw new Error("Dependency-Track не подтвердил полное количество элементов ответа.");
    const total = Number(count);
    if (!Number.isSafeInteger(total) || total > MAX_ITEMS || expected !== null && total !== expected || !Array.isArray(data)) throw new Error("Количество результатов Dependency-Track изменилось или превышает допустимый предел.");
    expected = total;
    for (const value of data) {
      const row = record(value); const key = identity(row);
      if (!key || seen.has(key)) throw new Error("Dependency-Track вернул повторяющиеся либо неполные элементы; пагинация не подтверждена.");
      seen.add(key); rows.push(row);
    }
    if (rows.length === total) return rows;
    if (!data.length || rows.length > total) throw new Error("Dependency-Track вернул усечённый или несогласованный список.");
  }
  throw new Error("Пагинация Dependency-Track не завершилась в допустимых пределах.");
}

function summary(findings: Finding[]) {
  const failed = findings.filter((item) => item.status === "failed");
  return { score: null, high: failed.filter((item) => item.risk === "high").length, medium: failed.filter((item) => item.risk === "medium").length,
    low: failed.filter((item) => item.risk === "low").length, info: findings.filter((item) => item.risk === "info").length, total: findings.length };
}

function manual(id: string, title: string, description: string): Finding {
  return { id, profileId: "dependency-track", title, category: "Компоненты и CVE", risk: "info", status: "manual", source: "dependency_track", description,
    recommendation: "Проверьте завершение анализа, настройки и актуальность источников в Dependency-Track. Выполните отдельную проверку применимости CVE.", remediationAvailable: false };
}

/** Publish immutable reports; never modify a historical report already used by a plan/PDF. */
function publish(reportId: string, output: Json, validate: () => void) {
  return withReportEvidenceLock(() => {
    validate();
    mkdirSync(getReportsDir(), { recursive: true });
    const target = path.join(getReportsDir(), `${reportId}.json`);
    if (existsSync(target)) {
      const previous = readRawReport(reportId).raw;
      if (previous.inventoryHost !== output.inventoryHost || previous.mode !== output.mode
          || record(previous.scanner).resultFingerprint !== record(output.scanner).resultFingerprint) throw new Error("Сохранённый идентификатор результата занят другим отчётом.");
      validateBinding(record(previous.scanner).binding);
      return false;
    }
    const serialized = JSON.stringify(output, null, 2);
    if (Buffer.byteLength(serialized) > MAX_BYTES) throw new Error("Итоговый отчёт превышает 32 МиБ. Импорт не опубликован.");
    const temporary = path.join(getReportsDir(), `.dependency-track-${randomUUID()}.tmp`);
    try {
      const fd = openSync(temporary, "wx", 0o600);
      try { writeFileSync(fd, serialized); fsyncSync(fd); } finally { closeSync(fd); }
      linkSync(temporary, target);
    } finally { if (existsSync(temporary)) unlinkSync(temporary); }
    return true;
  });
}

function validateBinding(value: unknown): Binding {
  const row = record(value);
  if (row.version !== 1 || !safeReportId(row.hostAlias) || !safeReportId(row.sourceCveReport) || !safeReportId(row.sbomFile)
      || ![row.sourceReportSha256, row.sbomSha256, row.componentManifestSha256, row.endpointId].every((item) => typeof item === "string" && SHA.test(item))
      || !Number.isSafeInteger(row.componentCount) || Number(row.componentCount) < 1 || Number(row.componentCount) > MAX_ITEMS
      || row.projectName !== row.hostAlias || row.projectVersion !== `hcp-sbom:${row.sbomSha256}`
      || typeof row.processingToken !== "string" || !UUID.test(row.processingToken)
      || typeof row.uploadedAt !== "string" || !Number.isFinite(Date.parse(row.uploadedAt))
      || row.serverUploadTime !== null && (!Number.isFinite(row.serverUploadTime) || Number(row.serverUploadTime) <= 0)) {
    throw new Error("Отчёт не содержит проверяемую привязку к SBOM. Для старой передачи заново отправьте исходный CVE-отчёт.");
  }
  return row as Binding;
}

function verifySource(binding: Binding) {
  const current = source(binding.hostAlias, binding.sourceCveReport);
  if (current.sourceSha256 !== binding.sourceReportSha256 || current.sbomFile !== binding.sbomFile || current.sbomSha256 !== binding.sbomSha256
      || current.manifest.sha256 !== binding.componentManifestSha256 || current.manifest.count !== binding.componentCount) throw new Error("Исходный CVE-отчёт или SBOM изменился после передачи. Результат не импортирован.");
  return current;
}

export async function syncDependencyTrack({ hostAlias, vulnerabilityReportId }: { hostAlias: string; vulnerabilityReportId: string }) {
  if (!safeReportId(hostAlias) || hostAlias.length > 96 || !safeReportId(vulnerabilityReportId)) throw new Error("Укажите корректный alias хоста и идентификатор CVE-отчёта.");
  const settings = configuration();
  if (!settings.configured) return { configured: false as const, message: "Dependency-Track не настроен: SBOM сохранён локально, передача не выполнялась." };
  const input = source(hostAlias, vulnerabilityReportId);
  const endpointId = digest(settings.baseUrl);
  const key = digest(JSON.stringify([hostAlias, vulnerabilityReportId, input.sourceSha256, input.sbomSha256, endpointId]));
  const reportId = `${hostAlias}-dependency-track-run-${key.slice(0, 24)}`;
  if (existsSync(path.join(getReportsDir(), `${reportId}.json`))) {
    const prior = readRawReport(reportId).raw;
    const binding = validateBinding(record(prior.scanner).binding);
    verifySource(binding);
    if (binding.endpointId !== endpointId || binding.hostAlias !== hostAlias) throw new Error("Сохранённая передача принадлежит другой конфигурации Dependency-Track.");
    return { configured: true as const, reportId, reused: true, message: "Этот SBOM уже передан. Откройте отчёт и проверьте результат анализа." };
  }
  const uploadedAt = new Date().toISOString();
  const projectVersion = `hcp-sbom:${input.sbomSha256}`;
  const response = await request(settings, "/api/v1/bom", AbortSignal.timeout(45_000), { method: "PUT", body: JSON.stringify({
    projectName: hostAlias, projectVersion, autoCreate: true, bom: input.bytes.toString("base64"),
  }) });
  const token = record(response.data).token;
  if (typeof token !== "string" || !UUID.test(token)) throw new Error("Dependency-Track не вернул токен обработки SBOM. Проверьте URL API-сервера и ответ сервиса.");
  const serverDate = Date.parse(response.headers.get("date") ?? "");
  // HTTP Date is rounded to seconds and generated for the response. The import
  // may already finish while the response is travelling. Derive a conservative
  // request-start bound on the server clock instead of rejecting that valid race.
  const serverUploadTime = Number.isFinite(serverDate) ? serverDate - Math.max(0, Date.now() - Date.parse(uploadedAt)) - 1000 : null;
  const binding: Binding = { version: 1, hostAlias, sourceCveReport: vulnerabilityReportId, sourceReportSha256: input.sourceSha256,
    sbomFile: input.sbomFile, sbomSha256: input.sbomSha256, componentManifestSha256: input.manifest.sha256, componentCount: input.manifest.count,
    endpointId, projectName: hostAlias, projectVersion, processingToken: token, uploadedAt, serverUploadTime };
  const findings = [manual("dependency_track_sbom_uploaded", "CycloneDX SBOM передан в Dependency-Track", "SBOM принят в очередь. Откройте проверку результата: приём не подтверждает завершение CVE-анализа.")];
  const output = { schemaVersion: 1, action: "dependencyTrackSync", runId: `run-${key.slice(0, 24)}`, inventoryHost: hostAlias, hostname: hostAlias,
    createdAt: uploadedAt, os: input.report.os ?? null, profileId: "dependency-track", mode: "dependency-track",
    scanner: { source: "dependency_track", sbomFile: input.sbomFile, sourceCveReport: vulnerabilityReportId, processingToken: token, binding, analysisStatus: "pending", partial: true },
    summary: summary(findings), findings, events: [] };
  const written = publish(reportId, output, () => { verifySource(binding); });
  return { configured: true as const, reportId, reused: !written, message: "SBOM передан в Dependency-Track. Откройте отчёт и проверьте результат асинхронного анализа." };
}

function timestamp(value: unknown) {
  const number = typeof value === "number" ? value : typeof value === "string" ? Date.parse(value) : NaN;
  return Number.isFinite(number) && number > 0 ? number : null;
}

function eventProcessing(value: unknown) {
  const event = record(value);
  if (event.status === "FAILED") throw new Error("Dependency-Track сообщил об ошибке обработки SBOM.");
  // 4.14.3 defines only the boolean. Do not guess the meaning of a different
  // API generation's status enum when deciding whether an import completed.
  if (event.status != null || typeof event.processing !== "boolean") throw new Error("Dependency-Track вернул неподдерживаемое состояние асинхронной обработки.");
  return event.processing;
}

function findingsFrom(rows: Json[], components: Json[], projectUuid: string): Finding[] {
  const componentByUuid = new Map(components.map((row) => [String(row.uuid), component(row)]));
  return rows.map((row) => {
    const c = record(row.component), v = record(row.vulnerability), analysis = record(row.analysis), attribution = record(row.attribution);
    const known = componentByUuid.get(String(c.uuid));
    if (!known || componentKey(component(c)) !== componentKey(known) || row.project != null && row.project !== projectUuid
        || c.project != null && c.project !== projectUuid || typeof v.uuid !== "string" || !UUID.test(v.uuid)
        || typeof v.vulnId !== "string" || !v.vulnId || typeof v.source !== "string" || !v.source
        || analysis.isSuppressed != null && typeof analysis.isSuppressed !== "boolean") throw new Error("Находка Dependency-Track не принадлежит проверенному компоненту/проекту либо не содержит идентификатор уязвимости.");
    const severity = text(v.severity).toLowerCase();
    const level = ["critical", "high", "medium", "low"].includes(severity) ? severity as "critical" | "high" | "medium" | "low" : null;
    const suppressed = analysis.isSuppressed === true || ["FALSE_POSITIVE", "NOT_AFFECTED", "RESOLVED"].includes(String(analysis.state));
    const aliases = Array.isArray(v.aliases) ? v.aliases.flatMap((item) => Object.values(record(item)).filter((value): value is string => typeof value === "string")) : [];
    return { id: `dependency_track_${digest(JSON.stringify([componentKey(known), v.source, v.vulnId])).slice(0, 24)}`, profileId: "dependency-track", source: "dependency_track",
      title: `${text(v.vulnId, 200)}: ${known.name} ${known.version}`, category: "Компоненты и CVE", status: suppressed ? "manual" : "failed",
      risk: level === "critical" ? "high" : level ?? "info", severityUnknown: !level,
      ...(level ? { severityAssessment: { level, source: "scanner_metadata" as const } } : {}),
      description: [text(v.description) || text(v.title) || "Dependency-Track сопоставил установленный компонент с записью уязвимости.",
        suppressed ? `Решение Dependency-Track: ${text(analysis.state) || "suppressed"}. Требуется отдельная оценка применимости; находка сохранена.` : "",
        text(analysis.detail)].filter(Boolean).join("\n"),
      recommendation: text(v.recommendation) || "Сверьте уведомление поставщика и исправленную версию для конкретного компонента. Обновление пакетов требует отдельного плана изменений.",
      remediationAvailable: false,
      evidence: JSON.stringify({ projectUuid, componentUuid: c.uuid, component: known, source: v.source, vulnerabilityId: v.vulnId, aliases,
        severity: text(v.severity), cvssV3: v.cvssV3BaseScore ?? null, cvssV4: v.cvssV4Score ?? null,
        attribution: { analyzerIdentity: attribution.analyzerIdentity ?? null, referenceUrl: attribution.referenceUrl ?? null }, analysis }),
    } satisfies Finding;
  });
}

export async function refreshDependencyTrack({ hostAlias, reportId }: { hostAlias: string; reportId: string }) {
  if (!safeReportId(hostAlias) || hostAlias.length > 96 || !safeReportId(reportId)) throw new Error("Укажите корректный хост и отчёт Dependency-Track.");
  const settings = configuration();
  if (!settings.configured) throw new Error("Dependency-Track не настроен. Укажите URL API и ключ доступа.");
  const selected = readRawReport(reportId);
  const deliveryReportId = selected.raw.mode === "dependency-track-analysis" ? record(selected.raw.scanner).deliveryReportId : reportId;
  if (!safeReportId(deliveryReportId)) throw new Error("В результате отсутствует исходный отчёт передачи SBOM.");
  const delivery = readRawReport(deliveryReportId);
  if (selected.raw.inventoryHost !== hostAlias || delivery.raw.inventoryHost !== hostAlias || delivery.raw.mode !== "dependency-track") throw new Error("Отчёт Dependency-Track не принадлежит выбранному хосту.");
  const binding = validateBinding(record(delivery.raw.scanner).binding);
  if (binding.hostAlias !== hostAlias || binding.endpointId !== digest(settings.baseUrl)) throw new Error("URL Dependency-Track или идентичность хоста изменились после передачи SBOM.");
  const input = verifySource(binding);
  const processing = (message: string) => ({ configured: true as const, status: "processing" as const, deliveryReportId, partial: true, message });
  const signal = AbortSignal.timeout(45_000);
  const event = eventProcessing((await request(settings, `/api/v1/event/token/${binding.processingToken}`, signal)).data);
  if (event) return processing("Dependency-Track ещё обрабатывает SBOM или анализирует компоненты.");
  const query = new URLSearchParams({ name: binding.projectName, version: binding.projectVersion });
  const before = record((await request(settings, `/api/v1/project/lookup?${query}`, signal)).data);
  if (before.name !== binding.projectName || before.version !== binding.projectVersion || typeof before.uuid !== "string" || !UUID.test(before.uuid)) throw new Error("Dependency-Track вернул другой проект: привязка к хосту и SHA-256 SBOM не подтверждена.");
  const imported = timestamp(before.lastBomImport), analyzed = timestamp(before.lastVulnerabilityAnalysis);
  // 4.14 also returns processing=false for unknown tokens. Require an actual
  // imported manifest and analysis newer than that import. HTTP Date uses the
  // server clock; a missing date cannot silently certify an old analysis.
  if (!binding.serverUploadTime) throw new Error("API не предоставил серверное время загрузки. Завершение анализа этой передачи достоверно не установлено.");
  if (!imported || imported < binding.serverUploadTime || !analyzed || analyzed < imported) return processing("Приём SBOM подтверждён, но более новый завершённый анализ проекта пока не подтверждён.");
  const projectUuid = before.uuid;
  const components = await list(settings, `/api/v1/component/project/${projectUuid}`, signal, (row) => typeof row.uuid === "string" && UUID.test(row.uuid) ? row.uuid : "");
  const observed = manifest(components);
  if (observed.sha256 !== binding.componentManifestSha256 || observed.count !== binding.componentCount) throw new Error("Компоненты проекта не совпадают с полным переданным SBOM. Результат не импортирован.");
  const rows = await list(settings, `/api/v1/finding/project/${projectUuid}?suppressed=true`, signal, (row) => {
    const c = record(row.component), v = record(row.vulnerability);
    return typeof c.uuid === "string" && typeof v.uuid === "string" ? `${c.uuid}:${v.uuid}` : "";
  });
  const after = record((await request(settings, `/api/v1/project/${projectUuid}`, signal)).data);
  const afterEvent = eventProcessing((await request(settings, `/api/v1/event/token/${binding.processingToken}`, signal)).data);
  if (afterEvent || after.name !== before.name || after.version !== before.version || after.uuid !== before.uuid
      || timestamp(after.lastBomImport) !== imported || timestamp(after.lastVulnerabilityAnalysis) !== analyzed) return processing("Проект изменился во время чтения результата. Повторите получение после завершения анализа.");
  const findings = findingsFrom(rows, components, projectUuid);
  findings.push(manual("dependency_track_coverage_unverified", "Полнота источников Dependency-Track требует проверки", SOURCE_LIMITATION));
  const resultFingerprint = digest(JSON.stringify({ binding, projectUuid, imported, analyzed, rows }));
  const analysisReportId = `${hostAlias}-dependency-track-analysis-run-${resultFingerprint.slice(0, 24)}`;
  const output = { schemaVersion: 1, action: "dependencyTrackRefresh", runId: `run-${resultFingerprint.slice(0, 24)}`, inventoryHost: hostAlias, hostname: hostAlias,
    os: input.report.os ?? null, profileId: "dependency-track", mode: "dependency-track-analysis", createdAt: new Date(analyzed).toISOString(), importedAt: new Date().toISOString(),
    scanner: { source: "dependency_track", analysisStatus: "complete", processingComplete: true, available: true, partial: true, partialReasons: [SOURCE_LIMITATION],
      deliveryReportId, sourceCveReport: binding.sourceCveReport, sbomFile: binding.sbomFile, binding, projectUuid, resultFingerprint,
      lastBomImport: imported, lastVulnerabilityAnalysis: analyzed, componentCount: components.length, findingCount: rows.length, findingsComplete: true,
      sourceCoverageVerified: false }, summary: summary(findings), findings, events: [] };
  const written = publish(analysisReportId, output, () => {
    verifySource(binding);
    if (readRawReport(deliveryReportId).sha256 !== delivery.sha256) throw new Error("Отчёт передачи изменился во время получения результата.");
  });
  return { configured: true as const, status: "complete" as const, reportId: analysisReportId, deliveryReportId, partial: true, reused: !written, findingCount: rows.length,
    message: `Результат Dependency-Track получен: ${rows.length} находок. Полнота источников остаётся неподтверждённой.` };
}
