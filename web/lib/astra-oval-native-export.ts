import { constants } from "node:fs";
import { mkdir, mkdtemp, open, rm, type FileHandle } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import path from "node:path";

const MAX_XML = 384 * 1024 * 1024;
const MAX_JSON = 64 * 1024 * 1024;
const MAX_HTML = 256 * 1024 * 1024;
const TIMEOUT_MS = 120_000;
const CHUNK = 256 * 1024;
let activeExports = 0;
export type NativeExportFormat = "html" | "xml" | "source-xml" | "json" | "dat" | "sbom";
type Artifact = { kind: string; path: string; bytes: number; sha256: string };
type ExportSpec = { format: NativeExportFormat; kind: string; extension: string; label: string; generator?: "oval" | "xccdf" };
const reportFormats: Record<string, ExportSpec[]> = {
  "astra-oval": [
    { format: "html", kind: "oval-results", extension: "xml", label: "Отчёт OpenSCAP (HTML)", generator: "oval" },
    { format: "xml", kind: "oval-results", extension: "xml", label: "Результаты OVAL (XML)" },
    { format: "source-xml", kind: "source", extension: "xml", label: "База OVAL (XML)" },
  ],
  openscap: [
    { format: "html", kind: "arf", extension: "xml", label: "Отчёт OpenSCAP (HTML)", generator: "xccdf" },
    { format: "xml", kind: "arf", extension: "xml", label: "Результаты OpenSCAP (ARF XML)" },
    { format: "source-xml", kind: "source", extension: "xml", label: "Профиль OpenSCAP (XML)" },
  ],
  nmap: [{ format: "xml", kind: "nmap", extension: "xml", label: "Отчёт Nmap (XML)" }],
  "ssh-audit": [{ format: "json", kind: "ssh-audit", extension: "json", label: "Отчёт ssh-audit (JSON)" }],
  lynis: [{ format: "dat", kind: "lynis-report", extension: "dat", label: "Отчёт Lynis (report.dat)" }],
  vulnerabilities: [{ format: "json", kind: "trivy", extension: "json", label: "Отчёт Trivy (JSON)" }],
  greenbone: [{ format: "xml", kind: "greenbone", extension: "xml", label: "Отчёт Greenbone (XML)" }],
  "dependency-track-analysis": [{ format: "json", kind: "dependency-track", extension: "json", label: "Экспорт Dependency-Track (JSON)" }],
  "dependency-track": [{ format: "sbom", kind: "sbom", extension: "json", label: "Переданный SBOM HCP (CycloneDX JSON)" }],
};
function formatsFor(raw: unknown) {
  const report = record(raw);
  if (report.mode === "vulnerabilities" && record(report.vulnerabilityScan).provider !== "Trivy") return [];
  return reportFormats[String(report.mode)] ?? [];
}
export class NativeExportError extends Error {
  constructor(public code: string, message: string, public status = 409) { super(message); }
}
const unavailable = () => new NativeExportError("native_original_unavailable", "Оригинальный отчёт инструмента не сохранён или недоступен. Данные HCP не заменяют оригинал.", 404);
const integrity = () => new NativeExportError("native_integrity_failed", "Целостность оригинального отчёта не подтверждена. Экспорт заблокирован.");
const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
function canonicalId(value: string) {
  const id = value.endsWith(".json") ? value.slice(0, -5) : value;
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,219}$/.test(id)) throw unavailable();
  return id;
}
function artifactFromReport(raw: unknown, id: string, spec: ExportSpec): Artifact {
  const report = record(raw);
  const evidence = record(report.rawEvidence);
  if (!formatsFor(raw).some(item => item.kind === spec.kind) || evidence.version !== 1 || !Array.isArray(evidence.artifacts)) throw unavailable();
  const matches = evidence.artifacts.map(record).filter((entry) => entry.kind === spec.kind);
  if (!matches.length) throw unavailable();
  const entry = matches[0];
  if (matches.length !== 1 || entry.path !== `.raw-evidence/${id}/${spec.kind}.${spec.extension}`
    || typeof entry.bytes !== "number" || !Number.isSafeInteger(entry.bytes) || entry.bytes <= 0 || entry.bytes > MAX_XML
    || typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw integrity();
  const scanner = record(report.scanner);
  const scannerHash = report.mode === "astra-oval"
    ? spec.kind === "source" ? record(scanner.database).sha256 : scanner.resultSha256
    : report.mode === "openscap" ? spec.kind === "source" ? scanner.datastreamChecksum : scanner.rawResultSha256 : null;
  if (scannerHash != null && (typeof scannerHash !== "string" || scannerHash.replace(/^sha256:/, "").toLowerCase() !== entry.sha256)) throw integrity();
  return entry as Artifact;
}

async function directory(file: string) {
  return open(file, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
}
// Pin each parent directory as an fd, not merely a lstat followed by an open.
async function evidenceFile(reports: string, id: string, spec: ExportSpec) {
  const handles: FileHandle[] = [];
  try {
    for (const name of [reports, ".raw-evidence", id]) {
      const parent = handles.at(-1);
      handles.push(await directory(parent ? `/proc/self/fd/${parent.fd}/${name}` : name));
    }
    return await open(`/proc/self/fd/${handles.at(-1)!.fd}/${spec.kind}.${spec.extension}`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } finally { await Promise.all(handles.map((handle) => handle.close())); }
}
async function boundedManifest(reports: string, id: string) {
  const root = await directory(reports);
  let file: FileHandle | undefined;
  try {
    file = await open(`/proc/self/fd/${root.fd}/${id}.json`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = await file.stat();
    if (!before.isFile() || before.size <= 0 || before.size > MAX_JSON) throw integrity();
    const chunks: Buffer[] = [];
    let bytes = 0;
    for (;;) {
      const buffer = Buffer.allocUnsafe(CHUNK);
      const { bytesRead } = await file.read(buffer, 0, buffer.length, null);
      if (!bytesRead) break;
      bytes += bytesRead;
      if (bytes > MAX_JSON) throw integrity();
      chunks.push(buffer.subarray(0, bytesRead));
    }
    const after = await file.stat();
    if (bytes !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw integrity();
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } finally { await file?.close(); await root.close(); }
}

/** UI hints only: every download reopens and hashes the actual bytes. */
export async function nativeReportAvailability(reports: string, reportId: string, raw: unknown) {
  return Promise.all(formatsFor(raw).map(async spec => {
    let available = false;
    try {
      const id = canonicalId(reportId);
      const artifact = artifactFromReport(raw, id, spec);
      const file = await evidenceFile(reports, id, spec);
      try { const stat = await file.stat(); available = stat.isFile() && stat.size === artifact.bytes; }
      finally { await file.close(); }
    } catch { /* Missing originals must not be replaced with normalized data. */ }
    return { format: spec.format, label: spec.label, available };
  }));
}
export async function nativeOvalAvailability(reports: string, reportId: string, raw: unknown) {
  return record(raw).mode === "astra-oval" && (await nativeReportAvailability(reports, reportId, raw)).some(item => item.format === "xml" && item.available);
}

function xmlSafetyGuard() {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let tail = "";
  let declaration = "";
  let declarationChecked = false;
  return (buffer: Buffer, final = false) => {
    let text: string;
    let decoded: string;
    try { decoded = decoder.decode(buffer, { stream: !final }); } catch { throw new NativeExportError("unsafe_xml", "Для HTML требуется безопасный XML в UTF-8."); }
    text = tail + decoded;
    // A short read may end inside the permitted XML declaration marker.
    const instructions = final ? text : text.replace(/<\?(?:x(?:m(?:l\??)?)?)?$/i, "");
    if (/\0|<!\s*(?:DOCTYPE|ENTITY)|<(?:[\w.-]+:)?include\b/i.test(text) || /<\?(?!xml(?:\s|\?>))/i.test(instructions)) {
      throw new NativeExportError("unsafe_xml", "HTML не создаётся: XML содержит внешние сущности, инструкции или включения.");
    }
    if (!declarationChecked) {
      declaration = (declaration + decoded).trimStart();
      if (!"<?xml".startsWith(declaration) && !declaration.startsWith("<?xml")) {
        declarationChecked = true;
      } else {
        const end = declaration.indexOf("?>");
        if ((end < 0 && (final || declaration.length > 1024)) || end + 2 > 1024) {
          throw new NativeExportError("unsafe_xml", "HTML не создаётся: XML-декларация неполна или превышает допустимый размер.");
        }
        if (end >= 0) {
          const encoding = declaration.slice(0, end).match(/\bencoding\s*=\s*(["'])([^"']+)\1/i);
          if (encoding && !/^(?:utf-8|utf8|us-ascii)$/i.test(encoding[2])) {
            throw new NativeExportError("unsafe_xml", "Для HTML требуется XML с кодировкой UTF-8.");
          }
          declarationChecked = true;
        }
      }
      if (declarationChecked) declaration = "";
    }
    tail = text.slice(-256);
  };
}
async function snapshot(input: FileHandle, destination: string, artifact: Artifact, signal: AbortSignal, inspectXml: boolean) {
  const before = await input.stat();
  if (!before.isFile() || before.size !== artifact.bytes || before.size > MAX_XML) throw integrity();
  const output = await open(destination, "wx", 0o600);
  const hash = createHash("sha256");
  const inspect = inspectXml ? xmlSafetyGuard() : null;
  const buffer = Buffer.allocUnsafe(CHUNK);
  let bytes = 0;
  try {
    for (;;) {
      signal.throwIfAborted();
      const { bytesRead } = await input.read(buffer, 0, buffer.length, null);
      if (!bytesRead) break;
      bytes += bytesRead;
      if (bytes > artifact.bytes || bytes > MAX_XML) throw integrity();
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk); inspect?.(chunk);
      for (let offset = 0; offset < bytesRead;) offset += (await output.write(chunk, offset, bytesRead - offset)).bytesWritten;
    }
    inspect?.(Buffer.alloc(0), true);
    const after = await input.stat();
    if (bytes !== artifact.bytes || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || hash.digest("hex") !== artifact.sha256) throw integrity();
  } finally { await output.close(); }
}

async function generateHtml(work: string, input: string, output: string, signal: AbortSignal, generator: "oval" | "xccdf") {
  // Fixed controller executable and installed stylesheet; never evaluate on the target.
  // OVAL's installed report stylesheet has no document() or remote imports.
  const file = await open(output, "wx", 0o600);
  // ARF already embeds results; disable automatic companion-file discovery.
  const templates = generator === "xccdf" ? ["--oval-template", "", "--sce-template", ""] : [];
  const child = spawn("/usr/bin/prlimit", ["--as=1610612736", "--cpu=90", `--fsize=${MAX_HTML}`, "--", "/usr/bin/oscap", generator, "generate", "report", ...templates, input], {
    cwd: work, shell: false, stdio: ["ignore", "pipe", "pipe"],
    env: { NODE_ENV: process.env.NODE_ENV ?? "production", PATH: "/usr/bin:/bin", HOME: work, LANG: "C.UTF-8", LC_ALL: "C.UTF-8", XML_CATALOG_FILES: "/dev/null" },
    signal, killSignal: "SIGKILL",
  });
  let stderrBytes = 0;
  child.stderr.on("data", (chunk: Buffer) => { stderrBytes += chunk.length; if (stderrBytes > 1024 * 1024) child.kill("SIGKILL"); });
  const exited = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve() : reject(new Error("OpenSCAP generation failed")));
  });
  let bytes = 0;
  const limit = new Transform({ transform(chunk: Buffer, _encoding, callback) {
    bytes += chunk.length;
    callback(bytes > MAX_HTML ? new Error("HTML exceeds size budget") : null, chunk);
  } });
  const written = pipeline(child.stdout, limit, file.createWriteStream(), { signal });
  try {
    await Promise.all([written, exited]);
    if (!bytes) throw new Error("Empty OpenSCAP report");
  } catch {
    child.kill("SIGKILL");
    await Promise.allSettled([written, exited]);
    signal.throwIfAborted();
    throw new NativeExportError("native_html_unavailable", "OpenSCAP не смог создать HTML на управляющем узле (инструмент недоступен или превышен лимит). Исходный XML доступен отдельно.", 503);
  } finally { await file.close().catch(() => {}); }
}

export const nativeExportSecurityHeaders = {
  "Cache-Control": "private, no-store, max-age=0",
  "Content-Security-Policy": "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
};

/** Snapshot, verify, then stream the private immutable copy. No JSON fallback. */
export async function nativeReportDownload(reports: string, reportId: string, format: NativeExportFormat | null, requestSignal: AbortSignal, view = false): Promise<Response> {
  const id = canonicalId(reportId);
  if (format !== null && !["html", "xml", "source-xml", "json", "dat", "sbom"].includes(format)) throw new NativeExportError("bad_format", "Неизвестный формат экспорта.", 400);
  if (activeExports >= 2) throw new NativeExportError("native_export_busy", "Экспорт занят. Повторите загрузку позже.", 429);
  activeExports++;
  const controller = new AbortController();
  const abort = () => controller.abort(requestSignal.reason);
  requestSignal.addEventListener("abort", abort, { once: true });
  if (requestSignal.aborted) abort();
  const timeout = setTimeout(() => controller.abort(new Error("Native export timeout")), TIMEOUT_MS);
  timeout.unref();
  const signal = controller.signal;
  let work: string | undefined;
  let responseFile: FileHandle | undefined;
  let cleanupPromise: Promise<void> | undefined;
  const cleanup = () => cleanupPromise ??= (async () => {
    clearTimeout(timeout); requestSignal.removeEventListener("abort", abort);
    signal.removeEventListener("abort", onStreamAbort);
    try {
      await responseFile?.close().catch(() => {});
      if (work) await rm(work, { recursive: true, force: true });
    } finally { activeExports--; }
  })();
  let streamController: ReadableStreamDefaultController<Uint8Array> | undefined;
  const onStreamAbort = () => { streamController?.error(new Error("Экспорт прерван.")); void cleanup().catch(() => {}); };
  try {
    signal.throwIfAborted();
    const raw = await boundedManifest(reports, id);
    const formats = formatsFor(raw);
    if (!formats.length) throw unavailable();
    const spec = format === null ? formats[0] : formats.find(item => item.format === format);
    if (!spec) throw new NativeExportError("bad_format", "Этот формат не предоставляется выбранным инструментом.", 400);
    const artifact = artifactFromReport(raw, id, spec);
    const input = await evidenceFile(reports, id, spec);
    try {
      const workspaceRoot = path.join(reports, ".native-exports");
      await mkdir(workspaceRoot, { mode: 0o700, recursive: true });
      const root = await directory(workspaceRoot);
      try {
        const stat = await root.stat();
        if (stat.mode & 0o077) throw integrity();
        // The export workspace is controller-owned, not scanner-controlled.
        work = await mkdtemp(path.join(workspaceRoot, "export-"));
      } finally { await root.close(); }
      const xml = path.join(work, "original.xml");
      await snapshot(input, xml, artifact, signal, Boolean(spec.generator));
      const output = spec.generator ? path.join(work, "report.html") : xml;
      if (spec.generator) await generateHtml(work, xml, output, signal, spec.generator);
      signal.throwIfAborted();
      responseFile = await open(output, constants.O_RDONLY | constants.O_NOFOLLOW);
      const size = (await responseFile.stat()).size;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          streamController = controller;
          signal.addEventListener("abort", onStreamAbort, { once: true });
          if (signal.aborted) onStreamAbort();
        },
        async pull(controller) {
          try {
            signal.throwIfAborted();
            const buffer = Buffer.allocUnsafe(CHUNK);
            const { bytesRead } = await responseFile!.read(buffer, 0, buffer.length, null);
            if (bytesRead) controller.enqueue(buffer.subarray(0, bytesRead));
            else { await cleanup(); controller.close(); }
          } catch (error) { if (!signal.aborted) controller.error(error); await cleanup(); }
        },
        async cancel() { controller.abort(); await cleanup(); },
      });
      return new Response(stream, { headers: {
        ...nativeExportSecurityHeaders,
        "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        "Content-Type": spec.generator ? "text/html; charset=utf-8" : view ? "text/plain; charset=utf-8" : spec.extension === "xml" ? "application/xml" : spec.extension === "json" ? "application/json" : "text/plain; charset=utf-8",
        "Content-Disposition": `${view ? "inline" : "attachment"}; filename="${id}-${spec.kind}.${spec.generator ? "html" : spec.extension}"`,
        "Content-Length": String(size),
        "X-Source-SHA256": artifact.sha256,
      } });
    } finally { await input.close(); }
  } catch (error) {
    await cleanup();
    if (error instanceof NativeExportError) throw error;
    if (signal.aborted) throw new NativeExportError("native_export_aborted", "Экспорт прерван или превышено время ожидания.", 503);
    throw unavailable();
  }
}

export const nativeOvalDownload = nativeReportDownload;
