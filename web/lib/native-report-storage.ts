import { createHash, randomUUID } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { getReportsDir } from "@/lib/ansible-reports";

const formats = {
  trivy: { extension: "json", maximum: 128 * 1024 * 1024 },
  greenbone: { extension: "xml", maximum: 20 * 1024 * 1024 },
  "dependency-track": { extension: "json", maximum: 32 * 1024 * 1024 },
  sbom: { extension: "json", maximum: 32 * 1024 * 1024 },
} as const;
export type NativeReportKind = keyof typeof formats;
export type NativeReportArtifact = { kind: NativeReportKind; bytes: Buffer };
export type NativeReportManifest = { version: 1; complete: boolean; missing: string[]; artifacts: Array<{ kind: string; path: string; bytes: number; sha256: string }> };
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

/** Read an already selected source without following links or accepting a changing file. */
export function readNativeReportFile(file: string, maximum: number, expected?: { bytes: number; sha256: string }): Buffer {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 384 * 1024 * 1024) throw new Error("Некорректный предел оригинала отчёта.");
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== BigInt(1) || before.size <= BigInt(0) || before.size > BigInt(maximum)) throw new Error("Недопустимый тип или размер оригинала отчёта.");
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const count = readSync(fd, buffer, bytes, Math.min(buffer.length - bytes, 64 * 1024), null);
      if (!count) break;
      bytes += count;
    }
    const after = fstatSync(fd, { bigint: true });
    const current = lstatSync(file, { bigint: true });
    const same = (other: typeof before) => other.isFile() && ["dev", "ino", "size", "mtimeNs", "ctimeNs", "nlink"].every((key) => before[key as keyof typeof before] === other[key as keyof typeof before]);
    const result = buffer.subarray(0, bytes);
    if (bytes !== Number(before.size) || !same(after) || !same(current)
        || expected && (expected.bytes !== bytes || expected.sha256 !== digest(result))) throw new Error("Оригинал отчёта изменён или не совпадает с SHA-256.");
    return result;
  } finally { closeSync(fd); }
}

function directory(file: string, privateDirectory: boolean) {
  try { mkdirSync(file, { mode: 0o700, recursive: !privateDirectory }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
  const info = lstatSync(file);
  if (!info.isDirectory() || info.isSymbolicLink() || privateDirectory && (info.mode & 0o077) !== 0) throw new Error("Небезопасный каталог оригиналов отчётов.");
}

function syncDirectory(file: string) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

/** Artifacts become reachable only when the complete immutable report is linked into place. */
export function publishNativeReport<T extends Record<string, unknown>>(
  reportId: string, report: T, inputs: NativeReportArtifact[], missing: string[] = [], reportsDir = getReportsDir(),
): T & { rawEvidence: NativeReportManifest } {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,219}$/.test(reportId) || reportId.includes("..")) throw new Error("Некорректный идентификатор оригинала отчёта.");
  const allowed: Record<string, NativeReportKind[]> = { vulnerabilities: ["trivy", "sbom"], greenbone: ["greenbone"],
    "dependency-track-analysis": ["dependency-track", "sbom"], "dependency-track": ["sbom"], packages: ["sbom"] };
  const kinds = allowed[String(report.mode)];
  if (!kinds || inputs.some((item) => !kinds.includes(item.kind) || !Buffer.isBuffer(item.bytes) || item.bytes.length === 0 || item.bytes.length > formats[item.kind].maximum)
      || new Set(inputs.map((item) => item.kind)).size !== inputs.length
      || missing.some((kind) => !kinds.includes(kind as NativeReportKind) || inputs.some((item) => item.kind === kind))) throw new Error("Недопустимый формат, тип или размер оригинала отчёта.");
  const required: Record<string, NativeReportKind> = { vulnerabilities: "trivy", greenbone: "greenbone", "dependency-track-analysis": "dependency-track", "dependency-track": "sbom", packages: "sbom" };
  missing = [...missing, ...(!inputs.some((item) => item.kind === required[String(report.mode)]) ? [required[String(report.mode)]] : [])];
  const artifacts = inputs.map((item) => ({ kind: item.kind, path: `.raw-evidence/${reportId}/${item.kind}.${formats[item.kind].extension}`,
    bytes: item.bytes.length, sha256: digest(item.bytes) }));
  const output = { ...report, rawEvidence: { version: 1 as const, complete: missing.length === 0, missing: [...new Set(missing)], artifacts } };
  const serialized = Buffer.from(JSON.stringify(output, null, 2));
  if (serialized.length > 384 * 1024 * 1024) throw new Error("Отчёт превышает допустимый размер.");
  directory(reportsDir, false);
  const root = path.join(reportsDir, ".raw-evidence");
  directory(root, true);
  const artifactDir = path.join(root, reportId);
  const temporary = path.join(reportsDir, `.native-report-${randomUUID()}.pending`);
  let created = false;
  let published = false;
  try {
    mkdirSync(artifactDir, { mode: 0o700 }); created = true;
    for (let index = 0; index < inputs.length; index++) {
      const fd = openSync(path.join(reportsDir, artifacts[index].path), "wx", 0o600);
      try { writeFileSync(fd, inputs[index].bytes); fsyncSync(fd); } finally { closeSync(fd); }
    }
    syncDirectory(artifactDir);
    syncDirectory(root);
    const fd = openSync(temporary, "wx", 0o600);
    try { writeFileSync(fd, serialized); fsyncSync(fd); } finally { closeSync(fd); }
    linkSync(temporary, path.join(reportsDir, `${reportId}.json`));
    published = true;
    try { syncDirectory(reportsDir); } catch (error) {
      rmSync(path.join(reportsDir, `${reportId}.json`)); published = false; throw error;
    }
    return output;
  } finally {
    rmSync(temporary, { force: true });
    if (created && !published) rmSync(artifactDir, { recursive: true, force: true });
  }
}
