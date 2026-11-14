import { constants, existsSync, lstatSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";

const MAX_FILE_BYTES = 384 * 1024 * 1024;
const MAX_TOTAL_BYTES = 768 * 1024 * 1024;
type Artifact = { kind: string; path: string; sha256: string; bytes: number };
export type RawScanEvidence = {
  version: 1; complete: boolean; missing: string[]; artifacts: Artifact[];
};
export type PreparedRawEvidence = {
  evidence: RawScanEvidence; temporaryDirectory: string; finalDirectory: string;
};
const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
function checksum(value: unknown) {
  if (typeof value !== "string") return null;
  const hash = value.replace(/^sha256:/, "").toLowerCase();
  return /^[a-f0-9]{64}$/.test(hash) ? hash : null;
}

/** Copy from one opened regular file; never follow a scanner-controlled link.
 * Originals are copied in chunks, independently of the JSON memory budget. */
async function copyOriginal(source: string, destination: string, expectedHash: string | null) {
  const input = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let output: FileHandle | undefined;
  try {
    const before = await input.stat();
    if (!before.isFile() || before.size <= 0 || before.size > MAX_FILE_BYTES) throw new Error("Недопустимый тип или размер исходного доказательства сканера.");
    output = await open(destination, "wx", 0o600);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    for (;;) {
      const { bytesRead: size } = await input.read(buffer, 0, buffer.length, null);
      if (!size) break;
      bytes += size;
      if (bytes > MAX_FILE_BYTES) throw new Error("Исходное доказательство превысило допустимый размер.");
      hash.update(buffer.subarray(0, size));
      for (let offset = 0; offset < size;) {
        const { bytesWritten } = await output.write(buffer, offset, size - offset, null);
        if (!bytesWritten) throw new Error("Не удалось полностью записать исходное доказательство.");
        offset += bytesWritten;
      }
    }
    const after = await input.stat();
    const sha256 = hash.digest("hex");
    if (bytes !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs
      || expectedHash && sha256 !== expectedHash) throw new Error("Исходное доказательство изменилось или его контрольная сумма не совпадает с отчётом.");
    await output.sync();
    return { bytes, sha256 };
  } finally { try { await output?.close(); } finally { await input.close(); } }
}

/** Prepare native originals privately. The report publisher commits them before
 * publishing the JSON that names their hashes. This is not publisher trust. */
export async function prepareRawScanEvidence(stage: string, file: string, report: Record<string, unknown>, reportsDirectory: string): Promise<PreparedRawEvidence | null> {
  if (!["openscap", "astra-oval", "nmap", "ssh-audit", "lynis"].includes(String(report.mode))) return null;
  if (!/^[A-Za-z0-9_.-]{1,220}\.json$/.test(file)) throw new Error("Недопустимое имя отчёта для исходных доказательств.");
  const id = file.slice(0, -5);
  const scanner = record(report.scanner);
  const native = report.mode === "nmap" ? { kind: "nmap", filename: "nmap.xml", sidecar: "nmap.xml" }
    : report.mode === "ssh-audit" ? { kind: "ssh-audit", filename: "ssh-audit.json", sidecar: "ssh-audit.json" }
    : report.mode === "lynis" ? { kind: "lynis-report", filename: "lynis-report.dat", sidecar: "report.dat" } : null;
  const specs = native ? [
    { kind: native.kind, filename: native.filename, names: [`.${id}.${native.sidecar}`], expected: null },
  ] : report.mode === "astra-oval" ? [
    { kind: "oval-results", filename: "oval-results.xml", names: [`.${id}.oval-results.xml`], expected: checksum(scanner.resultSha256) },
    { kind: "source", filename: "source.xml", names: [`.${id}.source.xml`], expected: checksum(record(scanner.database).sha256) },
  ] : [
    { kind: "arf", filename: "arf.xml", names: [`.${id}.xml`], expected: checksum(scanner.rawResultSha256) },
    { kind: "source", filename: "source.xml", names: [`.${id}.xml.datastream.xml`, `.${id}.xml.evaluated-xccdf.xml`], expected: checksum(scanner.datastreamChecksum) },
  ];
  mkdirSync(reportsDirectory, { recursive: true });
  const root = path.join(reportsDirectory, ".raw-evidence");
  mkdirSync(root, { mode: 0o700, recursive: true });
  const info = lstatSync(root);
  if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077) throw new Error("Каталог исходных доказательств имеет небезопасный тип или права.");
  const temporaryDirectory = mkdtempSync(path.join(root, ".staging-"));
  const evidence: RawScanEvidence = { version: 1, complete: false, missing: [], artifacts: [] };
  try {
    let total = 0;
    for (const spec of specs) {
      const matches = spec.names.filter((name) => lstatSync(path.join(stage, name), { throwIfNoEntry: false }));
      if (!matches.length) { evidence.missing.push(spec.kind); continue; }
      if (matches.length !== 1) throw new Error("Неоднозначный набор исходных доказательств сканера.");
      const source = path.join(stage, matches[0]);
      if (lstatSync(source).isSymbolicLink()) throw new Error("Ссылка вместо исходного доказательства сканера недопустима.");
      const copied = await copyOriginal(source, path.join(temporaryDirectory, spec.filename), spec.expected);
      total += copied.bytes;
      if (total > MAX_TOTAL_BYTES) throw new Error("Суммарный размер исходных доказательств превышает допустимый бюджет.");
      evidence.artifacts.push({ kind: spec.kind, path: path.posix.join(".raw-evidence", id, spec.filename), ...copied });
    }
    evidence.complete = evidence.missing.length === 0;
    const finalDirectory = path.join(root, id);
    if (existsSync(finalDirectory)) throw new Error("Исходные доказательства этого отчёта уже сохранены.");
    return { evidence, temporaryDirectory, finalDirectory };
  } catch (error) { rmSync(temporaryDirectory, { recursive: true, force: true }); throw error; }
}
