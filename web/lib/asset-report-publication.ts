import { closeSync, constants, existsSync, fstatSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { getReportsDir } from "@/lib/ansible-reports";
import type { AssetBinding } from "@/lib/asset-binding";
import { withReportEvidenceLock } from "@/lib/state-store";
import { prepareRawScanEvidence, type PreparedRawEvidence } from "@/lib/raw-scan-evidence";
const MAX_REPORT_BYTES = 384 * 1024 * 1024;

/** Reports stay private until their launch identity is part of the bytes. */
export async function publishCapturedAssetReports(stage: string, expected: Map<string, AssetBinding>, options: { preserveRaw?: boolean } = {}) {
  const originals: PreparedRawEvidence[] = [];
  const outputs: Array<{ file: string; temporary: string; raw: PreparedRawEvidence | null }> = [];
  try {
    const files = readdirSync(stage).filter((file) => !file.startsWith(".") && file.endsWith(".json"));
    if (files.length > expected.size) throw new Error("Запуск создал неожиданные отчёты; публикация остановлена.");
    let totalBytes = 0;
    mkdirSync(getReportsDir(), { recursive: true });
    for (const file of files) {
      const binding = expected.get(file);
      if (!binding) throw new Error("Имя отчёта не относится к запущенной проверке.");
      const fd = openSync(path.join(stage, file), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      let bytes: Buffer;
      try {
        const stat = fstatSync(fd);
        if (!stat.isFile() || stat.size > MAX_REPORT_BYTES) throw new Error("Отчёт имеет неподдерживаемый тип или превышает 384 МиБ.");
        bytes = readFileSync(fd);
        if (bytes.length > MAX_REPORT_BYTES) throw new Error("Отчёт превысил допустимый размер 384 МиБ.");
      } finally { closeSync(fd); }
      const report = JSON.parse(bytes.toString("utf8"));
      if (!report || Array.isArray(report) || report.inventoryHost !== binding.alias) throw new Error("Отчёт не принадлежит проверенному хосту.");
      const raw = options.preserveRaw ? await prepareRawScanEvidence(stage, file, report, getReportsDir()) : null;
      if (raw) originals.push(raw);
      if (raw && !raw.evidence.complete) {
        report.partial = true;
        report.scanner = { ...report.scanner, partial: true, partialReasons: [
          ...(Array.isArray(report.scanner?.partialReasons) ? report.scanner.partialReasons : []),
          "Не сохранены исходные доказательства: " + raw.evidence.missing.join(", ") + ".",
        ] };
      }
      const serialized = JSON.stringify({ ...report, assetBinding: binding,
        ...(raw ? { rawEvidence: raw.evidence } : {}) }, null, 2);
      totalBytes += Buffer.byteLength(serialized);
      if (totalBytes > MAX_REPORT_BYTES) throw new Error("Отчёты запуска с привязкой превышают 384 МиБ. Выполните большой OVAL-аудит отдельным запуском для одного хоста.");
      const temporary = path.join(getReportsDir(), `.asset-report-${randomUUID()}.tmp`);
      outputs.push({ file, temporary, raw });
      const output = await open(temporary, "wx", 0o600);
      try { await output.writeFile(serialized); await output.sync(); } finally { await output.close(); }
    }
    withReportEvidenceLock(() => {
      for (const { file } of outputs) if (existsSync(path.join(getReportsDir(), file))) throw new Error("Отчёт этого запуска уже существует; исторические данные не переписываются.");
      for (const { file, temporary, raw } of outputs) {
        let originalsCommitted = false;
        let reportCommitted = false;
        try {
          if (raw) {
            if (existsSync(raw.finalDirectory)) throw new Error("Исходные доказательства отчёта уже существуют.");
            renameSync(raw.temporaryDirectory, raw.finalDirectory);
            originalsCommitted = true;
          }
          linkSync(temporary, path.join(getReportsDir(), file));
          reportCommitted = true;
        } finally {
          rmSync(temporary, { force: true });
          if (raw && originalsCommitted && !reportCommitted) rmSync(raw.finalDirectory, { recursive: true, force: true });
        }
      }
    });
  } finally {
    for (const { temporary } of outputs) rmSync(temporary, { force: true });
    for (const raw of originals) rmSync(raw.temporaryDirectory, { recursive: true, force: true });
  }
}
