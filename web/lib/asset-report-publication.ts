import { closeSync, constants, existsSync, fstatSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { getReportsDir } from "@/lib/ansible-reports";
import type { AssetBinding } from "@/lib/asset-binding";
import { withReportEvidenceLock } from "@/lib/state-store";
const MAX_REPORT_BYTES = 384 * 1024 * 1024;

/** Reports stay private until their launch identity is part of the bytes. */
export function publishCapturedAssetReports(stage: string, expected: Map<string, AssetBinding>) {
  const files = readdirSync(stage).filter((file) => file.endsWith(".json"));
  if (files.length > expected.size) throw new Error("Запуск создал неожиданные отчёты; публикация остановлена.");
  let totalBytes = 0;
  const outputs = files.map((file) => {
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
    const serialized = JSON.stringify({ ...report, assetBinding: binding }, null, 2);
    totalBytes += Buffer.byteLength(serialized);
    if (totalBytes > MAX_REPORT_BYTES) throw new Error("Отчёты запуска с привязкой превышают 384 МиБ. Выполните большой OVAL-аудит отдельным запуском для одного хоста.");
    return { file, serialized };
  });
  withReportEvidenceLock(() => {
    mkdirSync(getReportsDir(), { recursive: true });
    for (const { file } of outputs) if (existsSync(path.join(getReportsDir(), file))) throw new Error("Отчёт этого запуска уже существует; исторические данные не переписываются.");
    for (const { file, serialized } of outputs) {
      const temporary = path.join(getReportsDir(), `.asset-report-${randomUUID()}.tmp`);
      try {
        const fd = openSync(temporary, "wx", 0o600);
        try { writeFileSync(fd, serialized); fsyncSync(fd); } finally { closeSync(fd); }
        linkSync(temporary, path.join(getReportsDir(), file));
      } finally { rmSync(temporary, { force: true }); }
    }
  });
}
