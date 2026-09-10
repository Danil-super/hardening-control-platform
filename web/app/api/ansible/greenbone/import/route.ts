import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import path from "node:path";
import { promisify } from "node:util";
import { NextResponse } from "next/server";
import { appendIncident, getRepoRoot, getStateDir, inventoryHostAddress, inventoryHostExists, isSafeLimit } from "@/lib/ansible-control";
import { getReportsDir } from "@/lib/ansible-reports";

const execFileAsync = promisify(execFile);
const maxXmlBytes = 20 * 1024 * 1024;

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  const form = await request.formData().catch(() => null);
  const hostAlias = typeof form?.get("hostAlias") === "string" ? String(form.get("hostAlias")).trim() : "";
  const reportFile = form?.get("report");
  if (!isSafeLimit(hostAlias) || hostAlias.includes(",") || !inventoryHostExists(hostAlias)) {
    return NextResponse.json({ ok: false, message: "Выберите существующий одиночный хост из inventory." }, { status: 400 });
  }
  if (!(reportFile instanceof File) || reportFile.size === 0 || reportFile.size > maxXmlBytes) {
    return NextResponse.json({ ok: false, message: "Загрузите XML-отчёт Greenbone размером до 20 МБ." }, { status: 400 });
  }

  const runId = `run-${new Date().toISOString().replace(/[-:.]/g, "")}-${randomUUID().slice(0, 8)}`;
  const stateDir = getStateDir();
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const temporaryDir = mkdtempSync(path.join(stateDir, "greenbone-import-"));
  const inputPath = path.join(temporaryDir, "report.xml");
  const reportId = `${hostAlias}-greenbone-${runId}`;
  const outputPath = path.join(getReportsDir(), `${reportId}.json`);
  try {
    const hostAddress = inventoryHostAddress(hostAlias);
    if (!hostAddress) throw new Error("Адрес выбранного хоста отсутствует в inventory.");
    const expectedAddresses = isIP(hostAddress) ? [] : await lookup(hostAddress, { all: true });
    writeFileSync(inputPath, Buffer.from(await reportFile.arrayBuffer()), { mode: 0o600 });
    await execFileAsync("/usr/bin/python3", [
      path.join(getRepoRoot(), "ansible", "scripts", "hcp-controller-scan.py"),
      "greenbone-report",
      "--input", inputPath,
      "--host", hostAddress,
      ...expectedAddresses.flatMap(({ address }) => ["--expected-host", address]),
      "--inventory-host", hostAlias,
      "--run-id", runId,
      "--output", outputPath,
    ], { timeout: 60_000, maxBuffer: 1024 * 1024 * 2 });
    const report = JSON.parse(readFileSync(outputPath, "utf8")) as { scanner?: { imported?: boolean; partial?: boolean; excludedOtherHostResults?: number } };
    if (report.scanner?.imported !== true) throw new Error("Парсер не подтвердил корректность импорта Greenbone.");
    const partial = report.scanner.partial === true;
    const excluded = report.scanner.excludedOtherHostResults ?? 0;
    const message = `Импортированы результаты Greenbone для ${hostAlias}.${partial ? " Отчёт частичный: ограничения указаны в результатах." : ""}${excluded ? ` Результаты других хостов исключены: ${excluded}.` : ""}`;
    appendIncident({
      action: "greenboneImport",
      kind: "audit",
      status: "success",
      profileId: "greenbone",
      limit: hostAlias,
      message,
    });
    return NextResponse.json({ ok: true, reportId, partial, message });
  } catch (error) {
    rmSync(outputPath, { force: true });
    const stderr = error && typeof error === "object" && "stderr" in error && typeof error.stderr === "string" ? error.stderr.trim() : "";
    const message = (stderr || (error instanceof Error ? error.message : "Не удалось импортировать XML-отчёт Greenbone.")).slice(0, 600);
    appendIncident({ action: "greenboneImport", kind: "audit", status: "failed", profileId: "greenbone", limit: hostAlias, message });
    return NextResponse.json({ ok: false, message }, { status: 400 });
  } finally {
    rmSync(temporaryDir, { recursive: true, force: true, maxRetries: 2 });
  }
}
