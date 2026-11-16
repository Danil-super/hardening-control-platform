import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { validateAstraOvalConfig, type AstraOvalConfig } from "@/lib/astra-oval-config";
import { currentOperationOwner } from "@/lib/operation-owner";

const MAX_BYTES = 192 * 1024 * 1024;
const DEADLINE = 1_500_000;
const active = new Set<string>();
type PreparedResult = { ok: boolean; database: { sha256: string; bytes: number; generatedAt: string; freshness: string }; sourceValidation: { sha256: string; schemaExitCode: number; schematronExitCode: number | null; location: string }; warnings: string[] };
type State = { state: "preparing" | "ready" | "failed"; owner: string; startedAt: string; finishedAt?: string; message: string; result?: PreparedResult };
export type OvalPreparationStatus = { state: "missing" | "preparing" | "ready" | "failed" | "local"; message: string; startedAt?: string; finishedAt?: string; bytes?: number; sha256?: string; generatedAt?: string };

function paths(config: AstraOvalConfig) {
  const key = createHash("sha256").update(JSON.stringify(validateAstraOvalConfig(config))).digest("hex");
  const repo = path.resolve(process.cwd(), "..");
  const root = path.join(process.env.HCP_STATE_DIR ? path.resolve(process.env.HCP_STATE_DIR) : path.join(repo, "ansible"), "oval-prepared");
  return { root, directory: path.join(root, key), key, repo };
}
function ensureDirectory(directory: string) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077) throw new Error("Небезопасный каталог подготовленных баз OVAL.");
}
function readState(directory: string): State | null {
  try {
    const fd = openSync(path.join(directory, "status.json"), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const info = fstatSync(fd);
      if (!info.isFile() || info.size > 65536) return null;
      return JSON.parse(readFileSync(fd, "utf8")) as State;
    } finally { closeSync(fd); }
  } catch { return null; }
}
function saveState(directory: string, value: State) {
  const temporary = path.join(directory, randomUUID() + ".json");
  writeFileSync(temporary, JSON.stringify(value), { mode: 0o600, flag: "wx" });
  renameSync(temporary, path.join(directory, "status.json"));
}
function assertPreparedResult(result: PreparedResult | undefined, config: AstraOvalConfig) {
  if (!result?.ok || result.database?.sha256 !== config.sha256 || !Number.isSafeInteger(result.database.bytes)
      || result.database.bytes <= 0 || result.database.bytes > MAX_BYTES
      || result.sourceValidation?.sha256 !== config.sha256 || result.sourceValidation.schemaExitCode !== 0
      || result.sourceValidation.schematronExitCode !== 0 || result.sourceValidation.location !== "control_node"
      || !Array.isArray(result.warnings) || result.warnings.length) throw new Error("Проверки SHA-256, XML или метаданных базы не завершены без ограничений. Проверьте источник.");
  const generated = Date.parse(result.database.generatedAt);
  const age = Date.now() - generated;
  if (!Number.isFinite(generated) || age < -300_000 || age > config.maxAgeDays * 86400_000) throw new Error("Подготовленная база устарела или имеет некорректную дату. Проверьте источник и подготовьте актуальную базу.");
}
function assertSourceFile(directory: string, config: AstraOvalConfig, expectedBytes: number) {
  const fd = openSync(path.join(directory, "database.xml"), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size !== expectedBytes || before.size <= 0 || before.size > MAX_BYTES) throw new Error("Подготовленная копия базы недоступна или повреждена.");
    const hash = createHash("sha256"), buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) { const count = readSync(fd, buffer, 0, buffer.length, null); if (!count) break; hash.update(buffer.subarray(0, count)); }
    const after = fstatSync(fd);
    if (hash.digest("hex") !== config.sha256 || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error("SHA-256 подготовленной базы не совпадает. Подготовьте базу повторно.");
  } finally { closeSync(fd); }
}
export function ovalPreparationStatus(config: AstraOvalConfig): OvalPreparationStatus {
  if (config.mode === "local") return { state: "local", message: "Локальный XML читается на целевом хосте: SHA-256, выпуск, возраст и XML проверяются перед вычислением результатов. Сетевая подготовка не требуется." };
  const { root, directory } = paths(config);
  for (const p of [root, directory]) {
    const info = lstatSync(p, { throwIfNoEntry: false });
    if (info && (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077)) return { state: "failed", message: "Небезопасный каталог подготовленных баз OVAL." };
  }
  const state = readState(directory);
  if (!state) return { state: "missing", message: "Сначала подготовьте базу: контроллер проверит HTTPS-доступ, скачает XML и проверит SHA-256, дату и схему OpenSCAP." };
  if (state.state === "preparing") {
    if (state.owner !== currentOperationOwner || Date.now() - Date.parse(state.startedAt) > DEADLINE + 60_000) return { state: "failed", message: "Подготовка прервана перезапуском или превысила время. Повторите подготовку базы." };
    return { state: "preparing", message: state.message, startedAt: state.startedAt };
  }
  if (state.state === "failed") return { state: "failed", message: state.message, finishedAt: state.finishedAt };
  try {
    assertPreparedResult(state.result, config);
    const info = lstatSync(path.join(directory, "database.xml"));
    if (!info.isFile() || info.isSymbolicLink() || info.size !== state.result!.database.bytes) throw new Error("Подготовленная копия базы отсутствует или повреждена.");
    return { state: "ready", message: "Копия подготовлена: SHA-256, дата, XSD и Schematron проверены. При запуске повторная загрузка не требуется; применимость проверяется на хосте.", finishedAt: state.finishedAt, sha256: state.result!.database.sha256, bytes: state.result!.database.bytes, generatedAt: state.result!.database.generatedAt };
  } catch (error) { return { state: "failed", message: error instanceof Error ? error.message : "База не готова." }; }
}
export function preparedOvalExtraVars(config: AstraOvalConfig): Record<string, string> {
  if (config.mode === "local") return {};
  const { root, directory } = paths(config);
  for (const p of [root, directory]) { const info = lstatSync(p, { throwIfNoEntry: false }); if (!info?.isDirectory() || info.isSymbolicLink() || info.mode & 0o077) throw new Error("Сначала подготовьте OVAL-базу для текущего источника в разделе «Хосты»."); }
  const state = readState(directory);
  if (state?.state !== "ready") throw new Error("Сначала подготовьте OVAL-базу для текущего источника в разделе «Хосты».");
  assertPreparedResult(state.result, config);
  assertSourceFile(directory, config, state.result!.database.bytes);
  return { hcp_oval_prepared_input: path.join(directory, "database.xml"), hcp_oval_source_validation: JSON.stringify(state.result!.sourceValidation) };
}

function executePreparation(config: AstraOvalConfig, output: string, repo: string) {
  return new Promise<PreparedResult>((resolve, reject) => {
    execFile("/usr/bin/python3", [path.join(repo, "ansible/scripts/hcp-oval-audit.py"), "prepare", "--validate", "--config", JSON.stringify(config), "--output", output], { timeout: DEADLINE, maxBuffer: 128 * 1024, cwd: repo }, (error, stdout) => {
      if (error) { reject(new Error("Загрузка или проверка OVAL не завершилась за отведённое время. Проверьте доступ к источнику, прокси и OpenSCAP.")); return; }
      try { const value = JSON.parse(stdout); if (!value.ok) throw new Error(typeof value.error === "string" ? value.error : "Не удалось подготовить OVAL."); resolve(value); } catch (cause) { reject(cause); }
    });
  });
}

/** Persisted state survives navigation. A process restart never promotes unfinished preparation. */
export function startOvalPreparation(config: AstraOvalConfig, execute = executePreparation): { status: OvalPreparationStatus; run: (() => Promise<void>) | null } {
  if (config.mode !== "online") return { status: ovalPreparationStatus(config), run: null };
  const { root, directory, key, repo } = paths(config);
  const status = ovalPreparationStatus(config);
  if (status.state === "preparing") return { status, run: null };
  if (status.state === "ready") {
    try { preparedOvalExtraVars(config); return { status, run: null }; }
    catch { /* Replace a damaged copy only after a new verified preparation. */ }
  }
  if (active.size) throw new Error("Уже подготавливается другая OVAL-база. Дождитесь завершения.");
  ensureDirectory(root); ensureDirectory(directory);
  const state: State = { state: "preparing", owner: currentOperationOwner, startedAt: new Date().toISOString(), message: "1. Проверка HTTPS-доступа → 2. Загрузка XML → 3. SHA-256 и дата → 4. XSD и Schematron. Подготовка может занять до 25 минут." };
  saveState(directory, state); active.add(key);
  return { status: ovalPreparationStatus(config), run: async () => {
    const temporary = path.join(directory, randomUUID() + ".xml");
    try {
      const result = await execute(config, temporary, repo);
      assertPreparedResult(result, config);
      renameSync(temporary, path.join(directory, "database.xml"));
      assertSourceFile(directory, config, result.database.bytes);
      saveState(directory, { ...state, state: "ready", finishedAt: new Date().toISOString(), message: "База подготовлена.", result });
    } catch (error) {
      // urllib exceptions may contain proxy credentials; never persist raw URLs with userinfo.
      const message = (error instanceof Error ? error.message : "Подготовка не завершена.").replace(/https?:\/\/[^\s/@]+@/g, "https://[скрыто]@").slice(0, 1500);
      saveState(directory, { ...state, state: "failed", finishedAt: new Date().toISOString(), message });
    } finally { rmSync(temporary, { force: true }); active.delete(key); }
  } };
}
