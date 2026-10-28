import { readFileSync } from "node:fs";
import { hostname } from "node:os";

type Owner = { version: 1; host: string; pid: number; token: string; boot: string | null; start: string | null };
function read(path: string) { try { return readFileSync(path, "utf8").trim(); } catch { return null; } }
function startTime(pid: number) {
  const stat = read(`/proc/${pid}/stat`);
  // comm can contain spaces and parentheses; fields after the final ') ' start
  // at field 3. Linux process start ticks (field 22) distinguish PID reuse.
  return stat?.slice(stat.lastIndexOf(") ") + 2).split(/\s+/)[19] ?? null;
}
const current: Owner = { version: 1, host: hostname(), pid: process.pid,
  token: `${process.pid}:${performance.timeOrigin}`, boot: read("/proc/sys/kernel/random/boot_id"), start: startTime(process.pid) };
export const currentOperationOwner = JSON.stringify(current);

/** A different container/host or a legacy record is unknown, never assumed dead. */
export function operationOwnerState(serialized: unknown): "live" | "dead" | "unknown" {
  if (serialized === currentOperationOwner) return "live";
  let owner: Owner;
  try { owner = JSON.parse(String(serialized)); } catch { return "unknown"; }
  if (!owner || owner.version !== 1 || owner.host !== current.host || !Number.isSafeInteger(owner.pid) || owner.pid < 1) return "unknown";
  if (owner.boot && current.boot && owner.boot !== current.boot) return "unknown";
  const observed = startTime(owner.pid);
  if (owner.boot === current.boot && owner.start && observed) return observed === owner.start ? "live" : "dead";
  try { process.kill(owner.pid, 0); return "live"; }
  catch (error) { return (error as NodeJS.ErrnoException).code === "ESRCH" ? "dead" : "unknown"; }
}

export type RecoveryAttestation = {
  confirmedHost?: unknown; confirmedOperation?: unknown; processesStopped?: unknown;
  outcomeVerified?: unknown; inspectionNote?: unknown; evidenceReference?: unknown; expectedRecoveryVersion?: unknown;
};
export function validateRecoveryAttestation(input: RecoveryAttestation, host: string, operation: string, recoveryVersion: string) {
  if (input.confirmedHost !== host || input.confirmedOperation !== operation) {
    throw Object.assign(new Error("Введите точные имя хоста и ID прерванной операции."), { code: "recovery_confirmation_required" });
  }
  if (input.expectedRecoveryVersion !== recoveryVersion) {
    throw Object.assign(new Error("Состояние операции изменилось после открытия формы. Обновите его и заново проверьте цель перед подтверждением."), { code: "recovery_version_stale" });
  }
  if (input.processesStopped !== true || input.outcomeVerified !== true) {
    throw Object.assign(new Error("Сначала остановите прежние процессы HCP/Ansible и проверьте фактическое состояние на цели через независимый доступ."), { code: "recovery_inspection_required" });
  }
  const inspectionNote = typeof input.inspectionNote === "string" ? input.inspectionNote.trim() : "";
  const evidenceReference = typeof input.evidenceReference === "string" ? input.evidenceReference.trim() : "";
  if (inspectionNote.length < 20 || inspectionNote.length > 2000 || evidenceReference.length < 5 || evidenceReference.length > 500
      || /[\0]/.test(inspectionNote + evidenceReference)) {
    throw Object.assign(new Error("Опишите проверенное состояние (20–2000 символов) и укажите ссылку на протокол, файл или тикет (5–500 символов). Не вставляйте секреты."), { code: "recovery_evidence_required" });
  }
  return { inspectionNote, evidenceReference, processesStopped: true, outcomeVerified: true, expectedRecoveryVersion: recoveryVersion };
}
