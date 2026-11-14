import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";
const compiled = compileServerModules(["audit-job-status"]);
const { completedAuditTransitions, auditCompletionMessage, mergeAuditSnapshot, auditJobProgress } = await import(compiled.url("audit-job-status"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));
const running = { id: "job-1", hostAlias: "host-one", action: "lynisTemporaryAudit", status: "running" };
const completed = { ...running, status: "completed", result: { ok: true, message: "Проверка выполнена." } };
test("loading completed history, navigating or polling again never replays completion", () => {
  assert.deepEqual(completedAuditTransitions([], [completed]), []);
  assert.deepEqual(completedAuditTransitions([completed], [completed]), []);
  assert.deepEqual(completedAuditTransitions([running], [completed]), [completed]);
});
test("completion names the actual test and host; detailed limitations remain intact", () => {
  assert.equal(auditCompletionMessage(completed), "Lynis · host-one: завершена.");
  assert.ok(auditCompletionMessage({ ...completed, status: "partial", result: { message: "Недоступен источник OVAL." } }).includes("Недоступен источник OVAL."));
});
test("a delayed older poll cannot erase a newly accepted job; server completion wins", () => {
  assert.deepEqual(mergeAuditSnapshot([], [running]), [running]);
  assert.deepEqual(mergeAuditSnapshot([completed], [running]), [completed]);
});
test("progress counts confirmed stages, never invents scanner percentages or ETA", () => {
  const job = { ...running, createdAt: "2026-11-10T09:00:00Z", updatedAt: "2026-11-10T09:00:00Z" };
  assert.equal(auditJobProgress({ ...job, status: "queued" }).completedStages, 0);
  assert.equal(auditJobProgress({ ...job, phase: "Подготовка проверки" }).stage, 0);
  assert.equal(auditJobProgress({ ...job, phase: "Выполняется проверка хоста" }).completedStages, 1);
  assert.equal(auditJobProgress({ ...job, phase: "Проверяются пакеты и CVE" }).stage, 1);
  assert.equal(auditJobProgress({ ...job, phase: "Передаётся SBOM в Dependency-Track" }).stage, 1);
  assert.equal(auditJobProgress({ ...job, phase: "Сохранение и проверка отчёта" }).completedStages, 2);
  assert.equal(auditJobProgress({ ...completed }).completedStages, 3);
  for (const status of ["failed", "interrupted", "partial"]) assert.notEqual(auditJobProgress({ ...job, status, phase: "Завершено" }).completedStages, 3);
  assert.equal(auditJobProgress({ ...job, phase: "unknown future phase" }).stage, null);
});
