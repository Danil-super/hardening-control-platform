import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["state-store", "astra-oval-config"]);
const state = mkdtempSync(path.join(tmpdir(), "hcp-remediation-plan-"));
process.env.HCP_STATE_DIR = state;
process.env.HCP_AUDIT_HMAC_KEY = "test-plan-hmac-key";
const store = await import(compiled.url("state-store"));
after(() => { delete process.env.HCP_STATE_DIR; delete process.env.HCP_AUDIT_HMAC_KEY; rmSync(compiled.directory, { recursive: true, force: true }); rmSync(state, { recursive: true, force: true }); });

test("plan keeps audit evidence immutable and requires agreement fields before work", () => {
  const item = store.createRemediationPlanItem({ hostAlias: "astra-1", findingKey: "cve:CVE-2026-1000:package:test", title: "CVE-2026-1000 · test", category: "Обнаруженные CVE", risk: "high", description: "Обнаружен признак уязвимости.", recommendation: "Проверьте бюллетень и обновите пакет.", evidence: [{ reportId: "astra-1-oval-run", findingId: "oval:test:1", source: "openscap", mode: "astra-oval", createdAt: new Date().toISOString(), evidence: "package=test; version=1.0", reportSha256: "a".repeat(64) }] });
  assert.equal(item.status, "discovered");
  assert.throws(() => store.transitionRemediationPlanItem(item.id, { status: "agreed", note: "Согласовано с заказчиком" }), /переход/);
  const proposed = store.transitionRemediationPlanItem(item.id, { status: "proposed", note: "Проверить бюллетень и подготовить безопасное обновление." });
  assert.equal(proposed.status, "proposed");
  assert.throws(() => store.transitionRemediationPlanItem(item.id, { status: "agreed", note: "Согласовано заказчиком." }), /ответственного/);
  const agreed = store.transitionRemediationPlanItem(item.id, { status: "agreed", note: "Согласовано заказчиком в тикете.", owner: "Администратор Astra", dueAt: new Date(Date.now() + 86_400_000).toISOString(), approvalReference: "TICKET-100" });
  assert.equal(agreed.status, "agreed");
  const done = store.transitionRemediationPlanItem(item.id, { status: "completed", note: "Исправление выполнено по согласованной процедуре." });
  assert.equal(done.status, "completed");
  assert.equal(store.listRemediationPlanHistory(item.id).length, 4);
  assert.equal(store.getRemediationPlanItem(item.id).evidence[0].reportSha256, "a".repeat(64));
  assert.equal(store.verifyAuditChain().valid, true);
});
