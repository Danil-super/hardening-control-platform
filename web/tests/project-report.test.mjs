import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["project-report", "state-store", "astra-oval-config", "ansible-reports", "audit-correlation", "host-credentials", "ssh-access"]);
const state = mkdtempSync(path.join(tmpdir(), "hcp-project-report-state-"));
const reports = mkdtempSync(path.join(tmpdir(), "hcp-project-report-reports-"));
process.env.HCP_STATE_DIR = state;
process.env.HCP_REPORTS_DIR = reports;
const projectReports = await import(compiled.url("project-report"));
const store = await import(compiled.url("state-store"));
after(() => { delete process.env.HCP_STATE_DIR; delete process.env.HCP_REPORTS_DIR; rmSync(compiled.directory, { recursive: true, force: true }); rmSync(state, { recursive: true, force: true }); rmSync(reports, { recursive: true, force: true }); });

test("final PDF stores a bounded snapshot and an HMAC-audited manifest", async () => {
  const createdAt = new Date().toISOString();
  writeFileSync(path.join(reports, "astra-1-basic_linux-run.json"), JSON.stringify({ inventoryHost: "astra-1", createdAt, mode: "agentless", profileId: "basic_linux", summary: { score: 72, high: 0, medium: 0, low: 0, info: 0 }, findings: [], events: [] }));
  const record = await projectReports.createProjectReport({ hostAlias: "astra-1", subject: { clientName: "ООО Тест", projectName: "Харденинг", period: "01.10.2026", specialist: "Специалист HCP" } });
  assert.match(record.id, /^project_report_/);
  assert.match(record.pdfSha256, /^[a-f0-9]{64}$/);
  assert.equal(projectReports.listProjectReports("astra-1").length, 1);
  assert.deepEqual(projectReports.listProjectReportSourceReferences("astra-1-basic_linux-run", "astra-1"), [{
    id: record.id, hostAlias: "astra-1", snapshotReadable: true,
  }]);
  const result = projectReports.readProjectReportPdf(record.id);
  assert.ok(result);
  assert.equal(result.pdf.subarray(0, 5).toString("ascii"), "%PDF-");
  assert.equal(store.verifyAuditChain().valid, true);
});
