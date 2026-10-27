import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
  store.setRecordArchive([{kind:"pdf",id:record.id},{kind:"report",id:"astra-1-basic_linux-run"}],"archive");
  assert.equal(projectReports.listProjectReports("astra-1").length,0);
  assert.equal(projectReports.listProjectReportSourceReferences("astra-1-basic_linux-run","astra-1")[0].id,record.id);
  assert.equal(projectReports.readProjectReportPdf(record.id).record.pdfSha256,record.pdfSha256);
});

test("a 4,000-observation audit exports beyond 1 MB and retains unknown severity and final row", async () => {
  const findings = Array.from({ length: 4000 }, (_, index) => ({
    id: `oval:fixture:def:${index}`, profileId: "astra-oval", title: `CVE-2026-${String(10000 + index)}: package-${index}`,
    category: "CVE", risk: "info", severityUnknown: true, status: "failed", source: "openscap",
    description: "An observation without vendor severity", recommendation: "Проверьте бюллетень производителя. После обновления повторите аудит.",
    evidence: JSON.stringify({ vendorSeverity: null }), remediationAvailable: false,
  }));
  writeFileSync(path.join(reports, "large-astra-oval-run.json"), JSON.stringify({ inventoryHost: "large", createdAt: new Date().toISOString(), mode: "astra-oval", profileId: "astra-oval", findings, events: [] }));
  const record = await projectReports.createProjectReport({ hostAlias: "large", subject: { clientName: "ООО Тест", projectName: "Все CVE", period: "10.10.2026", specialist: "HCP" } });
  const snapshot = readFileSync(path.join(state, "project-reports", record.fileName.replace(/\.pdf$/, ".json")), "utf8");
  assert.ok(Buffer.byteLength(snapshot) > 1024 * 1024);
  const parsed = JSON.parse(snapshot);
  assert.equal(parsed.unplannedFindings.length, 4000);
  assert.ok(parsed.unplannedFindings.every((finding) => finding.severityUnknown === true));
  assert.ok(parsed.unplannedFindings.some((finding) => finding.title.includes("CVE-2026-13999")));
  const pdf = projectReports.readProjectReportPdf(record.id).pdf;
  assert.ok(pdf.byteLength > 10_000);
  // Read the actual compressed page streams using Python's standard library.
  // Checking only the snapshot would miss a renderer silently keeping 80 rows.
  const contents = execFileSync("/usr/bin/python3", ["-c", `
import base64,json,re,sys,zlib
pdf=sys.stdin.buffer.read()
streams=[]
for raw in re.findall(rb'stream\\r?\\n(.*?)endstream',pdf,re.S):
    try:
        raw=raw.strip()
        if raw.endswith(b'~>'): raw=base64.a85decode(raw,adobe=True)
        streams.append(zlib.decompress(raw))
    except (ValueError,zlib.error): pass
text=b'\\n'.join(streams)
print(json.dumps({'count':len(re.findall(rb'CVE-2026-\\d{5}',text)),'last':b'CVE-2026-13999' in text}))
`], { input: pdf, encoding: "utf8" });
  assert.deepEqual(JSON.parse(contents), { count: 4000, last: true });
  assert.equal(store.verifyAuditChain().valid, true);
});
