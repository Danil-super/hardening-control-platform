import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, afterEach, beforeEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

// Real adapter, report parser, SQLite publication lock and correlation. Only
// the external DTrack4.14 HTTP service is a controlled API contract fixture.
const compiled = compileServerModules(["dependency-track", "ansible-reports", "audit-correlation", "project-report"]);
const { syncDependencyTrack, refreshDependencyTrack } = await import(compiled.url("dependency-track"));
const reports = await import(compiled.url("ansible-reports"));
const { buildHostCorrelation } = await import(compiled.url("audit-correlation"));
const projectReports = await import(compiled.url("project-report"));
const envNames = ["HCP_STATE_DIR", "HCP_REPORTS_DIR", "HCP_DEPENDENCY_TRACK_URL", "HCP_DEPENDENCY_TRACK_API_KEY"];
const prior = Object.fromEntries(envNames.map(key => [key, process.env[key]]));
const token = "11111111-1111-4111-8111-111111111111";
const projectUuid = "22222222-2222-4222-8222-222222222222";
const componentUuid = "33333333-3333-4333-8333-333333333333";
const vulnUuid = "44444444-4444-4444-8444-444444444444";
let directory, server, overrides, calls, bom, project, components, findings;
const json = (data, extra = {}) => ({ data, status: 200, headers: { "content-type": "application/json", ...extra } });
const file = id => path.join(directory, "reports", id + ".json");
const raw = id => JSON.parse(readFileSync(file(id), "utf8"));
const upload = () => syncDependencyTrack({ hostAlias: "host-one", vulnerabilityReportId: "source" });
const refresh = reportId => refreshDependencyTrack({ hostAlias: "host-one", reportId });

beforeEach(async () => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-dtrack-results-"));
  mkdirSync(path.join(directory, "reports")); mkdirSync(path.join(directory, "sbom"));
  process.env.HCP_STATE_DIR = directory;
  process.env.HCP_REPORTS_DIR = path.join(directory, "reports");
  process.env.HCP_DEPENDENCY_TRACK_API_KEY = "fixture-secret-api-key";
  bom = { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components: [{ type: "library", name: "libssl3", version: "3.0.2-0ubuntu1.7", purl: "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.7?arch=amd64&distro=ubuntu-22.04" }] };
  writeFileSync(path.join(directory, "sbom", "fixture.json"), JSON.stringify(bom));
  writeFileSync(file("source"), JSON.stringify({ inventoryHost: "host-one", mode: "vulnerabilities", os: "Ubuntu22.04", vulnerabilityScan: { sbomFile: "fixture.json" } }));
  project = { uuid: projectUuid, name: "host-one", version: "unset", lastBomImport: Date.now(), lastVulnerabilityAnalysis: Date.now() };
  components = [{ uuid: componentUuid, ...bom.components[0] }];
  findings = [{ component: { ...components[0], project: projectUuid }, vulnerability: { uuid: vulnUuid, vulnId: "CVE-2023-0286", source: "NVD", severity: "CRITICAL", description: "Fixture description", recommendation: "Vendor-fixed release", cvssV3BaseScore: 9.8 }, analysis: { isSuppressed: false }, attribution: { analyzerIdentity: "INTERNAL_ANALYZER" } }];
  overrides = new Map(); calls = [];
  server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    const url = new URL(request.url, "http://localhost");
    calls.push({ url, method: request.method, body, key: request.headers["x-api-key"] });
    let result;
    if (overrides.has(url.pathname)) result = await overrides.get(url.pathname)({ request, url, body });
    else if (url.pathname === "/api/v1/bom") {
      project.version = JSON.parse(body).projectVersion;
      project.lastBomImport = Date.now(); project.lastVulnerabilityAnalysis = project.lastBomImport + 1;
      result = json({ token });
    } else if (url.pathname.startsWith("/api/v1/event/token/")) result = json({ processing: false });
    else if (url.pathname === "/api/v1/project/lookup" || url.pathname === "/api/v1/project/" + projectUuid) result = json(project);
    else if (url.pathname.startsWith("/api/v1/component/project/")) result = json(components, { "x-total-count": String(components.length) });
    else if (url.pathname.startsWith("/api/v1/finding/project/")) result = json(findings, { "x-total-count": String(findings.length) });
    else result = { status: 404, data: {} };
    response.writeHead(result.status ?? 200, result.headers ?? { "content-type": "application/json" });
    response.end(JSON.stringify(result.data));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  process.env.HCP_DEPENDENCY_TRACK_URL = `http://127.0.0.1:${server.address().port}`;
});

afterEach(async () => {
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  rmSync(directory, { recursive: true, force: true });
});
after(() => { for (const [key, value] of Object.entries(prior)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } rmSync(compiled.directory, { recursive: true, force: true }); });

test("completed findings enter the real report and correlation while delivery stays historical and excluded", async () => {
  const delivered = await upload(); const before = readFileSync(file(delivered.reportId), "utf8");
  const result = await refresh(delivered.reportId);
  assert.equal(result.status, "complete"); assert.equal(result.findingCount, 1);
  const report = reports.readAnsibleReport(result.reportId);
  assert.equal(report.mode, "dependency-track-analysis"); assert.equal(report.partial, true);
  assert.equal(report.findings[0].status, "failed"); assert.equal(report.findings[0].severityAssessment.level, "critical");
  assert.match(report.findings[0].evidence, /CVE-2023-0286/);
  assert.equal(report.score, null);
  const correlation = buildHostCorrelation("host-one");
  assert.ok(correlation.findings.some(item => item.title.includes("CVE-2023-0286")));
  assert.equal(correlation.coverage.find(row => row.mode === "dependency-track").auditEvidence, false);
  assert.equal(correlation.coverage.find(row => row.mode === "dependency-track-analysis").auditEvidence, true);
  assert.equal(readFileSync(file(delivered.reportId), "utf8"), before);
  assert.ok(reports.listAnsibleReportDependents(delivered.reportId).some(item => item.id === result.reportId));
  assert.ok(reports.listAnsibleReportDependents("source").some(item => item.id === result.reportId));
  const exported = await projectReports.createProjectReport({ hostAlias: "host-one", subject: {
    clientName: "Fixture client", projectName: "Dependency-Track results", period: "Fixture interval", specialist: "Fixture reviewer",
  } });
  const snapshot = JSON.parse(readFileSync(path.join(directory, "project-reports", exported.fileName.replace(/\.pdf$/, ".json")), "utf8"));
  assert.ok(snapshot.unplannedFindings.some(item => item.title.includes("CVE-2023-0286")));
  assert.equal(snapshot.sourceManifest.find(item => item.id === result.reportId).partial, true);
  assert.equal(projectReports.readProjectReportPdf(exported.id).pdf.subarray(0, 5).toString(), "%PDF-");
  assert.ok(projectReports.listProjectReportSourceReferences(result.reportId, "host-one").some(item => item.id === exported.id));
});

test("upload and stable result refresh are idempotent and do not rewrite immutable evidence", async () => {
  const delivered = await upload();
  assert.equal((await upload()).reportId, delivered.reportId);
  assert.equal(calls.filter(call => call.method === "PUT").length, 1);
  const one = await refresh(delivered.reportId); const saved = readFileSync(file(one.reportId));
  const two = await refresh(one.reportId);
  assert.equal(two.reportId, one.reportId); assert.equal(two.reused, true);
  assert.deepEqual(readFileSync(file(one.reportId)), saved);
});

test("an empty result remains incomplete and never manufactures a pass or a security score", async () => {
  const delivered = await upload(); findings = [];
  const result = await refresh(delivered.reportId); const report = reports.readAnsibleReport(result.reportId);
  assert.equal(result.status, "complete"); assert.equal(result.findingCount, 0);
  assert.equal(report.partial, true); assert.equal(report.score, null);
  assert.deepEqual(report.findings.map(item => item.status), ["manual"]);
  assert.equal(raw(result.reportId).scanner.sourceCoverageVerified, false);
});

test("active processing and false tokens without a new analysis cannot finish an import", async () => {
  const delivered = await upload();
  overrides.set("/api/v1/event/token/" + token, () => json({ processing: true }));
  assert.equal((await refresh(delivered.reportId)).status, "processing");
  overrides.clear(); project.lastVulnerabilityAnalysis = project.lastBomImport - 1;
  assert.equal((await refresh(delivered.reportId)).status, "processing");
  delete project.lastVulnerabilityAnalysis;
  assert.equal((await refresh(delivered.reportId)).status, "processing");
  assert.equal(readdirSync(path.join(directory, "reports")).filter(name => name.includes("analysis")).length, 0);
});

test("an old import cannot be freshened by a later analysis or unknown event token", async () => {
  const delivered = await upload(); project.lastBomImport = 1; project.lastVulnerabilityAnalysis = Date.now();
  assert.equal((await refresh(delivered.reportId)).status, "processing");
});

test("unsupported event states and a missing server clock cannot certify completion", async () => {
  const delivered = await upload();
  overrides.set("/api/v1/event/token/" + token, () => json({ processing: false, status: "UNKNOWN" }));
  await assert.rejects(refresh(delivered.reportId), /неподдерживаемое/);
  overrides.clear();
  const report = raw(delivered.reportId); report.scanner.binding.serverUploadTime = null;
  writeFileSync(file(delivered.reportId), JSON.stringify(report));
  await assert.rejects(refresh(delivered.reportId), /серверное время/);
  assert.equal(readdirSync(path.join(directory, "reports")).filter(name => name.includes("analysis")).length, 0);
});

test("nested SBOM components are rejected instead of certifying only the top level", async () => {
  bom.components[0].components = [{ type: "library", name: "child", version: "1" }];
  writeFileSync(path.join(directory, "sbom", "fixture.json"), JSON.stringify(bom));
  await assert.rejects(upload(), /Вложенные компоненты/);
  assert.equal(calls.length, 0);
});

test("different host, endpoint, project version and component manifest are rejected", async () => {
  const delivered = await upload();
  await assert.rejects(refreshDependencyTrack({ hostAlias: "other-host", reportId: delivered.reportId }), /не принадлежит/);
  const endpoint = process.env.HCP_DEPENDENCY_TRACK_URL;
  process.env.HCP_DEPENDENCY_TRACK_URL = endpoint + "/other";
  await assert.rejects(refresh(delivered.reportId), /URL/);
  process.env.HCP_DEPENDENCY_TRACK_URL = endpoint;
  const version = project.version; project.version = "other-inventory";
  await assert.rejects(refresh(delivered.reportId), /другой проект/);
  project.version = version; components[0].version = "3.0.2-0ubuntu1.8";
  await assert.rejects(refresh(delivered.reportId), /не совпадают/);
});

test("source or SBOM tampering fails before an API request", async () => {
  const delivered = await upload(); const count = calls.length;
  writeFileSync(path.join(directory, "sbom", "fixture.json"), JSON.stringify({ ...bom, version: 2 }));
  await assert.rejects(refresh(delivered.reportId), /изменился/);
  assert.equal(calls.length, count);
});

test("a source deletion while the API is awaited prevents publishing an orphan analysis", async () => {
  const delivered = await upload();
  overrides.set("/api/v1/finding/project/" + projectUuid, () => {
    rmSync(file("source"));
    return json(findings, { "x-total-count": String(findings.length) });
  });
  await assert.rejects(refresh(delivered.reportId));
  assert.equal(readdirSync(path.join(directory, "reports")).filter(name => name.includes("analysis")).length, 0);
});

test("pagination gathers all components and findings and rejects repeated/truncated pages", async () => {
  bom.components.push({ type: "library", name: "openssl", version: "3.0.2-0ubuntu1.7", purl: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.7" });
  writeFileSync(path.join(directory, "sbom", "fixture.json"), JSON.stringify(bom));
  components.push({ uuid: "55555555-5555-4555-8555-555555555555", ...bom.components[1] });
  findings.push({ ...findings[0], component: { ...components[1], project: projectUuid } });
  const delivered = await upload();
  overrides.set("/api/v1/component/project/" + projectUuid, ({ url }) => json([components[Number(url.searchParams.get("pageNumber")) - 1]], { "x-total-count": "2" }));
  overrides.set("/api/v1/finding/project/" + projectUuid, ({ url }) => json([findings[Number(url.searchParams.get("pageNumber")) - 1]], { "x-total-count": "2" }));
  assert.equal((await refresh(delivered.reportId)).findingCount, 2);
  overrides.set("/api/v1/component/project/" + projectUuid, () => json([components[0]], { "x-total-count": "2" }));
  await assert.rejects(refresh(delivered.reportId), /повторяющиеся/);
  overrides.set("/api/v1/component/project/" + projectUuid, ({ url }) => json(url.searchParams.get("pageNumber") === "1" ? [components[0]] : [], { "x-total-count": "2" }));
  await assert.rejects(refresh(delivered.reportId), /усечённый/);
});

test("inconsistent total counts and missing total count are not accepted", async () => {
  const delivered = await upload();
  overrides.set("/api/v1/finding/project/" + projectUuid, () => json(findings));
  await assert.rejects(refresh(delivered.reportId), /полное количество/);
  overrides.set("/api/v1/finding/project/" + projectUuid, ({ url }) => json(findings, { "x-total-count": url.searchParams.get("pageNumber") === "1" ? "2" : "3" }));
  await assert.rejects(refresh(delivered.reportId), /Количество результатов/);
});

test("changed project metadata during pagination requests a retry without publishing", async () => {
  const delivered = await upload();
  overrides.set("/api/v1/project/" + projectUuid, () => json({ ...project, lastBomImport: project.lastBomImport + 10 }));
  assert.equal((await refresh(delivered.reportId)).status, "processing");
  assert.equal(readdirSync(path.join(directory, "reports")).filter(name => name.includes("analysis")).length, 0);
});

test("findings on a foreign component are rejected and unknown/suppressed severities stay explicit", async () => {
  const delivered = await upload();
  findings[0].component.uuid = "66666666-6666-4666-8666-666666666666";
  await assert.rejects(refresh(delivered.reportId), /не принадлежит/);
  findings[0].component.uuid = componentUuid;
  findings[0].component.project = "77777777-7777-4777-8777-777777777777";
  await assert.rejects(refresh(delivered.reportId), /не принадлежит/);
  findings[0].component.project = projectUuid;
  findings[0].component.uuid = componentUuid; findings[0].vulnerability.severity = "UNASSIGNED";
  findings[0].analysis = { isSuppressed: true, state: "FALSE_POSITIVE", detail: "Fixture adjudication" };
  const result = await refresh(delivered.reportId); const finding = raw(result.reportId).findings[0];
  assert.equal(finding.status, "manual"); assert.equal(finding.severityUnknown, true);
  assert.match(finding.description, /FALSE_POSITIVE/);
});

test("HTTP error bodies containing credentials are never exposed and redirects are not followed", async () => {
  const delivered = await upload();
  overrides.set("/api/v1/event/token/" + token, () => ({ status: 403, data: { key: process.env.HCP_DEPENDENCY_TRACK_API_KEY } }));
  await assert.rejects(refresh(delivered.reportId), error => error.message.includes("403") && !error.message.includes("fixture-secret"));
  overrides.set("/api/v1/event/token/" + token, () => ({ status: 302, headers: { location: "/should-not-follow" }, data: {} }));
  await assert.rejects(refresh(delivered.reportId), /перенаправление/);
  assert.equal(calls.some(call => call.url.pathname === "/should-not-follow"), false);
});

test("legacy upload reports cannot infer completion without the immutable SBOM binding", async () => {
  writeFileSync(file("legacy"), JSON.stringify({ inventoryHost: "host-one", mode: "dependency-track", scanner: { processingToken: token } }));
  await assert.rejects(refresh("legacy"), /старой передачи/);
  assert.equal(calls.length, 0);
});
