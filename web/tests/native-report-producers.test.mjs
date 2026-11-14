import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import vm from "node:vm";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
function load(relative, imports, extra = {}) {
  const exports = {};
  const source = ts.transpileModule(fs.readFileSync(path.join(web, relative), "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
  }).outputText;
  vm.runInNewContext(source, { exports, require: (name) => Object.hasOwn(imports, name) ? imports[name] : require(name),
    Buffer, TextDecoder, AbortSignal, URL, URLSearchParams, process, File, FormData, Response, fetch, ...extra });
  return exports;
}
function fixture(t, fsOverride) {
  const root = fs.mkdtempSync(path.join(web, "tests/.native-producers-"));
  const reports = path.join(root, "reports");
  fs.mkdirSync(reports);
  const environment = { HCP_STATE_DIR: root, HCP_REPORTS_DIR: reports, HCP_TRIVY_CACHE_DIR: path.join(root, "cache"),
    HCP_DEPENDENCY_TRACK_URL: "http://fixture.invalid", HCP_DEPENDENCY_TRACK_API_KEY: "private-fixture-api-key" };
  const previous = Object.fromEntries(Object.keys(environment).map(key => [key, process.env[key]]));
  Object.assign(process.env, environment);
  t.after(() => { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    fs.rmSync(root, { recursive: true, force: true }); });
  const reportsModule = { getReportsDir: () => reports, targetAliasFromReport: row => row.inventoryHost };
  const storage = load("lib/native-report-storage.ts", { "@/lib/ansible-reports": reportsModule, ...(fsOverride ? { "node:fs": fsOverride } : {}) });
  const state = { withReportEvidenceLock: fn => fn(), getVulnerabilityDatabaseSettings: () => ({ mode: "offline", source: "environment" }), getDebianTrackerSelection: () => ({}) };
  const control = { getStateDir: () => root, getRepoRoot: () => path.dirname(web) };
  return { root, reports, storage, state, control, reportsModule,
    raw: id => JSON.parse(fs.readFileSync(path.join(reports, id + ".json"), "utf8")) };
}
function artifact(f, report, kind, expected) {
  const item = report.rawEvidence.artifacts.find(row => row.kind === kind);
  assert.ok(item, kind);
  assert.match(item.path, new RegExp(`^\\.raw-evidence/[A-Za-z0-9_.:-]+/${kind}\\.(json|xml)$`));
  const bytes = fs.readFileSync(path.join(f.reports, item.path));
  assert.deepEqual(bytes, expected);
  assert.equal(item.bytes, bytes.length); assert.equal(item.sha256, sha(bytes));
  assert.equal(fs.statSync(path.join(f.reports, item.path)).mode & 0o077, 0);
  assert.equal(fs.statSync(path.dirname(path.join(f.reports, item.path))).mode & 0o077, 0);
}
function executor(handler) {
  const execFile = () => { throw new Error("unexpected callback execution"); };
  execFile[promisify.custom] = handler;
  return { execFile };
}

test("private atomic publication keeps exact XML/JSON and never rewrites historical reports", (t) => {
  const f = fixture(t);
  const bytes = Buffer.from('\ufeff{\r\n "original": "Кириллица", "order": 1 }\r\n');
  const report = f.storage.publishNativeReport("fixture-vuln", { mode: "vulnerabilities" }, [{ kind: "trivy", bytes }]);
  artifact(f, report, "trivy", bytes);
  assert.equal(report.rawEvidence.complete, true);
  const before = fs.readFileSync(path.join(f.reports, "fixture-vuln.json"));
  assert.throws(() => f.storage.publishNativeReport("fixture-vuln", { mode: "vulnerabilities" }, [{ kind: "trivy", bytes: Buffer.from("{}") }]));
  assert.deepEqual(fs.readFileSync(path.join(f.reports, "fixture-vuln.json")), before);
  artifact(f, report, "trivy", bytes);
  fs.writeFileSync(path.join(f.reports, "historical.json"), '{"mode":"vulnerabilities"}');
  assert.throws(() => f.storage.publishNativeReport("historical", { mode: "vulnerabilities" }, [{ kind: "trivy", bytes }]));
  assert.equal(fs.readFileSync(path.join(f.reports, "historical.json"), "utf8"), '{"mode":"vulnerabilities"}');
  assert.equal(fs.existsSync(path.join(f.reports, ".raw-evidence/historical")), false);
});

test("storage refuses paths, unsafe directories, types and sizes and rolls back failed publication", (t) => {
  const f = fixture(t);
  for (const id of ["../escape", ".", "x/y", "x\\y", "x..y", "x".repeat(240)]) {
    assert.throws(() => f.storage.publishNativeReport(id, { mode: "greenbone" }, [{ kind: "greenbone", bytes: Buffer.from("<xml/>") }]));
  }
  for (const input of [{ kind: "greenbone", bytes: "not bytes" }, { kind: "unknown", bytes: Buffer.from("{}") },
    { kind: "greenbone", bytes: Buffer.alloc(20 * 1024 * 1024 + 1) }]) {
    assert.throws(() => f.storage.publishNativeReport("invalid", { mode: "greenbone" }, [input]));
  }
  const outside = path.join(f.root, "outside"); fs.mkdirSync(outside);
  fs.symlinkSync(outside, path.join(f.reports, ".raw-evidence"));
  assert.throws(() => f.storage.publishNativeReport("link", { mode: "greenbone" }, [{ kind: "greenbone", bytes: Buffer.from("<xml/>") }]), /каталог/);
  assert.deepEqual(fs.readdirSync(outside), []);
  fs.rmSync(path.join(f.reports, ".raw-evidence"));
  const broken = fixture(t, { ...fs, linkSync() { throw new Error("publication failure"); } });
  assert.throws(() => broken.storage.publishNativeReport("rollback", { mode: "greenbone" }, [{ kind: "greenbone", bytes: Buffer.from("<xml/>") }]), /publication failure/);
  assert.deepEqual(fs.readdirSync(broken.reports), [".raw-evidence"]);
  assert.deepEqual(fs.readdirSync(path.join(broken.reports, ".raw-evidence")), []);
});

test("bounded source reader rejects links, directories, changed digest and oversized input", (t) => {
  const f = fixture(t), file = path.join(f.root, "source.xml"), bytes = Buffer.from("<xml>original</xml>");
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  assert.deepEqual(f.storage.readNativeReportFile(file, 100, { bytes: bytes.length, sha256: sha(bytes) }), bytes);
  assert.throws(() => f.storage.readNativeReportFile(file, 100, { bytes: bytes.length, sha256: "0".repeat(64) }));
  assert.throws(() => f.storage.readNativeReportFile(file, bytes.length - 1));
  assert.throws(() => f.storage.readNativeReportFile(f.root, 100));
  const linked = file + ".link"; fs.symlinkSync(file, linked);
  assert.throws(() => f.storage.readNativeReportFile(linked, 100));
  fs.rmSync(linked); fs.linkSync(file, linked);
  assert.throws(() => f.storage.readNativeReportFile(file, 100));
});

function trivyFixture(t, scenario) {
  const f = fixture(t);
  fs.mkdirSync(path.join(f.root, "cache/db"), { recursive: true });
  fs.writeFileSync(path.join(f.root, "cache/db/trivy.db"), "fixture database, no real scanner");
  fs.writeFileSync(path.join(f.root, "cache/db/metadata.json"), JSON.stringify({ Version: 2, UpdatedAt: new Date().toISOString() }));
  fs.writeFileSync(path.join(f.reports, "packages.json"), JSON.stringify({ mode: "packages", inventoryHost: "host", createdAt: new Date().toISOString(),
    packageInventory: { packageCount: 1, manager: "dpkg", osRelease: { ID: "ubuntu", VERSION_ID: "22.04" } },
    packages: [{ name: "openssl", version: "3.0.0-1", manager: "dpkg", arch: "amd64", sourceName: "openssl", sourceVersion: "3.0.0-1", origin: "Ubuntu" }] }));
  let native;
  const child = executor(async (_command, args) => {
    if (scenario === "unavailable") return { stdout: JSON.stringify({ ok: false, errorCode: "binary_missing" }) };
    const sbom = JSON.parse(fs.readFileSync(args[args.indexOf("--sbom") + 1], "utf8"));
    const pkg = sbom.components[0];
    native = Buffer.from('\ufeff' + JSON.stringify({ SchemaVersion: 2, Metadata: { OS: { Family: "ubuntu", Name: "22.04" } },
      Results: [{ Class: "os-pkgs", Type: "ubuntu", Packages: [{ Name: pkg.name, Version: pkg.version, Identifier: { BOMRef: pkg["bom-ref"], PURL: pkg.purl } }] }] }, null, 3) + "\r\n");
    if (scenario === "malformed") native = Buffer.from([0xff, 0xfe, 0x7b]);
    const file = args[args.indexOf("--stdout-file") + 1];
    fs.writeFileSync(file, native, { mode: 0o600 });
    return { stdout: JSON.stringify({ ok: scenario !== "native-failure", errorCode: "native_exit", stdoutFile: { bytes: native.length, sha256: sha(native) },
      sourceEvidence: { version: 1, status: "unchanged", checkedAt: new Date().toISOString(), databaseUpdatedAt: new Date().toISOString() } }) };
  });
  const scan = load("lib/vulnerability-scan.ts", {
    "node:child_process": child, "@/lib/ansible-control": f.control, "@/lib/ansible-reports": f.reportsModule, "@/lib/state-store": f.state,
    "@/lib/native-report-storage": f.storage, "@/lib/trivy-output": load("lib/trivy-output.ts", {}),
    "@/lib/linux-platform": load("lib/linux-platform.ts", {}), "@/lib/astra-oval-policy": {},
    "@/lib/ubuntu-osv-preview": { annotateUbuntuOsvPreview: ({ findings }) => ({ findings }) },
    "@/lib/debian-tracker-preview": { annotateDebianTrackerPreview: ({ findings }) => ({ findings }) },
    "@/lib/debian-apt-provenance": { summarizeDebianAptRepositoryEvidence: () => null },
    "@/lib/debian-signed-release": { summarizeDebianSignedReleases: () => null },
    "@/lib/debian-package-index-evidence": { summarizeDebianPackageIndexes: () => null },
  });
  return { ...f, scan, native: () => native };
}

test("Trivy publishes its exact stdout (including BOM) and HCP SBOM before normalizing", async (t) => {
  const f = trivyFixture(t, "success");
  const result = await f.scan.scanPackageInventory({ hostAlias: "host", reportId: "packages" });
  const report = f.raw(result.reportId);
  assert.equal(report.scanner.available, true); assert.equal(report.rawEvidence.complete, true);
  artifact(f, report, "trivy", f.native());
  artifact(f, report, "sbom", fs.readFileSync(path.join(f.root, "sbom", report.vulnerabilityScan.sbomFile)));
  assert.match(report.vulnerabilityScan.sbomOrigin, /HCP.*не официальный/);
  assert.equal(fs.readdirSync(f.root).some(name => name.startsWith("hcp-trivy-output-")), false);
  assert.equal(f.raw("packages").rawEvidence, undefined);
});

test("unavailable Trivy stays explicit while a failed native process retains verified stdout", async (t) => {
  for (const scenario of ["unavailable", "native-failure", "malformed"]) {
    const f = trivyFixture(t, scenario);
    const result = await f.scan.scanPackageInventory({ hostAlias: "host", reportId: "packages" });
    const report = f.raw(result.reportId);
    assert.equal(report.scanner.available, false); assert.equal(report.scanner.partial, true);
    if (scenario === "unavailable") { assert.deepEqual(report.rawEvidence.missing, ["trivy"]); assert.equal(report.rawEvidence.complete, false); }
    else artifact(f, report, "trivy", f.native());
  }
});

function greenboneFixture(t, valid) {
  const f = fixture(t);
  const route = load("app/api/ansible/greenbone/import/route.ts", {
    "node:child_process": executor(async (_command, args) => {
      const output = args[args.indexOf("--output") + 1];
      assert.equal(output.startsWith(f.reports + path.sep), false);
      fs.writeFileSync(output, JSON.stringify({ mode: "greenbone", inventoryHost: "host", scanner: { imported: valid, partial: false }, findings: [] }));
      return { stdout: "", stderr: "" };
    }), "next/server": { NextResponse: { json: (body, init) => ({ body, status: init?.status ?? 200 }) } },
    "@/lib/ansible-control": { ...f.control, isSafeLimit: value => value === "host", inventoryHostExists: () => true, inventoryHostAddress: () => "192.0.2.1", appendIncident() {} },
    "@/lib/native-report-storage": f.storage, "@/lib/state-store": f.state,
  });
  return { ...f, route };
}

test("Greenbone import atomically binds the byte-exact uploaded XML, not regenerated XML", async (t) => {
  const f = greenboneFixture(t, true);
  const bytes = Buffer.concat([Buffer.from('<?xml version="1.0" encoding="ISO-8859-1"?>\r\n<report>'), Buffer.from([0xe9]), Buffer.from("</report>\r\n")]);
  const form = new FormData(); form.set("hostAlias", "host"); form.set("report", new File([bytes], "original.xml"));
  const response = await f.route.POST({ formData: async () => form });
  assert.equal(response.status, 200); assert.equal(response.body.ok, true);
  artifact(f, f.raw(response.body.reportId), "greenbone", bytes);
  assert.equal(fs.readdirSync(f.root).some(name => name.startsWith("greenbone-import-")), false);
});

test("rejected Greenbone imports publish neither normalized data nor an artifact", async (t) => {
  const f = greenboneFixture(t, false);
  const form = new FormData(); form.set("hostAlias", "host"); form.set("report", new File(["<bad/>"], "bad.xml"));
  assert.equal((await f.route.POST({ formData: async () => form })).status, 400);
  assert.deepEqual(fs.readdirSync(f.reports), []);
});

function dtrackFixture(t, exportMode = "official") {
  const f = fixture(t);
  const token = "11111111-1111-4111-8111-111111111111", uuid = "22222222-2222-4222-8222-222222222222";
  const component = { uuid: "33333333-3333-4333-8333-333333333333", name: "openssl", version: "3.0.0", purl: "pkg:generic/openssl@3.0.0" };
  const sbom = Buffer.from(JSON.stringify({ bomFormat: "CycloneDX", components: [{ type: "library", ...component, uuid: undefined }] }, null, 3) + "\n");
  fs.mkdirSync(path.join(f.root, "sbom")); fs.writeFileSync(path.join(f.root, "sbom/source.json"), sbom);
  fs.writeFileSync(path.join(f.reports, "source.json"), JSON.stringify({ inventoryHost: "host", mode: "vulnerabilities", vulnerabilityScan: { sbomFile: "source.json" } }));
  const project = { uuid, name: "host", version: "", lastBomImport: Date.now(), lastVulnerabilityAnalysis: Date.now() + 1 };
  const calls = []; let native;
  const service = async (url, init) => {
    const endpoint = new URL(url).pathname; calls.push({ endpoint, method: init?.method ?? "GET" });
    const headers = { "content-type": "application/json", date: new Date().toUTCString() };
    let data;
    if (endpoint === "/api/v1/bom") { project.version = JSON.parse(init.body).projectVersion; data = { token }; }
    else if (endpoint.startsWith("/api/v1/event/token/")) data = { processing: false };
    else if (endpoint.startsWith("/api/v1/project/")) data = project;
    else if (endpoint.startsWith("/api/v1/component/project/")) { data = [component]; headers["x-total-count"] = "1"; }
    else if (endpoint.endsWith("/export")) {
      if (exportMode === "unavailable") return new Response('{"password":"do not persist"}', { status: 403 });
      data = { version: "1.4", meta: { application: "Dependency-Track" }, project, findings: [],
        ...(exportMode === "secret" ? { echoed: process.env.HCP_DEPENDENCY_TRACK_API_KEY } : {}) };
      if (exportMode === "foreign") data.project = { ...project, uuid: token };
      native = Buffer.from(" \r\n" + JSON.stringify(data, null, 2) + "\r\n");
      return new Response(native, { headers });
    } else if (endpoint.startsWith("/api/v1/finding/project/")) { data = []; headers["x-total-count"] = "0"; }
    else throw new Error("unexpected endpoint");
    return new Response(JSON.stringify(data), { headers });
  };
  const adapter = load("lib/dependency-track.ts", { "@/lib/ansible-control": f.control, "@/lib/ansible-reports": f.reportsModule,
    "@/lib/state-store": f.state, "@/lib/native-report-storage": f.storage, "@/lib/asset-binding": { parseAssetBinding: () => null } }, { fetch: service });
  return { ...f, adapter, calls, sbom, native: () => native };
}

test("Dependency-Track retains only the official FPF export bytes and HCP SBOM; old reports stay immutable", async (t) => {
  const f = dtrackFixture(t);
  const delivery = await f.adapter.syncDependencyTrack({ hostAlias: "host", vulnerabilityReportId: "source" });
  const before = fs.readFileSync(path.join(f.reports, delivery.reportId + ".json"));
  artifact(f, f.raw(delivery.reportId), "sbom", f.sbom);
  assert.match(f.raw(delivery.reportId).scanner.sbomOrigin, /HCP.*не официальный/);
  const result = await f.adapter.refreshDependencyTrack({ hostAlias: "host", reportId: delivery.reportId });
  assert.equal(result.status, "complete");
  const report = f.raw(result.reportId); artifact(f, report, "dependency-track", f.native());
  assert.equal(report.rawEvidence.complete, true); assert.equal(report.scanner.nativeReport.format, "FPF");
  assert.deepEqual(fs.readFileSync(path.join(f.reports, delivery.reportId + ".json")), before);
  assert.equal(fs.readFileSync(path.join(f.reports, result.reportId + ".json"), "utf8").includes(process.env.HCP_DEPENDENCY_TRACK_API_KEY), false);
  assert.ok(f.calls.some(call => call.endpoint.endsWith("/export") && call.method === "GET"));
  assert.equal(f.calls.filter(call => call.method !== "GET").length, 1);
  const again = await f.adapter.refreshDependencyTrack({ hostAlias: "host", reportId: result.reportId });
  assert.equal(again.reused, true); assert.equal(again.reportId, result.reportId);
});

test("missing, foreign or credential-bearing FPF is never replaced by a fake native envelope", async (t) => {
  for (const mode of ["unavailable", "foreign", "secret"]) {
    const f = dtrackFixture(t, mode);
    const delivery = await f.adapter.syncDependencyTrack({ hostAlias: "host", vulnerabilityReportId: "source" });
    const result = await f.adapter.refreshDependencyTrack({ hostAlias: "host", reportId: delivery.reportId });
    const report = f.raw(result.reportId);
    assert.equal(result.status, "complete"); assert.equal(report.rawEvidence.complete, false);
    assert.deepEqual(report.rawEvidence.missing, ["dependency-track"]);
    assert.deepEqual(report.rawEvidence.artifacts.map(item => item.kind), ["sbom"]);
    assert.match(report.scanner.nativeReport.limitation, /не являются оригинальным/);
    assert.equal(fs.readFileSync(path.join(f.reports, result.reportId + ".json"), "utf8").includes(process.env.HCP_DEPENDENCY_TRACK_API_KEY), false);
  }
});
