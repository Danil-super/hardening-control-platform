import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test, { after } from "node:test";
import ts from "typescript";

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// Keep all fixtures and transpiled modules inside the project, not system temp.
const directory = mkdtempSync(path.join(web, ".native-export-tests-"));
const reports = path.join(directory, "reports"); mkdirSync(reports);
after(() => rmSync(directory, { recursive: true, force: true }));
const source = readFileSync(path.join(web, "lib/astra-oval-native-export.ts"), "utf8");
const transpile = (text) => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
writeFileSync(path.join(directory, "native.mjs"), transpile(source + "\nexport { xmlSafetyGuard };\n").replace('"node:child_process"', '"./generator.mjs"'));
writeFileSync(path.join(directory, "generator.mjs"), `
import { spawn as actualSpawn } from "node:child_process";
export let behavior = "success";
export let calls = [];
export function configure(value) { behavior = value; calls.length = 0; }
export function spawn(command, args, options) {
  calls.push({ command, args, options });
  const program = behavior === "failure" ? "process.exit(3)" : behavior === "hang" ? "setInterval(() => {}, 1000)" : "process.stdout.write('<!DOCTYPE html><html><body>native report</body></html>')";
  return actualSpawn(process.execPath, ["-e", program], options);
}
`);
const generator = await import(pathToFileURL(path.join(directory, "generator.mjs")).href);
const { nativeOvalDownload: download, nativeOvalAvailability: availability, nativeReportAvailability: reportAvailability, xmlSafetyGuard } = await import(pathToFileURL(path.join(directory, "native.mjs")).href);
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
let sequence = 0;
function fixture(xml = Buffer.from('<?xml version="1.0" encoding="UTF-8"?><oval_results>original XML</oval_results>')) {
  const id = `historic-astra-oval-${++sequence}`;
  const folder = path.join(reports, ".raw-evidence", id); mkdirSync(folder, { recursive: true, mode: 0o700 });
  const source = Buffer.from("<oval_definitions>exact original source</oval_definitions>");
  const raw = { mode: "astra-oval", scanner: { resultSha256: sha(xml), database: { sha256: sha(source) } }, rawEvidence: { version: 1, complete: true, artifacts: [
    { kind: "oval-results", path: `.raw-evidence/${id}/oval-results.xml`, bytes: xml.length, sha256: sha(xml) },
    { kind: "source", path: `.raw-evidence/${id}/source.xml`, bytes: source.length, sha256: sha(source) },
  ] } };
  const json = path.join(reports, `${id}.json`);
  const result = path.join(folder, "oval-results.xml");
  writeFileSync(result, xml); writeFileSync(path.join(folder, "source.xml"), source);
  const save = () => writeFileSync(json, JSON.stringify(raw)); save();
  return { id, folder, json, raw, xml, source, result, save };
}
const signal = () => new AbortController().signal;
const noWork = () => assert.deepEqual(readdirSync(path.join(reports, ".native-exports")), []);

test("view uses sandboxed inline HTML or inert text; download still returns the original bytes", async () => {
  const f = fixture();
  generator.configure("success");
  for (const format of ["html", "xml"]) {
    const response = await download(reports, f.id, format, signal(), true);
    assert.match(response.headers.get("content-disposition"), /^inline;/);
    assert.match(response.headers.get("content-security-policy"), /sandbox;/);
    assert.equal(response.headers.get("content-type"), format === "html" ? "text/html; charset=utf-8" : "text/plain; charset=utf-8");
    const bytes = Buffer.from(await response.arrayBuffer());
    if (format === "xml") assert.deepEqual(bytes, f.xml);
    else assert.match(bytes.toString(), /native report/);
    noWork();
  }
});

test("historical preserved XML/source bytes stream exactly; generated HTML is an attachment, not JSON", async () => {
  const f = fixture();
  assert.equal(await availability(reports, f.id, f.raw), true);
  for (const format of ["xml", "source-xml", "html"]) {
    generator.configure("success");
    const response = await download(reports, f.id, format, signal());
    assert.match(response.headers.get("content-disposition"), /^attachment; filename="historic/);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.match(response.headers.get("content-security-policy"), /sandbox; default-src 'none'/);
    assert.match(response.headers.get("cache-control"), /no-store/);
    const content = Buffer.from(await response.arrayBuffer());
    assert.equal(content.length, Number(response.headers.get("content-length")));
    if (format !== "html") assert.deepEqual(content, format === "xml" ? f.xml : f.source);
    else {
      assert.match(content.toString(), /native report/);
      assert.equal(generator.calls.length, 1);
      const call = generator.calls[0];
      assert.equal(call.command, "/usr/bin/prlimit");
      assert.deepEqual(call.args.slice(4, 9), ["/usr/bin/oscap", "oval", "generate", "report", path.join(call.options.cwd, "original.xml")]);
      assert.equal(call.options.shell, false);
      assert.equal(call.options.env.XML_CATALOG_FILES, "/dev/null");
    }
    noWork();
  }
  assert.deepEqual(readFileSync(f.result), f.xml);
});

test("preserved result remains downloadable without the source; absent original is explicit", async () => {
  const f = fixture();
  f.raw.rawEvidence.complete = false;
  f.raw.rawEvidence.missing = ["source"];
  f.raw.rawEvidence.artifacts.pop(); f.save();
  rmSync(path.join(f.folder, "source.xml"));
  const response = await download(reports, f.id, "xml", signal());
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), f.xml);
  await assert.rejects(download(reports, f.id, "source-xml", signal()), (error) => error.status === 404);
  rmSync(f.result);
  assert.equal(await availability(reports, f.id, f.raw), false);
  await assert.rejects(download(reports, f.id, "xml", signal()), (error) => error.code === "native_original_unavailable");
  noWork();
});

test("snapshot is private and immutable if published XML changes after verification", async () => {
  const f = fixture();
  const response = await download(reports, f.id, "xml", signal());
  const [work] = readdirSync(path.join(reports, ".native-exports"));
  assert.equal(statSync(path.join(reports, ".native-exports", work)).mode & 0o077, 0);
  assert.equal(statSync(path.join(reports, ".native-exports", work, "original.xml")).mode & 0o077, 0);
  writeFileSync(f.result, "changed later");
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), f.xml); noWork();
});

test("missing originals and metadata never substitute normalized JSON; identifiers/manifest paths fail closed", async () => {
  const f = fixture();
  for (const id of ["../escape", "%2e%2e%2fescape", "a/b", "a\\b", ".", "..", "a\r\nInjected:yes"]) {
    await assert.rejects(download(reports, id, "xml", signal()), (error) => error.code === "native_original_unavailable");
  }
  f.raw.rawEvidence.artifacts[0].path = "../../outside.xml"; f.save();
  await assert.rejects(download(reports, f.id, "xml", signal()), (error) => error.code === "native_integrity_failed");
  delete f.raw.rawEvidence; f.save();
  assert.equal(await availability(reports, f.id, f.raw), false);
  await assert.rejects(download(reports, f.id, "xml", signal()), (error) => error.status === 404);
  await assert.rejects(download(reports, f.id, "json", signal()), (error) => error.status === 400);
  noWork();
});

test("refuses changed hashes/sizes, oversized originals, nonregular files and symlinked files/parents/manifests", async () => {
  for (const scenario of ["hash", "size", "oversize", "directory", "file-link", "parent-link", "manifest-link", "scanner-hash"]) {
    const f = fixture();
    if (scenario === "hash") writeFileSync(f.result, Buffer.alloc(f.xml.length, 65));
    if (scenario === "size") writeFileSync(f.result, "short");
    if (scenario === "oversize") truncateSync(f.result, 384 * 1024 * 1024 + 1);
    if (scenario === "directory") { rmSync(f.result); mkdirSync(f.result); }
    if (scenario === "file-link") { rmSync(f.result); symlinkSync(path.join(f.folder, "source.xml"), f.result); }
    if (scenario === "parent-link") { renameSync(f.folder, `${f.folder}-other`); symlinkSync(`${f.folder}-other`, f.folder); }
    if (scenario === "manifest-link") { renameSync(f.json, `${f.json}.other`); symlinkSync(`${f.json}.other`, f.json); }
    if (scenario === "scanner-hash") { f.raw.scanner.resultSha256 = "a".repeat(64); f.save(); }
    await assert.rejects(download(reports, f.id, "xml", signal()), /Оригинальный|Целостность/);
    noWork();
  }
});

test("DTD/entities, alternate encodings, processing instructions and XInclude never reach OpenSCAP", async () => {
  for (const xml of [
    '<!DOCTYPE root SYSTEM "https://invalid.example/test"><root/>',
    '<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]><root>&x;</root>',
    '<?xml-stylesheet href="https://invalid.example/x.xsl"?><root/>',
    '<root><xi:include href="https://invalid.example/test"/></root>',
    '<root>' + "a".repeat(256 * 1024 - 9) + '<!DOCTYPE root SYSTEM "https://invalid.example/test"></root>',
    Buffer.from('<?xml version="1.0"?><root/>', "utf16le"),
  ]) {
    const f = fixture(Buffer.isBuffer(xml) ? xml : Buffer.from(xml));
    generator.configure("success");
    await assert.rejects(download(reports, f.id, "html", signal()), (error) => error.code === "unsafe_xml");
    assert.equal(generator.calls.length, 0); noWork();
    // Native XML is not parsed or rewritten, even when HTML is refused.
    const response = await download(reports, f.id, "xml", signal());
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), f.xml); noWork();
  }
});

test("generation failure and request cancellation clean private work; generation is bounded and cancelled", async () => {
  const f = fixture(); generator.configure("failure");
  await assert.rejects(download(reports, f.id, "html", signal()), (error) => error.code === "native_html_unavailable"); noWork();
  generator.configure("hang");
  const controller = new AbortController();
  const pending = download(reports, f.id, "html", controller.signal);
  const timer = setTimeout(() => controller.abort(), 100);
  await assert.rejects(pending, (error) => error.code === "native_export_aborted"); clearTimeout(timer); noWork();
  const response = await download(reports, f.id, "xml", signal());
  await response.body.cancel(); noWork();
});

test("at most two in-flight exports; cancellation releases capacity", async () => {
  const f = fixture();
  const first = await download(reports, f.id, "xml", signal());
  const second = await download(reports, f.id, "xml", signal());
  await assert.rejects(download(reports, f.id, "xml", signal()), (error) => error.status === 429);
  await first.body.cancel(); await second.body.cancel();
  const next = await download(reports, f.id, "xml", signal()); await next.body.cancel(); noWork();
});

function scannerFixture(mode, kind, extension, original) {
  const id = `native-${mode}-${++sequence}`;
  const folder = path.join(reports, ".raw-evidence", id); mkdirSync(folder, { recursive: true, mode: 0o700 });
  const raw = { mode, vulnerabilityScan: { provider: "Trivy" }, rawEvidence: { version: 1, complete: true, artifacts: [
    { kind, path: `.raw-evidence/${id}/${kind}.${extension}`, bytes: original.length, sha256: sha(original) },
  ] } };
  const result = path.join(folder, `${kind}.${extension}`);
  writeFileSync(result, original);
  const save = () => writeFileSync(path.join(reports, `${id}.json`), JSON.stringify(raw)); save();
  return { id, raw, result, save };
}

test("HTML rejects incompatible or oversized XML declarations while originals stay exact", async () => {
  for (const [mode, kind] of [["astra-oval", "oval-results"], ["openscap", "arf"]]) {
    for (const declaration of [
      '<?xml version="1.0" encoding="ISO-8859-1"?>',
      "<?xml version='1.0' " + " ".repeat(300) + "encoding='utf-7'?>",
      '<?xml version="1.0" ' + " ".repeat(1024) + 'encoding="UTF-8"?>',
      '<?xml version="1.0"',
    ]) {
      const xml = Buffer.from(declaration + (declaration.endsWith("?>") ? "<root>ordinary text</root>" : ""));
      const f = scannerFixture(mode, kind, "xml", xml);
      generator.configure("success");
      await assert.rejects(async () => {
        const response = await download(reports, f.id, "html", signal());
        await response.body.cancel();
      }, (error) => error.code === "unsafe_xml" && error.status === 409);
      assert.equal(generator.calls.length, 0); noWork();
      const original = await download(reports, f.id, "xml", signal());
      assert.deepEqual(Buffer.from(await original.arrayBuffer()), xml); noWork();
    }
  }
});

test("HTML accepts UTF-8 declaration aliases, BOM and long ordinary bodies", async () => {
  for (const [mode, kind] of [["astra-oval", "oval-results"], ["openscap", "arf"]]) {
    for (const prefix of ["", "\uFEFF", '<?xml version="1.0" encoding="UTF-8"?>',
      "\uFEFF<?xml version='1.0' encoding='uTf8'?>", '<?xml version="1.0" encoding="US-ASCII"?>']) {
      const xml = Buffer.from(prefix + "<root>" + "text".repeat(1000) + "</root>");
      const f = scannerFixture(mode, kind, "xml", xml);
      generator.configure("success");
      const response = await download(reports, f.id, "html", signal());
      assert.match(Buffer.from(await response.arrayBuffer()).toString(), /native report/);
      assert.equal(generator.calls.length, 1); noWork();
    }
  }
});

test("XML encoding checks survive every split in a declaration, BOM and multibyte text", () => {
  const valid = Buffer.from("\uFEFF<?xml version='1.0' " + " ".repeat(300) + "encoding = 'uTf8'?><root>Текст</root>");
  const incompatible = Buffer.from("<?xml version='1.0' encoding = 'ISO-8859-1'?><root>text</root>");
  const instruction = Buffer.from('<?xml-stylesheet href="style.xsl"?><root/>');
  for (const [bytes, accepted] of [[valid, true], [incompatible, false], [instruction, false]]) {
    for (let split = 0; split <= bytes.length; split++) {
      const inspect = xmlSafetyGuard();
      const run = () => {
        inspect(bytes.subarray(0, split)); inspect(bytes.subarray(split)); inspect(Buffer.alloc(0), true);
      };
      if (accepted) assert.doesNotThrow(run, `split ${split}`);
      else assert.throws(run, (error) => error.code === "unsafe_xml", `split ${split}`);
    }
  }
  for (const bytes of [Buffer.from("<root>\u20ac</root>").subarray(0, 8), Buffer.from("<?xml version='1.0'")]) {
    const inspect = xmlSafetyGuard();
    inspect(bytes);
    assert.throws(() => inspect(Buffer.alloc(0), true), (error) => error.code === "unsafe_xml");
  }
});

test("all supported scanners download their exact original bytes with format-specific names and MIME types", async () => {
  for (const [mode, kind, extension, format, bytes] of [
    ["nmap", "nmap", "xml", "xml", '<!DOCTYPE nmaprun><nmaprun scanner="nmap"/>\n'],
    ["ssh-audit", "ssh-audit", "json", "json", '{ "banner": "SSH-2.0-fixture", "original": true }\n'],
    ["lynis", "lynis-report", "dat", "dat", '# Lynis report\nwarning[]=FIXTURE|original|\n'],
    ["vulnerabilities", "trivy", "json", "json", '{"SchemaVersion":2,"Results":[]}\n'],
    ["greenbone", "greenbone", "xml", "xml", '<report id="fixture"><results/></report>\n'],
    ["dependency-track-analysis", "dependency-track", "json", "json", '{"project":"fixture","findings":[]}\n'],
    ["dependency-track", "sbom", "json", "sbom", '{"bomFormat":"CycloneDX","components":[]}\n'],
    ["openscap", "arf", "xml", "xml", '<arf:asset-report-collection xmlns:arf="urn:fixture"/>\n'],
  ]) {
    const original = Buffer.from(bytes);
    const f = scannerFixture(mode, kind, extension, original);
    const choices = await reportAvailability(reports, f.id, f.raw);
    assert.equal(choices.find(item => item.format === format)?.available, true, mode);
    const response = await download(reports, f.id, format, signal());
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), original, mode);
    assert.ok(response.headers.get("content-disposition").endsWith(`${kind}.${extension}"`));
    assert.match(response.headers.get("content-type"), extension === "xml" ? /application\/xml/ : extension === "json" ? /application\/json/ : /text\/plain/);
    assert.equal(response.headers.get("x-source-sha256"), sha(original));
    if (mode !== "openscap") {
      const automatic = await download(reports, f.id, null, signal());
      assert.deepEqual(Buffer.from(await automatic.arrayBuffer()), original);
      await assert.rejects(download(reports, f.id, "html", signal()), error => error.status === 400);
    }
    writeFileSync(f.result, Buffer.alloc(original.length, 65));
    await assert.rejects(download(reports, f.id, format, signal()), error => error.code === "native_integrity_failed");
    noWork();
  }
});

test("OpenSCAP configuration reports use its XCCDF generator; historical inline data is never a native original", async () => {
  const f = scannerFixture("openscap", "arf", "xml", Buffer.from('<asset-report-collection/>'));
  generator.configure("success");
  const response = await download(reports, f.id, "html", signal());
  await response.arrayBuffer();
  assert.equal(generator.calls[0].args[5], "xccdf");
  assert.deepEqual(generator.calls[0].args.slice(8, -1), ["--oval-template", "", "--sce-template", ""]);
  delete f.raw.rawEvidence; f.raw.scanner = { rawReport: "must not fabricate original" }; f.save();
  assert.ok((await reportAvailability(reports, f.id, f.raw)).every(item => !item.available));
  await assert.rejects(download(reports, f.id, "xml", signal()), error => error.status === 404);
  const unexpected = scannerFixture("nmap", "ssh-audit", "json", Buffer.from('{}'));
  await assert.rejects(download(reports, unexpected.id, "json", signal()), error => error.status === 400);
  noWork();
});

test("route authenticates before reading evidence and exposes explicit download failures", async () => {
  const mock = path.join(directory, "route-mocks.mjs");
  writeFileSync(mock, `export const authCookieName = "session"; export let token = ""; export const cookies = async () => ({ get: () => ({ value: token }) }); export const isAuthConfigured = () => true; export const isValidSessionToken = (value) => value === "valid"; export function authenticate() { token = "valid"; } export const getReportsDir = () => ${JSON.stringify(reports)};`);
  const routeSource = readFileSync(path.join(web, "app/api/ansible/reports/[reportId]/native/route.ts"), "utf8");
  writeFileSync(path.join(directory, "route.mjs"), transpile(routeSource)
    .replace('"next/headers"', '"./route-mocks.mjs"').replace('"@/lib/auth"', '"./route-mocks.mjs"')
    .replace('"@/lib/ansible-reports"', '"./route-mocks.mjs"').replace('"@/lib/astra-oval-native-export"', '"./native.mjs"'));
  const { GET } = await import(pathToFileURL(path.join(directory, "route.mjs")).href);
  const request = new Request("https://hcp.example/api/ansible/reports/missing/native?format=xml");
  const params = { params: Promise.resolve({ reportId: "missing" }) };
  assert.equal((await GET(request, params)).status, 401);
  (await import(pathToFileURL(mock).href)).authenticate();
  const missing = await GET(request, params);
  assert.equal(missing.status, 404); assert.equal((await missing.json()).error, "native_original_unavailable");
  const f = fixture();
  const response = await GET(request, { params: Promise.resolve({ reportId: f.id }) });
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), f.xml); noWork();
  const view = await GET(new Request('https://hcp.example/native?format=xml&view=1'), { params: Promise.resolve({ reportId: f.id }) });
  assert.match(view.headers.get('content-disposition'), /^inline;/);
  assert.deepEqual(Buffer.from(await view.arrayBuffer()), f.xml); noWork();
  assert.equal((await GET(new Request('https://hcp.example/native?view=invalid'), params)).status, 400);
});
