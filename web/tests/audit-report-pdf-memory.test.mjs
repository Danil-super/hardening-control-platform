import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';
import ts from 'typescript';
import { compileServerModules } from './_typescript-loader.mjs';

const compiled = compileServerModules(['ansible-reports', 'native-report-storage', 'state-store', 'audit-result']);
const source = ts.transpileModule(readFileSync(new URL('../lib/audit-report-pdf.ts', import.meta.url), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test('preparing a PDF snapshot avoids report-sized comparison strings while retaining the exact source hash', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'hcp-pdf-memory-'));
  try {
    const fd = openSync(path.join(directory, 'large.json'), 'wx');
    const hash = createHash('sha256');
    const append = bytes => { writeSync(fd, bytes); hash.update(bytes); };
    try {
      append(Buffer.from('{"inventoryHost":"server","mode":"facts","findings":[],"events":[],"scanner":{"padding":"'));
      const chunk = Buffer.alloc(64 * 1024, 'x');
      for (let index = 0; index < 512; index++) append(chunk);
      append(Buffer.from('","tail":"Конец отчёта"}}'));
    } finally { closeSync(fd); }
    const code = `
      import { createRequire } from 'node:module';
      const require = createRequire(${JSON.stringify(import.meta.url)});
      const stubs = {
        '@/lib/ansible-reports': await import(${JSON.stringify(compiled.url('ansible-reports'))}),
        '@/lib/native-report-storage': await import(${JSON.stringify(compiled.url('native-report-storage'))}),
        '@/lib/state-store': await import(${JSON.stringify(compiled.url('state-store'))}),
        '@/lib/audit-result': await import(${JSON.stringify(compiled.url('audit-result'))}),
        '@/lib/project-report': {runPdfRenderer: async snapshot => {
          if(snapshot.id !== 'large' || snapshot.findings.length) throw new Error('Invalid snapshot');
          return Buffer.from('%PDF-stub');
        }},
      };
      const module = {exports:{}};
      new Function('require','module','exports',${JSON.stringify(source)})(name=>stubs[name]??require(name),module,module.exports);
      global.gc();const before=process.resourceUsage().maxRSS;
      const result=await module.exports.renderAuditReportPdf('large');
      console.log(JSON.stringify({sourceSha256:result.sourceSha256,additionalPeakBytes:(process.resourceUsage().maxRSS-before)*1024}));
    `;
    const child = spawnSync(process.execPath, ['--expose-gc', '--input-type=module', '-e', code], {
      env: { ...process.env, HCP_STATE_DIR: directory, HCP_REPORTS_DIR: directory }, encoding: 'utf8', timeout: 30_000,
    });
    assert.equal(child.status, 0, child.stderr);
    const result = JSON.parse(child.stdout);
    assert.equal(result.sourceSha256, hash.digest('hex'));
    // Non-ASCII input also needs a widened decoded string; keep room for parsing, not two extra serializations.
    assert.ok(result.additionalPeakBytes < 256 * 1024 * 1024, `32 MiB snapshot added ${result.additionalPeakBytes} bytes of peak RSS`);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('source comparison rejects changed nested values, types and array order before rendering', async () => {
  const raw = JSON.parse('{"scanner":{"nested":[null,true,1,"1",{"__proto__":"own value"}]}}');
  const require = createRequire(import.meta.url);
  let bytes = Buffer.from(JSON.stringify(raw)), rendered = 0, locked = false;
  const stubs = {
    '@/lib/ansible-reports': { readAnsibleReport: () => {
      assert.equal(locked, true);
      return { id: 'run', path: 'selected-report', raw, findings: [], events: [] };
    } },
    '@/lib/native-report-storage': { readNativeReportFile: (file, maximum) => {
      assert.equal(locked, true); assert.equal(file, 'selected-report'); assert.equal(maximum, 64 * 1024 * 1024);
      return bytes;
    } },
    '@/lib/state-store': { withReportEvidenceLock: callback => { locked = true; try { return callback(); } finally { locked = false; } } },
    '@/lib/audit-result': { auditReportLimitations: () => [] },
    '@/lib/project-report': { runPdfRenderer: async () => { assert.equal(locked, false); rendered++; return Buffer.from('%PDF-stub'); } },
  };
  const module = { exports: {} };
  new Function('require','module','exports',source)(name=>stubs[name]??require(name),module,module.exports);
  const result = await module.exports.renderAuditReportPdf('run');
  assert.equal(result.sourceSha256, createHash('sha256').update(bytes).digest('hex'));
  for (const nested of [[null,true,2,'1'], [null,true,'1',1], [null,true,1,'1',null], JSON.parse('[null,true,1,"1",{"__proto__":"changed"}]')]) {
    bytes = Buffer.from(JSON.stringify({scanner:{nested}}));
    await assert.rejects(module.exports.renderAuditReportPdf('run'), /report_changed/);
  }
  assert.equal(rendered, 1);
});
