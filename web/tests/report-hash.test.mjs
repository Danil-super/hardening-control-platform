import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { closeSync, mkdirSync, mkdtempSync, openSync, readdirSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';
import { compileServerModules } from './_typescript-loader.mjs';

const compiled = compileServerModules(['ansible-reports']);
const root = mkdtempSync(path.join(tmpdir(), 'hcp-report-hash-'));
process.env.HCP_REPORTS_DIR = root;
const reports = await import(compiled.url('ansible-reports'));
after(() => {
  delete process.env.HCP_REPORTS_DIR;
  rmSync(root, { recursive: true, force: true });
  rmSync(compiled.directory, { recursive: true, force: true });
});

test('hashing a large source preserves every byte without another report-sized memory allocation', () => {
  const fd = openSync(path.join(root, 'large.json'), 'wx');
  const expected = createHash('sha256');
  const append = bytes => { writeSync(fd, bytes); expected.update(bytes); };
  try {
    append(Buffer.from('{"mode":"facts","payload":"'));
    const chunk = Buffer.alloc(64 * 1024, 'x');
    for (let index = 0; index < 1024; index++) append(chunk);
    append(Buffer.from('","tail":"Конец отчёта"}\n'));
  } finally { closeSync(fd); }
  const code = `
    const { hashAnsibleReport } = await import(${JSON.stringify(compiled.url('ansible-reports'))});
    global.gc();
    const before = process.resourceUsage().maxRSS;
    const sha256 = hashAnsibleReport('large');
    console.log(JSON.stringify({ sha256, additionalPeakBytes: (process.resourceUsage().maxRSS - before) * 1024 }));
  `;
  const child = spawnSync(process.execPath, ['--expose-gc', '--input-type=module', '-e', code], {
    env: process.env, encoding: 'utf8', timeout: 30_000,
  });
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.equal(result.sha256, expected.digest('hex'));
  assert.ok(result.additionalPeakBytes < 32 * 1024 * 1024,
    `hashing 64 MiB added ${result.additionalPeakBytes} bytes of peak RSS`);
});

test('source hashes include empty input, exact block boundaries and the final partial block', () => {
  for (const size of [0, 1, 1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1, 2 * 1024 * 1024 + 73]) {
    const bytes = Buffer.alloc(size, 0xa5);
    if (size) bytes[size - 1] = 0x17;
    writeFileSync(path.join(root, 'boundary.json'), bytes);
    assert.equal(reports.hashAnsibleReport('boundary'), createHash('sha256').update(bytes).digest('hex'));
  }
});

test('invalid and missing reports stay unavailable; read errors do not leak descriptors', () => {
  for (const id of ['../outside', '../../etc/passwd', 'missing', '\0']) assert.equal(reports.hashAnsibleReport(id), null);
  mkdirSync(path.join(root, 'directory.json'));
  const before = readdirSync('/proc/self/fd').length;
  for (let index = 0; index < 32; index++) assert.equal(reports.hashAnsibleReport('directory'), null);
  assert.equal(readdirSync('/proc/self/fd').length, before);
  writeFileSync(path.join(root, 'recovered.json'), 'source still readable');
  assert.equal(reports.hashAnsibleReport('recovered'), createHash('sha256').update('source still readable').digest('hex'));
});
