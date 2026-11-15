import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import ts from 'typescript';

const require = createRequire(import.meta.url);
const source = ts.transpileModule(readFileSync(new URL('../lib/project-report.ts', import.meta.url), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
}).outputText;
const children = [];
let spawnFailure = false;
function loadRenderer() {
  const module = { exports: {} };
  new Function('require', 'module', 'exports', source)(name => {
    if (name === 'node:child_process') return { spawn() {
      if (spawnFailure) throw new Error('fixture spawn failed');
      const child = new EventEmitter();
      for (const stream of ['stdin', 'stdout', 'stderr']) child[stream] = new PassThrough();
      child.killed = false;
      child.kill = signal => { assert.equal(signal, 'SIGKILL'); child.killed = true; };
      children.push(child);
      return child;
    } };
    return name.startsWith('@/') ? {} : require(name);
  }, module, module.exports);
  return module.exports.runPdfRenderer;
}
const firstBundle = loadRenderer(), secondBundle = loadRenderer();
const busy = error => error.code === 'pdf_export_busy';
const finish = child => { child.stdout.emit('data', Buffer.from('%PDF-fixture')); child.emit('close', 0); };
async function expectBusy(renderer, snapshot = {}) {
  const start = children.length;
  const pending = (async () => renderer(snapshot))();
  children.slice(start).forEach(finish);
  await assert.rejects(pending, busy);
}

test('one-run and final PDFs share two slots across module copies; busy snapshots are not serialized', async () => {
  const start = children.length;
  const first = firstBundle({}), second = secondBundle({});
  try {
    await expectBusy(secondBundle, { get findings() { throw new Error('busy request read its snapshot'); } });
    assert.equal(children.length - start, 2);
  } finally { children.slice(start).forEach(finish); await Promise.allSettled([first, second]); }
  assert.equal((await first).toString(), '%PDF-fixture');
  const retry = secondBundle({}); finish(children.at(-1)); await retry;
});

test('serialization, input size and synchronous spawn failures release capacity', async () => {
  const circular = {}; circular.self = circular;
  await assert.rejects(firstBundle(circular), /circular/i);
  await assert.rejects(firstBundle({ value: 'x'.repeat(32 * 1024 * 1024) }), /32 МБ/);
  spawnFailure = true;
  try { await assert.rejects(firstBundle({}), /spawn failed/); }
  finally { spawnFailure = false; }
  const first = firstBundle({}), second = secondBundle({});
  children.slice(-2).forEach(finish); await Promise.all([first, second]);
});

test('spawn error and timeout retain capacity until close, then allow retry', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const first = firstBundle({}), second = secondBundle({});
  const [failed, timedOut] = children.slice(-2);
  const failure = assert.rejects(first, /Средство формирования PDF недоступно/);
  const timeout = assert.rejects(second, /Не удалось безопасно/);
  failed.emit('error', new Error('private child diagnostics'));
  t.mock.timers.tick(120_000);
  assert.equal(timedOut.killed, true);
  try { await expectBusy(firstBundle); }
  finally { failed.emit('close', null); timedOut.emit('close', null); await Promise.allSettled([failure, timeout]); }
  await Promise.all([failure, timeout]);
  const retry = firstBundle({}); finish(children.at(-1)); await retry;
});

test('output overflow kills the renderer without releasing a live slot or accepting a partial PDF', async () => {
  const first = firstBundle({}), second = secondBundle({});
  const [overflow, normal] = children.slice(-2);
  const failure = assert.rejects(first, /Не удалось безопасно/);
  overflow.stdout.emit('data', Buffer.alloc(12 * 1024 * 1024 + 1));
  assert.equal(overflow.killed, true);
  try { await expectBusy(secondBundle); }
  finally { overflow.emit('close', null); finish(normal); await Promise.allSettled([failure, second]); }
  await Promise.all([failure, second]);
  const retry = firstBundle({}); finish(children.at(-1)); await retry;
});
