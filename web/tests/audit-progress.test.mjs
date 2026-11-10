import assert from 'node:assert/strict';
import test, { after } from 'node:test';
import { rmSync } from 'node:fs';
import { compileServerModules } from './_typescript-loader.mjs';
const compiled = compileServerModules(['audit-progress']);
const { withAuditProgress, reportAuditProgress } = await import(compiled.url('audit-progress'));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));
test('simultaneous jobs receive only their own confirmed phases; no global leftover callback', async () => {
  const first = [], second = [];
  let release;
  const paused = new Promise(resolve => { release = resolve; });
  await Promise.all([
    withAuditProgress(phase => first.push(phase), async () => { reportAuditProgress('prepare'); await paused; reportAuditProgress('report'); }),
    withAuditProgress(phase => second.push(phase), async () => { reportAuditProgress('scan'); release(); }),
  ]);
  reportAuditProgress('scan');
  assert.deepEqual(first, ['Подготовка проверки', 'Сохранение и проверка отчёта']);
  assert.deepEqual(second, ['Выполняется проверка хоста']);
});
test('an unavailable progress store cannot interrupt the scanner or evidence cleanup', async () => {
  const warning = console.warn;
  const warnings = [];
  console.warn = message => warnings.push(message);
  try {
    await withAuditProgress(() => { throw new Error('private storage diagnostic'); }, async () => reportAuditProgress('report'));
    assert.deepEqual(warnings, ['audit_progress_update_failed']);
  } finally { console.warn = warning; }
});
