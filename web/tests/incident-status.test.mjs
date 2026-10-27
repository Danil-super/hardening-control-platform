import test from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { compileServerModules } from './_typescript-loader.mjs';
const compiled = compileServerModules(['incident-status']);
const { incidentDisplayStatus } = await import(compiled.url('incident-status'));
try {
 test('legacy completed partial audits are distinct from errors without altering history', () => {
  assert.equal(incidentDisplayStatus({ kind:'audit', status:'failed', message:'Проверка выполнена. Проверка неполная: ограничения в отчёте.' }), 'partial');
  assert.equal(incidentDisplayStatus({ kind:'audit', status:'failed', message:'Command failed: ansible-playbook' }), 'failed');
  assert.equal(incidentDisplayStatus({ kind:'response', status:'failed', message:'Проверка выполнена. Проверка неполная: текст' }), 'failed');
  assert.equal(incidentDisplayStatus({ kind:'audit', status:'partial', message:'Ограничение' }), 'partial');
 });
} finally { rmSync(compiled.directory, { recursive:true, force:true }); }
