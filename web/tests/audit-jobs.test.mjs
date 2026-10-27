import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test, { after, beforeEach } from 'node:test';
import { compileServerModules } from './_typescript-loader.mjs';
const compiled = compileServerModules(['state-store', 'astra-oval-config']);
const store = await import(compiled.url('state-store'));
const directories = [];
beforeEach(() => { process.env.HCP_STATE_DIR = mkdtempSync(path.join(tmpdir(), 'hcp-jobs-')); directories.push(process.env.HCP_STATE_DIR); });
after(() => { delete process.env.HCP_STATE_DIR; for (const directory of [...directories, compiled.directory]) rmSync(directory, { recursive: true, force: true }); });
const input = { action: 'astraOvalAudit', hostAlias: 'host-one', profileId: 'basic_linux', requestKey: 'same-request' };
test('navigation retries attach to the same active job and another audit cannot overlap', () => {
  const first = store.createAuditJob(input);
  assert.equal(first.created, true);
  assert.equal(store.createAuditJob(input).job.id, first.job.id);
  assert.equal(store.createAuditJob({ ...input, action: 'collectFacts', requestKey: 'other' }).created, false);
  assert.equal(store.listAuditJobs()[0].status, 'queued');
});
test('completion retains a partial result, releases host lock and excludes credentials/output', () => {
  const { job } = store.createAuditJob({ ...input, sudoPassword: 'never-store-this' });
  store.finishAuditJob(job.id, { ok: true, partial: true, reportId: 'report-one', message: 'Ограничение XML', sudoPassword: 'never-store-this', stdout: 'sensitive-output' });
  const saved = store.listAuditJobs()[0];
  assert.equal(saved.status, 'partial');
  assert.equal(saved.result.reportId, 'report-one');
  assert.equal(saved.result.stdout, undefined);
  assert.equal(store.createAuditJob(input).created, true);
  assert.equal(readFileSync(path.join(process.env.HCP_STATE_DIR, 'hcp.sqlite-wal')).includes(Buffer.from('never-store-this')), false);
});
test('a server restart marks unfinished work interrupted without relaunching it', () => {
  const { job } = store.createAuditJob(input);
  store.recoverAuditJobs('different-server-process');
  const saved = store.listAuditJobs()[0];
  assert.equal(saved.id, job.id);
  assert.equal(saved.status, 'interrupted');
  assert.equal(saved.result.ok, false);
  assert.match(saved.result.message, /перезапуск/);
});
