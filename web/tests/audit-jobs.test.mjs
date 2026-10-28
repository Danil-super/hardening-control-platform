import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
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
const workerPath = path.join(compiled.directory, 'audit-worker.mjs');
writeFileSync(workerPath, `
  import * as store from './state-store.mjs';
  const { job } = store.createAuditJob(${JSON.stringify(input)});
  store.setAuditJobPhase(job.id, 'Worker is still scanning');
  process.send({ job });
  process.on('message', (message) => {
    if (message === 'complete') {
      store.finishAuditJob(job.id, { ok: true, message: 'Worker completed' });
      process.send({ completed: true });
    }
  });
`);
async function startWorker(t) {
  const worker = fork(workerPath, [], { env: { ...process.env }, silent: true });
  t.after(async () => {
    if (worker.exitCode !== null || worker.signalCode !== null) return;
    const stopped = once(worker, 'exit');
    worker.kill('SIGTERM');
    await stopped;
  });
  const [message] = await once(worker, 'message', { signal: AbortSignal.timeout(10_000) });
  return { worker, job: message.job };
}
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
test('another live local worker keeps its host lock and can still complete', async (t) => {
  const { worker, job } = await startWorker(t);
  process.kill(worker.pid, 0);
  assert.equal(store.listAuditJobs().find((item) => item.id === job.id).status, 'running');
  const overlapping = store.createAuditJob({ ...input, requestKey: 'different-request' });
  assert.equal(overlapping.created, false);
  assert.equal(overlapping.job.id, job.id);
  const completed = once(worker, 'message', { signal: AbortSignal.timeout(10_000) });
  worker.send('complete');
  await completed;
  assert.equal(store.listAuditJobs().find((item) => item.id === job.id).status, 'completed');
  assert.equal(store.createAuditJob(input).created, true);
});
test('a stopped worker is marked interrupted without relaunching its scan', async (t) => {
  const { worker, job } = await startWorker(t);
  const exited = once(worker, 'exit');
  worker.kill('SIGTERM');
  await exited;
  store.recoverAuditJobs();
  const saved = store.listAuditJobs()[0];
  assert.equal(saved.id, job.id);
  assert.equal(saved.status, 'interrupted');
  assert.equal(saved.result.ok, false);
  assert.match(saved.result.message, /перезапуск/);
  assert.equal(store.listAuditJobs().length, 1);
  assert.equal(store.createAuditJob(input).created, true);
});
test('single-controller upgrades still interrupt an unknown legacy container owner', () => {
  const { job } = store.createAuditJob(input);
  const database = new DatabaseSync(path.join(process.env.HCP_STATE_DIR, 'hcp.sqlite'));
  try {
    database.prepare('UPDATE audit_jobs SET owner = ? WHERE id = ?').run('previous-container:123:legacy-start', job.id);
  } finally { database.close(); }
  assert.equal(store.listAuditJobs()[0].status, 'interrupted');
  assert.equal(store.createAuditJob(input).created, true);
});
