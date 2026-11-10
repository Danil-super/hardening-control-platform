import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import ts from 'typescript';
import { compileServerModules } from './_typescript-loader.mjs';

const previous = { cwd: process.cwd(), path: process.env.PATH,
  state: process.env.HCP_STATE_DIR, reports: process.env.HCP_REPORTS_DIR };
const fixture = mkdtempSync(path.join(tmpdir(), 'hcp-failed-audit-'));
for (const name of ['web', 'ansible', 'bin', 'state', 'reports']) mkdirSync(path.join(fixture, name), { mode: 0o700 });
writeFileSync(path.join(fixture, 'ansible/inventory.ini'), '[linux_hosts]\nfixture-host ansible_host=127.0.0.1 ansible_user=fixture\n');
process.chdir(path.join(fixture, 'web'));
process.env.HCP_STATE_DIR = path.join(fixture, 'state');
process.env.HCP_REPORTS_DIR = path.join(fixture, 'reports');
process.env.PATH = path.join(fixture, 'bin') + path.delimiter + previous.path;
const compiled = compileServerModules(['ansible-control', 'ansible-reports', 'audit-result', 'state-store', 'asset-binding']);
const identity = await import(compiled.url('asset-binding'));
const observation = { machineIdSha256: 'a'.repeat(64),
  sshHostKeyFingerprint: 'SHA256:' + Buffer.alloc(32, 1).toString('base64').replace(/=+$/, ''), observedAt: new Date().toISOString() };
const binding = { version: 1, status: 'verified', alias: 'fixture-host', generation: 1,
  assetId: identity.assetIdForObservation(observation), ...observation,
  verifiedAt: observation.observedAt, connectionId: 'b'.repeat(64) };
writeFileSync(path.join(compiled.directory, 'asset-execution.mjs'), `export async function prepareAssetExecution() {
 return {inventoryPath:${JSON.stringify(path.join(fixture, 'ansible/inventory.ini'))},
 bindings:new Map([['fixture-host',${JSON.stringify(binding)}]]),release(){}};
}`);
writeFileSync(path.join(fixture, 'bin/ansible-playbook'), `#!/usr/bin/env python3
import sys,os,json,pathlib,datetime
values={}
for i,v in enumerate(sys.argv[:-1]):
 if v=='-e':values.update(json.loads(sys.argv[i+1]))
def value(k):
 v=values[k]
 return v.get('__ansible_unsafe') if isinstance(v,dict) else v
run=value('report_run_id')
if os.environ.get('HCP_FAILURE_FIXTURE_WRITE')=='true':
 report={'schemaVersion':1,'action':'astraOvalAudit','runId':run,'inventoryHost':'fixture-host',
  'hostname':'fixture-host','createdAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'mode':'astra-oval','profileId':'astra-oval','summary':{'total':0,'score':None},'findings':[],
  'scanner':{'available':True,'partial':True,'evaluationPerformed':False,'partialReasons':['Fixture scanner stopped by SIGKILL']}}
 (pathlib.Path(value('hcp_reports_dir'))/('fixture-host-astra-oval-'+run+'.json')).write_text(json.dumps(report))
print('TASK [Fetch original scanner evidence] ************************')
print('fatal: [fixture-host]: FAILED! => '+json.dumps({'censored':'Output hidden by no_log'}))
sys.exit(2)
`, { mode: 0o700 });
const control = await import(compiled.url('ansible-control'));
const reports = await import(compiled.url('ansible-reports'));
const auditResult = await import(compiled.url('audit-result'));
const store = await import(compiled.url('state-store'));
const { withAuditProgress } = await import(compiled.url('audit-progress'));
const require = createRequire(import.meta.url);
const stubs = {
  'next/server': { NextResponse: { json: (body, init) => Response.json(body, init) } },
  '@/lib/ansible-control': control, '@/lib/ansible-reports': reports,
  '@/lib/audit-result': auditResult, '@/lib/state-store': store,
  '@/lib/astra-oval-policy': { resolveAstraOvalPolicyForHost: () => ({ config: {} }) },
  '@/lib/astra-oval-preparation': { preparedOvalExtraVars: () => ({}) },
  '@/lib/openscap-policy': {}, '@/lib/remediation': {},
  '@/lib/audit-repeat': { findRepeatAuditNotice: () => null },
  '@/lib/ssh-bootstrap': { credentialTransportAllowed: () => true },
};
const source = ts.transpileModule(readFileSync(new URL('../app/api/ansible/run/route.ts', import.meta.url), 'utf8'),
  { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const module = { exports: {} };
new Function('require', 'module', 'exports', source)(name => stubs[name] ?? require(name), module, module.exports);
function request() {
  return new Request('http://127.0.0.1/api/ansible/run', { method: 'POST', body: JSON.stringify({
    action: 'astraOvalAudit', profileId: 'basic_linux', limit: 'fixture-host',
    confirmAudit: true, sudoPassword: 'fixture-ephemeral-password',
  }) });
}
after(() => {
  process.chdir(previous.cwd); process.env.PATH = previous.path;
  for (const [key, value] of [['HCP_STATE_DIR', previous.state], ['HCP_REPORTS_DIR', previous.reports]]) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  delete process.env.HCP_FAILURE_FIXTURE_WRITE;
  rmSync(fixture, { recursive: true, force: true }); rmSync(compiled.directory, { recursive: true, force: true });
});

test('a failed Ansible child keeps the published partial report linked through HTTP and the stored job', async () => {
  process.env.HCP_FAILURE_FIXTURE_WRITE = 'true';
  const phases = [];
  const response = await withAuditProgress(phase => phases.push(phase), () => module.exports.POST(request()));
  assert.deepEqual(phases, ['Подготовка проверки', 'Выполняется проверка хоста', 'Сохранение и проверка отчёта']);
  const body = await response.json();
  assert.equal(response.status, 500); assert.equal(body.ok, false);
  const saved = readdirSync(process.env.HCP_REPORTS_DIR).find(name => name.endsWith('.json'));
  assert.ok(saved, 'the real publisher must have retained a report before the runner rejected');
  assert.equal(body.reportId, saved.slice(0, -5));
  assert.equal(body.reportRunId, reports.readAnsibleReport(body.reportId).raw.runId);
  assert.equal(body.partial, true);
  assert.match(body.warnings.join(' '), /SIGKILL/);
  const job = store.createAuditJob({ action: 'astraOvalAudit', hostAlias: 'fixture-host', profileId: 'basic_linux', requestKey: 'fixture-key' }).job;
  store.finishAuditJob(job.id, body);
  const result = store.listAuditJobs().find(item => item.id === job.id);
  assert.equal(result.status, 'failed'); assert.equal(result.result.reportId, body.reportId);
  assert.equal(result.result.stdout, undefined);
  assert.ok(!JSON.stringify(result).includes('fixture-ephemeral-password'));
});

test('a failed run without a published file never links the previous run report', async () => {
  process.env.HCP_FAILURE_FIXTURE_WRITE = 'false';
  const response = await module.exports.POST(request());
  const body = await response.json();
  assert.equal(response.status, 500); assert.equal(body.ok, false);
  assert.equal(body.reportId, null);
  assert.equal(body.partial, false);
  assert.equal(readdirSync(process.env.HCP_REPORTS_DIR).filter(name => name.endsWith('.json')).length, 1);
});
