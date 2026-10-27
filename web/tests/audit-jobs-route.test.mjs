import test, { after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import ts from 'typescript';
import { compileServerModules } from './_typescript-loader.mjs';
const compiled = compileServerModules(['state-store', 'astra-oval-config']);
const store = await import(compiled.url('state-store'));
const tasks = [], calls = [], directories = [];
let release, audit, cve;
const source = ts.transpileModule(readFileSync(new URL('../app/api/ansible/jobs/route.ts', import.meta.url), 'utf8'), { compilerOptions:{ target:ts.ScriptTarget.ES2022, module:ts.ModuleKind.CommonJS } }).outputText;
const require = createRequire(import.meta.url);
const module = { exports:{} };
const stubs = {
 'next/server': { after: task => tasks.push(task), NextResponse: { json: (body, init) => Response.json(body, init) } },
 '@/lib/state-store': store,
 '@/lib/ansible-control': { isPlaybookAction: action => ['collectFacts','packageInventory','closePort'].includes(action), playbooks: {collectFacts:{kind:'audit'}, packageInventory:{kind:'audit'},closePort:{kind:'response'}}, normalizeProfileId: ()=>'basic_linux', inventoryHostExists: alias => alias==='host-one' },
 '@/lib/ssh-bootstrap': { credentialTransportAllowed: () => true },
 '@/app/api/ansible/run/route': { POST: async request => {calls.push(await request.json()); await audit; return Response.json({ok:true,reportId:'inventory-one'});} },
 '@/app/api/ansible/vulnerabilities/check/route': { POST: async () => {calls.push('cve'); return Response.json(cve);} },
 '@/app/api/ansible/dependency-track/sync/route': { POST: async () => {calls.push('dependency-track'); return Response.json({ok:true,configured:false});} },
};
new Function('require','module','exports',source)(name => stubs[name] ?? require(name),module,module.exports);
const route = module.exports;
beforeEach(() => { process.env.HCP_STATE_DIR = mkdtempSync(path.join(tmpdir(),'hcp-job-route-')); directories.push(process.env.HCP_STATE_DIR); tasks.length=0; calls.length=0; audit=new Promise(resolve=>{release=resolve}); cve={ok:true,partial:true,message:'Astra: требуется OVAL',reportId:'cve-one'}; });
after(() => { delete process.env.HCP_STATE_DIR; for(const directory of [...directories,compiled.directory]) rmSync(directory,{recursive:true,force:true}); });
function request(action='packageInventory', signal) {return new Request('http://127.0.0.1/api/ansible/jobs',{method:'POST',body:JSON.stringify({action,limit:'host-one',sudoPassword:'ephemeral-test-password'}),signal});}
test('response returns before the test completes and disconnection does not stop the server CVE chain', async () => {
 const controller = new AbortController();
 const response = await route.POST(request('packageInventory',controller.signal));
 assert.equal(response.status,202); assert.equal(calls.length,0);
 controller.abort();
 const running = tasks.shift()();
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(store.listAuditJobs()[0].status,'running');
 assert.equal(calls[0].sudoPassword,'ephemeral-test-password');
 const duplicate=await route.POST(request()); assert.equal(duplicate.status,202); assert.equal(tasks.length,0);
 release(); await running;
 const job=store.listAuditJobs()[0]; assert.equal(job.status,'partial'); assert.equal(job.result.reportId,'cve-one');
 assert.deepEqual(calls.slice(1),['cve']);
 assert.equal(JSON.stringify(job).includes('ephemeral-test-password'),false);
});
test('changes are never queued via the audit endpoint',async()=>{
 const response=await route.POST(request('closePort'));
 assert.equal(response.status,400); assert.equal(tasks.length,0); assert.equal(store.listAuditJobs().length,0);
});
test('scanner errors release the lock and remain visible as failures',async()=>{
 cve={ok:false,message:'Trivy registry unavailable'};
 await route.POST(request()); release(); await tasks.shift()();
 assert.equal(store.listAuditJobs()[0].status,'failed');
 assert.equal(store.listAuditJobs()[0].result.message,cve.message);
 assert.equal((await route.POST(request())).status,202);
});
