import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const source=ts.transpileModule(readFileSync(new URL('../app/api/ansible/reports/[reportId]/pdf/route.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
let authenticated=false, render=async()=>null, calls=0;
const module={exports:{}};
const stubs={
  'next/headers':{cookies:async()=>({get:()=>({value:authenticated?'valid':''})})},
  '@/lib/auth':{authCookieName:'session',isAuthConfigured:()=>true,isValidSessionToken:token=>token==='valid'},
  '@/lib/audit-report-pdf':{renderAuditReportPdf:async id=>{calls++;return render(id);}},
};
new Function('require','module','exports',source)(name=>stubs[name],module,module.exports);
const request=new Request('https://hcp.example/api/ansible/reports/run/pdf');
const context=id=>({params:Promise.resolve({reportId:id})});
test('authentication precedes PDF generation; errors are explicit and never disclose renderer output',async()=>{
  assert.equal((await module.exports.GET(request,context('run'))).status,401);assert.equal(calls,0);
  authenticated=true;
  assert.equal((await module.exports.GET(request,context('../private'))).status,400);assert.equal(calls,0);
  assert.equal((await module.exports.GET(request,context('missing'))).status,404);
  render=async()=>{throw new Error('private password or command');};
  const failure=await module.exports.GET(request,context('run'));assert.equal(failure.status,503);assert.equal((await failure.text()).includes('private password'),false);
});
test('two bounded PDF exports can run; the next gets 429 and completed exports release capacity',async()=>{
  const releases=[];render=id=>new Promise(resolve=>releases.push(()=>resolve({id,pdf:Buffer.from('%PDF-fixture'),sourceSha256:'a'.repeat(64)})));
  const first=module.exports.GET(request,context('first')),second=module.exports.GET(request,context('second'));
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal((await module.exports.GET(request,context('third'))).status,429);
  for(const release of releases)release();
  for(const response of await Promise.all([first,second])){assert.equal(response.status,200);assert.equal(response.headers.get('content-type'),'application/pdf');assert.match(response.headers.get('content-disposition'),/^attachment;/);assert.equal(response.headers.get('x-source-sha256'),'a'.repeat(64));}
  render=async()=>null;assert.equal((await module.exports.GET(request,context('missing'))).status,404);
});
