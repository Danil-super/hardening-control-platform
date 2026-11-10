import assert from 'node:assert/strict';
import test, { after } from 'node:test';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { compileServerModules } from './_typescript-loader.mjs';
const compiled = compileServerModules(['audit-report-pdf']);
const { auditPdfSnapshot, renderAuditReportPdf } = await import(compiled.url('audit-report-pdf'));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));
test('one-run PDF uses this report only, preserves all findings and never carries credentials or child output', () => {
  const findings = Array.from({length: 4000}, (_, i) => ({id:`rule-${i}`,title:`CVE-2026-${10000+i}`,risk:'info',severityUnknown:true,status:'failed',description:'Описание источника',recommendation:'Проверить бюллетень',source:'openscap',evidence:'private child output',remediationAvailable:false}));
  const report = { id:'one-run',mode:'astra-oval',host:'server',hostname:'server',createdAt:'2026-11-10T12:00:00Z',partial:false,available:true,reportTimeValid:true,findings,events:[],raw:{sudoPassword:'must-not-export',stdout:'must-not-export',scanner:{partialReasons:[]}} };
  const snapshot = auditPdfSnapshot(report, 'a'.repeat(64));
  assert.equal(snapshot.kind,'audit'); assert.equal(snapshot.id,'one-run'); assert.equal(snapshot.findings.length,4000);
  assert.equal(snapshot.findings.at(-1).id,'rule-3999'); assert.equal(snapshot.findings[0].severityUnknown,true);
  assert.deepEqual(auditPdfSnapshot({...report, assetBinding: {version:1,status:'unknown',alias:'server',reason:'unauthenticated_network_scan'}}, 'c'.repeat(64)).assetBinding, {version:1,status:'unknown',reason:'unauthenticated_network_scan'});
  assert.equal(snapshot.sourceSha256,'a'.repeat(64)); assert.equal(snapshot.partial,false);
  assert.equal(JSON.stringify(snapshot).includes('must-not-export'),false);
  assert.equal(JSON.stringify(snapshot).includes('private child output'),false);
  assert.equal(snapshot.findings[0].status,'failed');
  const identity = auditPdfSnapshot({...report, assetBinding: {version:1,status:'verified',assetId:'asset-'+ 'a'.repeat(64),generation:2,sshHostKeyFingerprint:'not-needed'},contentId:'sha256:'+ 'b'.repeat(64)}, 'c'.repeat(64));
  assert.equal(identity.assetBinding.generation,2);assert.equal(identity.assetBinding.sshHostKeyFingerprint,undefined);assert.equal(identity.contentId,'sha256:'+ 'b'.repeat(64));
});
test('unavailable, incomplete and historical invalid-time results keep their limitations in the PDF', () => {
  const report = {id:'partial-run',mode:'openscap',host:'server',partial:true,available:false,reportTimeValid:false,findings:[],events:[],raw:{scanner:{partialReasons:['Оценка прервана']}}};
  const snapshot = auditPdfSnapshot(report, 'b'.repeat(64));
  assert.equal(snapshot.partial,true);assert.equal(snapshot.available,false);assert.equal(snapshot.reportTimeValid,false);
  assert.deepEqual(snapshot.limitations,['Оценка прервана']);
});
test('the real one-run PDF includes all 4000 controls and the exact JSON checksum without creating a project export', async () => {
  const original = { cwd:process.cwd(), state:process.env.HCP_STATE_DIR, reports:process.env.HCP_REPORTS_DIR };
  const directory=mkdtempSync(path.join(tmpdir(),'hcp-one-pdf-'));
  process.chdir(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'));
  process.env.HCP_STATE_DIR=directory;process.env.HCP_REPORTS_DIR=directory;
  try {
    const id='single-audit';
    const raw={inventoryHost:'server',createdAt:new Date().toISOString(),mode:'agentless',profileId:'basic_linux',scanner:{available:true,partial:false},findings:Array.from({length:4000},(_,i)=>({id:`rule-${i}`,profileId:'basic_linux',title:`CVE-2099-${10000+i}`,category:'test',risk:'info',severityUnknown:true,status:'failed',source:'agentless',description:i?'Текст источника':'<img src="http://127.0.0.1/forbidden"> '+ 'long description '.repeat(500)+'END_DESCRIPTION',recommendation:'Проверить',remediationAvailable:false})),events:[]};
    const bytes=Buffer.from(JSON.stringify(raw));const file=path.join(directory,id+'.json');writeFileSync(file,bytes,{mode:0o600});
    const result=await renderAuditReportPdf(id);
    assert.equal(result.sourceSha256,createHash('sha256').update(bytes).digest('hex'));
    assert.equal(result.pdf.subarray(0,5).toString(),'%PDF-');assert.deepEqual(readFileSync(file),bytes);
    const stats=JSON.parse(execFileSync('python3',['-c',`import re,zlib,sys,json
pdf=sys.stdin.buffer.read(); parts=[]
for raw in re.findall(rb'stream\\r?\\n(.*?)endstream',pdf,re.S):
 try: parts.append(zlib.decompress(__import__('base64').a85decode(raw.strip(),adobe=True)))
 except (ValueError,zlib.error): pass
text=b'\\n'.join(parts)
print(json.dumps({'cves':len(re.findall(rb'CVE-2099-\\d{5}',text)),'last':b'CVE-2099-13999' in text,'longText':b'END_DESCRIPTION' in text}))`],{input:result.pdf,encoding:'utf8'}));
    assert.deepEqual(stats,{cves:4000,last:true,longText:true});
    const store=await import(compiled.url('state-store'));assert.equal(store.listProjectReportRecords().length,0);
    assert.equal(await renderAuditReportPdf('missing-report'),null);
  } finally {
    process.chdir(original.cwd);
    for(const [key,value] of [['HCP_STATE_DIR',original.state],['HCP_REPORTS_DIR',original.reports]]){if(value===undefined)delete process.env[key];else process.env[key]=value;}
    rmSync(directory,{recursive:true,force:true});
  }
});
