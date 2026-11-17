import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test,{after} from 'node:test';
import {compileServerModules} from './_typescript-loader.mjs';
const compiled=compileServerModules(['ansible-reports','audit-report-pdf']);
const {readAnsibleReport}=await import(compiled.url('ansible-reports'));
const {auditPdfSnapshot}=await import(compiled.url('audit-report-pdf'));
const directory=mkdtempSync(path.join(tmpdir(),'hcp-xccdf-severity-'));
after(()=>{rmSync(compiled.directory,{recursive:true,force:true});rmSync(directory,{recursive:true,force:true});delete process.env.HCP_REPORTS_DIR;});
function finding(severity,status='passed') {
 return {id:'openscap_rule-'+severity,profileId:'openscap',title:'Rule '+severity,category:'system',risk:'info',status,source:'openscap',description:'Checked',recommendation:'Review',remediationAvailable:false,evidence:`rule=rule-${severity}; result=${status==='passed'?'pass':status==='failed'?'fail':'error'}; severity=${severity}; instance=`};
}
function save(id,findings,mode='openscap') {
 process.env.HCP_REPORTS_DIR=directory;
 const file=path.join(directory,id+'.json');
 const original=JSON.stringify({mode,profileId:mode,inventoryHost:'lab',createdAt:new Date().toISOString(),findings});writeFileSync(file,original);
 return {report:readAnsibleReport(id),file,original};
}
test('historical passed XCCDF rules retain scanner severity in the view and PDF, with zero violations',()=>{
 const {report,file,original}=save('lab-openscap-run-passed',['high','medium','low','info','unknown'].map(x=>finding(x)));
 assert.deepEqual(report.findings.map(x=>x.risk),['high','medium','low','info','info']);
 assert.equal(report.findings[4].severityUnknown,true);
 assert.equal(report.high,0);assert.equal(report.medium,0);assert.equal(report.low,0);assert.equal(report.unknown,0);
 assert.deepEqual(auditPdfSnapshot(report,'a'.repeat(64)).findings.map(x=>x.risk),['high','medium','low','info','info']);
 assert.equal(readFileSync(file,'utf8'),original);assert.equal(report.raw.findings[0].risk,'info');
});
test('failed/manual results keep their states; Critical and Unknown are not invented or downgraded',()=>{
 const {report}=save('lab-openscap-run-states',[finding('critical','failed'),finding('high','manual'),finding('unknown','failed')]);
 assert.equal(report.findings[0].severityAssessment.level,'critical');assert.equal(report.critical,1);assert.equal(report.high,1);
 assert.equal(report.findings[1].risk,'high');assert.equal(report.findings[1].status,'manual');assert.equal(report.unknown,1);
});
test('only adapter severity before observations is used, never arbitrary description or other scanner evidence',()=>{
 const custom={...finding('unknown'),evidence:'rule=x; result=pass; severity=unknown; instance=; observation=severity=high;',description:'severity=critical'};
 const {report}=save('lab-openscap-run-observation',[custom]);assert.equal(report.findings[0].severityUnknown,true);
 const unrelated=save('lab-agentless-run-other',[{...finding('high'),source:'agentless'}],'agentless').report;
 assert.equal(unrelated.findings[0].risk,'info');
});
