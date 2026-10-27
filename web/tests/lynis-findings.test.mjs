import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import test, { after } from 'node:test';
import { compileServerModules } from './_typescript-loader.mjs';
const compiled = compileServerModules(['ansible-reports','project-report']);
const api = await import(compiled.url('ansible-reports'));
const projects = await import(compiled.url('project-report'));
const root = mkdtempSync(path.join(tmpdir(),'hcp-lynis-view-'));
process.env.HCP_REPORTS_DIR = root;
process.env.HCP_STATE_DIR = path.join(root,'state');
after(()=>{delete process.env.HCP_REPORTS_DIR;delete process.env.HCP_STATE_DIR;rmSync(root,{recursive:true,force:true});rmSync(compiled.directory,{recursive:true,force:true});});
const legacy=(rule,kind,evidence)=>({id:`lynis_${kind}_${rule}`,profileId:'lynis',title:`Lynis ${kind}: ${rule}`,category:'Внешняя проверка',risk:kind==='warning'?'medium':'low',status:kind==='warning'?'failed':'manual',source:'lynis',description:'Старый общий шаблон',recommendation:'Старый общий шаблон',evidence,remediationAvailable:false});
function save(findings){const text=JSON.stringify({mode:'lynis',profileId:'lynis',inventoryHost:'host-one',createdAt:new Date().toISOString(),scanner:{version:'3.0.8',hardeningIndex:70,available:true,partial:false},findings,events:[]});writeFileSync(path.join(root,'host-one-lynis.json'),text);return text;}

test('legacy Lynis results explain observed data in Russian without rewriting evidence or inventing severity',()=>{
  const original=save([legacy('GEN-0010','warning','This version 10.0 is marked end-of-life as of 2022-01-01|-|-|'),legacy('NAME-4210','warning','Found BIND version in banner|-|-|')]);
  const result=api.readAnsibleReport('host-one-lynis');
  assert.match(result.findings[0].description,/10\.0/);assert.match(result.findings[0].description,/2022-01-01/);
  assert.match(result.findings[0].recommendation,/Astra/);
  assert.match(result.findings[1].title,/BIND/);assert.match(result.findings[1].recommendation,/version/);
  assert.equal(result.findings[1].description,'Lynis обнаружил версию BIND в ответе на локальный DNS-запрос.');
  assert.ok(result.findings.every(f=>f.severityUnknown&&f.status==='manual'));
  assert.equal(result.medium,0);assert.equal(result.score,70);
  assert.equal(result.lynisWarnings,2);assert.equal(readFileSync(path.join(root,'host-one-lynis.json'),'utf8'),original);
});
test('a BIND suggestion describes the actual advice separately from its warning',()=>{
  save([legacy('NAME-4210','suggestion',"The version in BIND can be masked by defining 'version none' in the configuration file|-|-|")]);
  const result=api.readAnsibleReport('host-one-lynis').findings[0];
  assert.equal(result.title,'Проверить скрытие версии BIND');
  assert.match(result.description,/рекомендует скрыть версию BIND/);
  assert.equal(result.lynis.kind,'suggestion');
});
test('different findings under a repeated rule keep stable identities and actual SSH values',()=>{
  save([legacy('SSH-7408','suggestion','Consider hardening SSH configuration|AllowTcpForwarding (set YES to NO)|-|'),legacy('SSH-7408','suggestion','Consider hardening SSH configuration|Port (set 22 to )|-|')]);
  const results=api.readAnsibleReport('host-one-lynis').findings;
  assert.equal(new Set(results.map(f=>f.id)).size,2);
  assert.match(results[0].title,/AllowTcpForwarding/);assert.match(results[0].description,/YES/);
  assert.match(results[1].recommendation,/отсутствует/);assert.doesNotMatch(results[1].recommendation,/2222/);
  assert.deepEqual(api.readAnsibleReport('host-one-lynis').findings.map(f=>f.id),results.map(f=>f.id));
});
test('unknown rules retain their exact source message and remain translatable',()=>{
  save([legacy('TEST-9999','warning','Unexpected scanner observation|Context value|text:Review the setting|')]);
  const finding=api.readAnsibleReport('host-one-lynis').findings[0];
  assert.equal(finding.description,'Unexpected scanner observation');
  assert.equal(finding.lynis.kind,'warning');assert.equal(finding.lynis.details,'Context value');
  assert.equal(finding.lynis.solution,'text:Review the setting');
  assert.equal(finding.severityUnknown,true);
});
test('a new PDF snapshot retains Russian Lynis observations, unknown severity and distinct SSH advice',async()=>{
  const original=save([legacy('NAME-4210','warning','Found BIND version in banner|-|-|'),legacy('SSH-7408','suggestion','Consider hardening SSH configuration|AllowTcpForwarding (set YES to NO)|-|'),legacy('SSH-7408','suggestion','Consider hardening SSH configuration|Port (set 22 to )|-|')]);
  const record=await projects.createProjectReport({hostAlias:'host-one',subject:{clientName:'Тест',projectName:'Lynis',period:'Тест',specialist:'HCP'}});
  const snapshot=JSON.parse(readFileSync(path.join(root,'state','project-reports',record.fileName.replace(/\.pdf$/,'.json')),'utf8'));
  assert.equal(snapshot.unplannedFindings.length,3);
  assert.equal(new Set(snapshot.unplannedFindings.map(f=>f.id)).size,3);
  assert.ok(snapshot.unplannedFindings.every(f=>f.severityUnknown&&f.status==='manual'));
  assert.match(snapshot.unplannedFindings.find(f=>f.title.includes('BIND')).description,/локальный DNS-запрос/);
  assert.match(snapshot.unplannedFindings.find(f=>f.title.includes('Port')).recommendation,/отсутствует/);
  assert.equal(projects.readProjectReportPdf(record.id).pdf.subarray(0,5).toString(),'%PDF-');
  assert.equal(readFileSync(path.join(root,'host-one-lynis.json'),'utf8'),original);
});
