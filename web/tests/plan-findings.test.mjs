import assert from 'node:assert/strict';
import test, { after } from 'node:test';
import { rmSync } from 'node:fs';
import { compileServerModules } from './_typescript-loader.mjs';
const compiled = compileServerModules(['plan-findings']);
const api = await import(compiled.url('plan-findings'));
after(()=>rmSync(compiled.directory,{recursive:true,force:true}));
const finding=(id,risk,extra={})=>({id,title:id,category:'Пакеты',description:'Описание',recommendation:'Обновить пакет',risk,...extra});
test('plan filters preserve explicit critical and unknown severity and sort by priority',()=>{
  const items=[finding('Unknown','info',{severityUnknown:true}),finding('High','high'),finding('Critical','high',{severityAssessment:{level:'critical'}}),finding('Low','low')];
  assert.deepEqual(api.selectPlanFindings(items,{risk:'all',query:''}).map(f=>f.id),['Critical','High','Low','Unknown']);
  assert.deepEqual(api.selectPlanFindings(items,{risk:'critical',query:''}).map(f=>f.id),['Critical']);
  assert.deepEqual(api.selectPlanFindings(items,{risk:'high',query:''}).map(f=>f.id),['High']);
  assert.deepEqual(api.selectPlanFindings(items,{risk:'unknown',query:''}).map(f=>f.id),['Unknown']);
});
test('search covers recommendation, category and CVE without changing the original order or data',()=>{
  const items=[finding('CVE-2026-1234','high'),finding('Example','medium',{recommendation:'Проверить firewall'})];
  assert.equal(api.selectPlanFindings(items,{risk:'all',query:' FIREWALL '})[0].id,'Example');
  assert.equal(api.selectPlanFindings(items,{risk:'all',query:'ПАКЕТЫ'}).length,2);
  assert.deepEqual(items.map(f=>f.id),['CVE-2026-1234','Example']);
});
