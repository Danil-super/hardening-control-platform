import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';
import { compileServerModules } from './_typescript-loader.mjs';

const compiled = compileServerModules(['state-store', 'astra-oval-config', 'ansible-reports', 'archive']);
const root = mkdtempSync(path.join(tmpdir(), 'hcp-archive-'));
process.env.HCP_STATE_DIR = path.join(root, 'state');
process.env.HCP_REPORTS_DIR = path.join(root, 'reports');
mkdirSync(process.env.HCP_REPORTS_DIR);
const store = await import(compiled.url('state-store'));
const reports = await import(compiled.url('ansible-reports'));
const archive = await import(compiled.url('archive'));
after(() => { delete process.env.HCP_STATE_DIR; delete process.env.HCP_REPORTS_DIR; rmSync(root,{recursive:true,force:true});rmSync(compiled.directory,{recursive:true,force:true}); });

test('archiving reports clears active results without changing source evidence, and restoration persists', () => {
  const filename = path.join(process.env.HCP_REPORTS_DIR, 'host-one-facts-old.json');
  const content = JSON.stringify({inventoryHost:'host-one',mode:'facts',profileId:'facts',createdAt:new Date().toISOString(),findings:[],events:[]});
  writeFileSync(filename, content);
  assert.equal(reports.listAnsibleReports().length, 1);
  store.setRecordArchive([{kind:'report',id:'host-one-facts-old'}], 'archive');
  assert.equal(reports.listAnsibleReports().length, 0);
  assert.equal(reports.listAnsibleReports('archive')[0].id, 'host-one-facts-old');
  assert.ok(reports.readAnsibleReport('host-one-facts-old'));
  assert.equal(readFileSync(filename,'utf8'),content);
  writeFileSync(path.join(process.env.HCP_REPORTS_DIR,'host-one-facts-new.json'),content);
  assert.deepEqual(reports.listAnsibleReports().map(r=>r.id), ['host-one-facts-new']);
  store.setRecordArchive([{kind:'report',id:'host-one-facts-old'}], 'restore');
  assert.equal(reports.listAnsibleReports().length,2);
  assert.equal(reports.listAnsibleReports('archive').length,0);
  assert.equal(store.verifyAuditChain().valid,true);
});

test('clearing the visible journal retains its signed chain and exposes subsequent executions', () => {
  const original = store.appendIncident({action:'ping',kind:'audit',status:'success',profileId:'facts',limit:'host-one',message:'fixture'});
  store.setRecordArchive([{kind:'incident',id:original.id}], 'archive');
  assert.equal(store.readIncidents().length,0);
  assert.equal(store.readIncidents(300,'archive')[0].id,original.id);
  assert.equal(store.verifyAuditChain().valid,true);
  const next = store.appendIncident({action:'ping',kind:'audit',status:'success',profileId:'facts',limit:'host-one',message:'next fixture'});
  assert.deepEqual(store.readIncidents().map(r=>r.id),[next.id]);
  store.setRecordArchive([{kind:'incident',id:original.id}], 'restore');
  assert.equal(store.readIncidents().length,2);
  assert.equal(store.verifyAuditChain().valid,true);
});

test('PDF records remain addressable and retain their report protection while archived', () => {
  const id='project_report_53f754a3-6c4c-4cf9-8791-17aa3e856e4e';
  store.createProjectReportRecord({id,hostAlias:'host-one',fileName:'project-report-53f754a3-6c4c-4cf9-8791-17aa3e856e4e.pdf',createdAt:new Date().toISOString(),pdfSha256:'a'.repeat(64),snapshotSha256:'b'.repeat(64),sourceManifestSha256:'c'.repeat(64),subject:{clientName:'Test customer',projectName:'Test project',period:'October',specialist:'Tester'}});
  store.setRecordArchive([{kind:'pdf',id}], 'archive');
  assert.equal(store.listProjectReportRecords('host-one').length,0);
  assert.equal(store.listProjectReportRecords('host-one','archive')[0].id,id);
  assert.equal(store.listProjectReportRecords('host-one','all')[0].id,id);
  assert.equal(store.getProjectReportRecord(id).pdfSha256,'a'.repeat(64));
});

test('a changed preview cannot silently archive results that were not shown to the user', () => {
  const preview = archive.archivePreview('reports','archive');
  writeFileSync(path.join(process.env.HCP_REPORTS_DIR,'host-two-facts-new.json'),JSON.stringify({inventoryHost:'host-two',mode:'facts',profileId:'facts',createdAt:new Date().toISOString(),findings:[],events:[]}));
  assert.throws(()=>archive.applyArchive('reports','archive',preview.token),{code:'archive_preview_changed'});
  assert.ok(reports.listAnsibleReports().some(r=>r.id==='host-two-facts-new'));
});

test('bulk clear and restore do not mutate raw results; active work prevents clearing', () => {
  const {job}=store.createAuditJob({action:'collectFacts',hostAlias:'host-two',profileId:'facts',requestKey:'fixture'});
  const preview=archive.archivePreview('reports','archive');
  assert.throws(()=>archive.applyArchive('reports','archive',preview.token),{code:'operation_in_progress'});
  store.finishAuditJob(job.id,{ok:true,message:'fixture'});
  const ids=reports.listAnsibleReports().map(r=>r.id);
  const hashes=ids.map(id=>reports.hashAnsibleReport(id));
  assert.ok(archive.applyArchive('reports','archive',preview.token)>0);
  assert.equal(reports.listAnsibleReports().length,0);
  assert.deepEqual(ids.map(id=>reports.hashAnsibleReport(id)),hashes);
  const restore=archive.archivePreview('reports','restore');
  archive.applyArchive('reports','restore',restore.token);
  assert.deepEqual(new Set(reports.listAnsibleReports().map(r=>r.id)),new Set(ids));
  assert.equal(store.verifyAuditChain().valid,true);
});
