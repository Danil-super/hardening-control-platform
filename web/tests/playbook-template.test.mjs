import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {test,after} from 'node:test';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';import path from 'node:path';
import {compileServerModules} from './_typescript-loader.mjs';
const compiled=compileServerModules(['playbook-registry']);
const {playbookTemplates}=await import(compiled.url('playbook-registry'));
const directory=mkdtempSync(path.join(tmpdir(),'hcp-template-'));
after(()=>{rmSync(directory,{recursive:true,force:true});rmSync(compiled.directory,{recursive:true,force:true});});
test('package template checks the real package tool on Astra-like facts and distinguishes an absent package',()=>{
 const inventory=path.join(directory,'inventory.ini'),playbook=path.join(directory,'package.yml');
 writeFileSync(inventory,'[linux_hosts]\ntemplate-fixture ansible_connection=local ansible_become=false ansible_python_interpreter=/usr/bin/python3\n');writeFileSync(playbook,playbookTemplates[0].content);
 for(const packageName of ['bash','hcp-package-not-installed-fixture']) {
  const stdout=execFileSync('ansible-playbook',['-i',inventory,playbook,'-e',JSON.stringify({package_name:packageName,ansible_os_family:'Astra Linux'})],{encoding:'utf8',timeout:20000,env:{...process.env,ANSIBLE_LOCAL_TEMP:path.join(directory,'local-temp'),ANSIBLE_NOCOLOR:'1'}});
  assert.match(stdout,/failed=0/);
  assert.match(stdout,packageName==='bash'?/install ok installed/:/Пакет не установлен/);
 }
});
