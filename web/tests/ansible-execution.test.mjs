import assert from 'node:assert/strict';
import {test,after} from 'node:test';
import {existsSync,mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {compileServerModules} from './_typescript-loader.mjs';
const compiled=compileServerModules(['ansible-control']);
const control=await import(compiled.url('ansible-control'));
const directory=mkdtempSync(path.join(tmpdir(),'hcp-execution-test-'));
const previousPath=process.env.PATH;
writeFileSync(path.join(directory,'ansible-playbook'),`#!/usr/bin/env python3
import sys,json,os,stat
args=sys.argv[1:]
file=args[args.index('--extra-vars')+1][1:]
secret=json.load(open(file))['ansible_become_password']
print(json.dumps({'file':file,'fileMode':stat.S_IMODE(os.stat(file).st_mode),'directoryMode':stat.S_IMODE(os.stat(os.path.dirname(file)).st_mode),'secret':secret}))
if os.environ.get('HCP_EXECUTION_TEST_FAIL')=='true':
 print(secret,file=sys.stderr)
 sys.exit(2)
`,{mode:0o700});
after(()=>{process.env.PATH=previousPath;delete process.env.HCP_EXECUTION_TEST_FAIL;rmSync(directory,{recursive:true,force:true});rmSync(compiled.directory,{recursive:true,force:true});});
test('shared execution keeps one-time sudo private, redacts output and removes it after success or failure',async()=>{
 process.env.PATH=directory+path.delimiter+previousPath;
 const secret='fixture-SUDO-only';
 const request={args:['-i','fixture-inventory','fixture.yml'],timeout:5000,becomePassword:secret};
 for(const fail of [false,true]) {
  process.env.HCP_EXECUTION_TEST_FAIL=String(fail);
  let output;
  if(fail) await assert.rejects(control.executeAnsiblePlaybook(request),error=>{output=JSON.parse(error.stdout);assert.ok(!error.stderr.includes(secret));assert.ok(!error.message.includes(secret));return true;});
  else {const result=await control.executeAnsiblePlaybook(request);output=JSON.parse(result.stdout);assert.ok(!result.command.includes(secret));assert.ok(!result.command.includes(output.file));}
  assert.equal(output.fileMode,0o600);assert.equal(output.directoryMode,0o700);assert.equal(output.secret,'[скрыто]');assert.equal(existsSync(output.file),false);assert.equal(existsSync(path.dirname(output.file)),false);
 }
 await assert.rejects(control.executeAnsiblePlaybook({...request,becomePassword:'bad\npassword'}),/одной строкой/);
});
