import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source=ts.transpileModule(readFileSync(new URL('../app/api/ansible/project-reports/route.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
class PdfExportBusyError extends Error {}
let failure;
const module={exports:{}};
const stubs={
  'next/server':{NextResponse:Response},
  '@/lib/project-report':{PdfExportBusyError,createProjectReport:async()=>{throw failure;}},
};
new Function('require','module','exports',source)(name=>stubs[name],module,module.exports);
const request=()=>new Request('https://hcp.example/api/ansible/project-reports',{method:'POST',body:JSON.stringify({hostAlias:'fixture',subject:{clientName:'Test'}})});
test('a one-run PDF occupying the shared renderer returns a retryable final PDF response',async()=>{
  failure=new PdfExportBusyError('Формирование PDF занято. Повторите позже.');
  const response=await module.exports.POST(request());
  assert.equal(response.status,429);assert.match((await response.json()).message,/Повторите позже/);
  failure=new Error('Проверьте сведения');
  assert.equal((await module.exports.POST(request())).status,400);
});
