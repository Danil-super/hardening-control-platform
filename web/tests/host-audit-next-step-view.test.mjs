import assert from "node:assert/strict";
import { readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";
import { compileServerModules } from "./_typescript-loader.mjs";

const require = createRequire(import.meta.url);
const compiled = compileServerModules(["host-audit-workflow"]);
const workflow = await import(compiled.url("host-audit-workflow"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));
const source = ts.transpileModule(readFileSync(new URL("../components/hosts/host-audit-next-step.tsx", import.meta.url), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
}).outputText;
const stubs = {
  "@/lib/host-audit-workflow": workflow,
  "@/components/ui/select": { Select: ({ value, children }) => createElement("select", { value, onChange() {} }, children) },
  "@/components/ui/button": { LinkButton: ({ href, children }) => createElement("a", { href }, children) },
  "@/components/hosts/host-source-guidance": { HostSourceGuidance: () => createElement("p", null, "OVAL / OpenSCAP") },
};
const module = { exports: {} };
new Function("require", "module", "exports", source)((name) => Object.hasOwn(stubs, name) ? stubs[name] : require(name), module, module.exports);
const risk = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, auditCount: 0, freshCount: 0, partialCount: 0, staleCount: 0, maxAgeHours: 168 };
const render = (changes = {}, flags = {}) => {
  const host = { alias: "astra", riskSummary: { ...risk, ...changes } };
  return renderToStaticMarkup(createElement(module.exports.HostAuditNextStep, { hosts: [host], host, onSelectHost() {}, controlReady: true, activeJob: false, recoveryRequired: false, ...flags }));
};

test("routine audit advice does not duplicate the tool selector; source settings remain accessible", () => {
  for (const changes of [{}, { auditCount: 1, freshCount: 1 }, { auditCount: 1, freshCount: 1, high: 1 }, { auditCount: 1, staleCount: 1 }, { auditCount: 1, freshCount: 1, partialCount: 1 }]) {
    const html = render(changes);
    assert.doesNotMatch(html, /Запустите (первый )?аудит|Выбрать инструмент|Разберите наблюдаемые|Проверьте состояние отчётов|Обновите доказательства/);
    assert.match(html, /Источники и профиль/); assert.match(html, /OVAL \/ OpenSCAP/);
  }
});

test("recovery, controller and identity problems retain their actionable notices", () => {
  assert.match(render({}, { recoveryRequired: true }), /Проверьте прерванное изменение/);
  assert.match(render({}, { controlReady: false }), /Проверьте управляющий узел/);
  assert.match(render({ identityExcludedCount: 1 }), /Уточните идентичность хоста/);
  assert.match(render({ auditCount: NaN }), /Статус аудита не подтверждён/);
});
