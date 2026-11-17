import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const code = ts.transpileModule(readFileSync(new URL("../components/settings/openscap-policies-client.tsx", import.meta.url), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
}).outputText;

function form() {
  const states = [], effects = [], requests = [];
  let cursor = 0, mounted = false;
  const useState = (initial) => {
    const index = cursor++;
    if (!(index in states)) states[index] = typeof initial === "function" ? initial() : initial;
    return [states[index], (value) => { states[index] = typeof value === "function" ? value(states[index]) : value; }];
  };
  const presets = { ASTRA_BASELINE_DATASTREAM: "hcp-astra.xml", ASTRA_BASELINE_PROFILE: "hcp-astra" };
  const payload = { ok: true, inventoryGroups: ["linux_hosts", "astra", "new-group"], policies: [
    { groupName: "linux_hosts", datastream: "/custom/scap.xml", profile: "custom-profile", updatedAt: "2026-11-17T08:00:00Z" },
    { groupName: "astra", datastream: presets.ASTRA_BASELINE_DATASTREAM, profile: presets.ASTRA_BASELINE_PROFILE, updatedAt: "2026-11-17T08:00:00Z" },
  ] };
  const stubs = {
    react: { useState, useEffect: (effect) => { if (!mounted) effects.push(effect); } },
    "@/components/ui/feedback": { useFeedbackMessage: () => useState("") },
    "@/components/ui/select": { Select: "Select" },
    "@/components/ui/button": { Button: "Button" },
    "@/lib/client-api": { readApiResponse: (response) => response.json(), errorMessage: (error) => error.message },
    "@/lib/scap-presets": presets,
  };
  const module = { exports: {} };
  new Function("require", "module", "exports", "fetch", code)(
    (name) => Object.hasOwn(stubs, name) ? stubs[name] : require(name), module, module.exports,
    async (url, options) => { requests.push({ url, ...options }); return { ok: true, json: async () => payload }; },
  );
  const render = () => { cursor = 0; const tree = module.exports.OpenScapPoliciesClient(); mounted = true; return tree; };
  const find = (tree, predicate) => {
    if (!tree || typeof tree !== "object") return null;
    if (predicate(tree)) return tree;
    for (const child of [tree.props?.children].flat(Infinity)) { const match = find(child, predicate); if (match) return match; }
    return null;
  };
  render(); effects.forEach((effect) => effect());
  return { render, find, requests, ready: () => new Promise((resolve) => setImmediate(resolve)) };
}

test("policy form reads the existing custom profile without changing the saved policy", async () => {
  const view = form(); await view.ready(); const tree = view.render();
  assert.equal(view.find(tree, (node) => node.type === "Select" && node.props.value === "custom")?.props.value, "custom");
  assert.equal(view.find(tree, (node) => node.props.placeholder === "Полный путь к SCAP datastream на хосте")?.props.value, "/custom/scap.xml");
  assert.equal(view.find(tree, (node) => node.props.placeholder === "Идентификатор из oscap info")?.props.value, "custom-profile");
  assert.equal(view.requests.length, 1); assert.equal(view.requests[0].method, undefined);
});

test("switching groups restores their own profile and never carries custom values to a new group", async () => {
  const view = form(); await view.ready();
  const group = () => view.find(view.render(), (node) => node.props["aria-label"] === "Группа профиля");
  group().props.onValueChange("astra");
  let tree = view.render();
  assert.equal(view.find(tree, (node) => node.props["aria-label"] === "Набор проверок")?.props.value, "astra");
  group().props.onValueChange("new-group");
  tree = view.render();
  view.find(tree, (node) => node.props["aria-label"] === "Набор проверок").props.onValueChange("custom");
  tree = view.render();
  assert.equal(view.find(tree, (node) => node.props.placeholder === "Полный путь к SCAP datastream на хосте")?.props.value, "");
  group().props.onValueChange("linux_hosts");
  assert.equal(view.find(view.render(), (node) => node.props.placeholder === "Полный путь к SCAP datastream на хосте")?.props.value, "/custom/scap.xml");
  assert.equal(view.requests.length, 1);
});
