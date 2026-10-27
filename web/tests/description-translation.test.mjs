import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["description-translation"]);
const { needsRussianTranslation, verifyTranslation, translateDescription } = await import(compiled.url("description-translation"));
const state = mkdtempSync(path.join(tmpdir(), "hcp-translation-test-"));
process.env.HCP_STATE_DIR = state;
after(() => { delete process.env.HCP_STATE_DIR; rmSync(compiled.directory, { recursive: true, force: true }); rmSync(state, { recursive: true, force: true }); });

test("Russian descriptions bypass the translator; English prose requires it", async () => {
  assert.equal(needsRussianTranslation("Проверьте настройки Chromium и выполните аудит"), false);
  assert.equal(needsRussianTranslation("Use after free in Chromium allows code execution."), true);
  assert.deepEqual(await translateDescription("Проверьте настройки Chromium"), { text: "Проверьте настройки Chromium", language: "ru", machineTranslated: false, engine: "original" });
  assert.equal(readdirSync(state).length, 0);
});

test("a translation cannot add, omit, or change CVEs, CWEs and affected versions", () => {
  const original = "CVE-2024-10487 affects versions before 130.0.6723.92, CWE-787.";
  assert.equal(verifyTranslation(original, "CVE-2024-10487: затронуты версии до 130.0.6723.92, CWE-787."), true);
  for (const translated of ["CVE-2024-10487: версии до 131.0.6723.92, CWE-787.", "Версии до 130.0.6723.92, CWE-787.", "CVE-2024-10487: 130.0.6723.92, CWE-787; 1.2.", original]) assert.equal(verifyTranslation(original, translated), false);
});

test("content-addressed cache requires the exact original and model and rejects symlinks", async () => {
  const original = "The Chromium vulnerability affects versions before 130.0.6723.92.";
  const translated = "Уязвимость Chromium затрагивает версии до 130.0.6723.92.";
  // A failed translator invocation still creates the private cache directory.
  await assert.rejects(translateDescription(original));
  const engine = "argos-en-ru-1.9-glossary-v4";
  const key = createHash("sha256").update(engine + "\n" + original).digest("hex");
  const pathname = path.join(state, "description-translations", key + ".json");
  writeFileSync(pathname, JSON.stringify({ engine, text: translated, sourceSha256: createHash("sha256").update(original).digest("hex") }));
  assert.equal((await translateDescription(original)).text, translated);
  rmSync(pathname);
  symlinkSync(path.join(state, "outside"), pathname);
  await assert.rejects(translateDescription(original), /недопустимый тип/);
});


test("OpenSSH patch versions remain exact in Russian text", () => {
  assert.equal(verifyTranslation("Installed 8.4p1, fixed 9.3p2", "Установлено 8.4p1, исправлено 9.3p2"), true);
  assert.equal(verifyTranslation("Installed 8.4p1, fixed 9.3p2", "Установлено 8.4p2, исправлено 9.3p2"), false);
});


test("Greenbone short prose is translated while CPE identifiers remain technical data", () => {
  assert.equal(needsRussianTranslation("Services"), true);
  assert.equal(needsRussianTranslation("Traceroute"), true);
  assert.equal(needsRussianTranslation("192.0.2.10|cpe:/a:openbsd:openssh:8.4p1\n192.0.2.10|cpe:/o:debian:debian_linux"), false);
});
