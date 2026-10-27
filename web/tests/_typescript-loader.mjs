import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

// Execute the actual server modules, without Next.js or a source-text mock.
export function compileServerModules(names) {
  const directory = mkdtempSync(path.join(tmpdir(), "hcp-server-tests-"));
  const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const pending = [...names];
  const written = new Set();
  for (const name of pending) {
    if (written.has(name)) continue;
    written.add(name);
    if (name.endsWith(".json")) {
      writeFileSync(path.join(directory, `${name}.mjs`), `export default ${readFileSync(path.join(webDir, "lib", name), "utf8")};`);
      continue;
    }
    const source = readFileSync(path.join(webDir, "lib", `${name}.ts`), "utf8");
    const output = ts.transpileModule(source, {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
    }).outputText.replace(/(["'])@\/lib\/([^"']+)\1/g, '"./$2.mjs"');
    for (const match of output.matchAll(/["']\.\/([\w.-]+)\.mjs["']/g)) if (!written.has(match[1])) pending.push(match[1]);
    writeFileSync(path.join(directory, `${name}.mjs`), output);
  }
  return { directory, url: (name) => pathToFileURL(path.join(directory, `${name}.mjs`)).href };
}
