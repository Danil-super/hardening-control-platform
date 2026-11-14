import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compileServerModules } from "./compile-server-modules.mjs";

// shortcut: restart dev after editing server normalizers; production rebuilds this bundle.
const destination = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../.hcp-report-reader");
const compiled = compileServerModules(["ansible-reports"]);
try {
  rmSync(destination, { recursive: true, force: true });
  mkdirSync(destination, { recursive: true });
  cpSync(compiled.directory, destination, { recursive: true });
  writeFileSync(path.join(destination, "reader.mjs"), `import { parentPort, workerData } from "node:worker_threads";
import { readReportMetadata } from "./ansible-reports.mjs";
parentPort.postMessage(workerData.map(file => readReportMetadata(file)));
`);
} finally { rmSync(compiled.directory, { recursive: true, force: true }); }
