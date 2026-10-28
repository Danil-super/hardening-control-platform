#!/usr/bin/env node
import assert from "node:assert/strict";
import { rmSync, writeFileSync } from "node:fs";
import { compileServerModules } from "../../web/tests/_typescript-loader.mjs";

const [reportId, definitionId, cve, expected, output] = process.argv.slice(2);
assert.ok(process.env.HCP_REPORTS_DIR && process.env.HCP_STATE_DIR);
const compiled = compileServerModules(["ansible-reports"]);
try {
  const { readAnsibleReport } = await import(compiled.url("ansible-reports"));
  const report = readAnsibleReport(reportId);
  assert.ok(report, "The production web normalizer must read the actual VM report");
  assert.equal(report.mode, "astra-oval");
  assert.equal(report.score, null);
  assert.equal(report.partial, report.raw.scanner.partial);
  const control = report.findings.filter((finding) => finding.id === definitionId);
  assert.equal(control.length, expected === "true" ? 1 : 0);
  if (control.length) {
    assert.equal(control[0].status, "failed");
    assert.ok(control[0].vulnerability.cveIds.includes(cve));
  }
  writeFileSync(output, JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
} finally {
  rmSync(compiled.directory, { recursive: true, force: true });
}
