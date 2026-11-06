#!/usr/bin/env node
// Isolated HTTP launch boundary: no SSH, scanner or changes on a target host.
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import path from "node:path";

assert.ok(process.env.HCP_PREFLIGHT_FIXTURE, "Only for isolated HTTP tests");
const args = process.argv.slice(2);
assert.ok(args.some((value) => value.endsWith("/astra-oval-audit.yml")));
const variables = {};
for (let i = 0; i < args.length; i++) {
  if (args[i] !== "-e") continue;
  for (const [key, value] of Object.entries(JSON.parse(args[++i]))) {
    variables[key] = typeof value === "object" ? value.__ansible_unsafe : value;
  }
}
const config = JSON.parse(variables.hcp_oval_config);
writeFileSync(`${process.env.HCP_PREFLIGHT_FIXTURE}.oval-config`, JSON.stringify(config));
const alias = args[args.indexOf("--limit") + 1];
writeFileSync(path.join(variables.hcp_reports_dir, `${alias}-astra-oval-${variables.report_run_id}.json`), JSON.stringify({
  inventoryHost: alias, hostname: alias, mode: "astra-oval", profileId: "astra-oval", createdAt: new Date().toISOString(),
  scanner: {
    available: true, partial: false, evaluationPerformed: true, exitCode: 0, partialReasons: [],
    database: { sha256: config.sha256, checksumVerified: true }, resultSha256: "b".repeat(64),
    evidenceProjection: config.evidenceProjection, fullDefinitionIdSetPreserved: true,
    auxiliaryDetailsOmitted: config.evidenceProjection === "bounded",
    definitionCount: 1, evaluatedDefinitionCount: 1, resultCounts: { false: 1 },
    definitionResults: [{ id: "oval:fixture:def:1", class: "vulnerability", result: "false", platformApplicability: { status: "astra_named" } }],
  }, findings: [], events: [],
}));
console.log("Isolated OVAL launch fixture completed; no real scanner executed.");
