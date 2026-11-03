import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import vm from "node:vm";
import test from "node:test";
import ts from "typescript";
import { compileServerModules } from "./_typescript-loader.mjs";
import { rmSync } from "node:fs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const file = readFileSync(path.join(root, "app/api/settings/debian-tracker/route.ts"), "utf8");
const js = ts.transpileModule(file, { compilerOptions: {
  module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true,
} }).outputText;

const audit = { download: 0, approve: 0 };
const status = () => ({ ok: true, selectedSha256: null, lastImportedSha256: null });
class ManagementError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const mockManager = {
  getDebianTrackerManagementStatus: status,
  fetchDebianTrackerCandidate: async () => {
    audit.download++;
    return { ...status(), imported: { sha256: "a".repeat(64) } };
  },
  approveDebianTrackerSelection: input => {
    audit.approve++;
    return { ...status(), selectedSha256: input.selectedSha256 };
  },
  DebianTrackerManagementError: ManagementError,
};
const exports = {};
vm.runInNewContext(js, {
  exports,
  require: name => {
    if (name === "next/server") return { NextResponse: {
      json: (body, init = {}) => ({ body, status: init.status ?? 200 }),
    } };
    if (name === "@/lib/debian-tracker-management") return mockManager;
    throw new Error("Unexpected dependency " + name);
  },
  Buffer,
});
const request = (value, extra = {}) => {
  const body = typeof value === "string" ? value : JSON.stringify(value);
  return { headers: new Headers({ "content-length": String(Buffer.byteLength(body)) }),
    text: async () => body, ...extra };
};

test("unknown URLs and arbitrary filesystem paths are rejected before import", async () => {
  const result = await exports.POST(request({ url: "http://127.0.0.1/admin" }));
  assert.equal(result.status, 400);
  assert.equal(audit.download, 0);
  assert.equal((await exports.POST(request({ path: "/etc/passwd" }))).status, 400);
  assert.equal(audit.download, 0);
  assert.equal((await exports.POST(request("{broken"))).status, 400);
  assert.equal(audit.download, 0);
});

test("only explicitly confirmed selection with known prior version can change CVE source", async () => {
  const noApproval = await exports.PATCH(request({ selectedSha256: "a".repeat(64), expectedSha256: null }));
  assert.equal(noApproval.status, 400);
  assert.equal(audit.approve, 0);
  const extra = await exports.PATCH(request({ approved: true, selectedSha256: "a".repeat(64),
    expectedSha256: null, url: "file:///etc/shadow" }));
  assert.equal(extra.status, 400);
  assert.equal(audit.approve, 0);
  const valid = await exports.PATCH(request({ approved: true, selectedSha256: "a".repeat(64), expectedSha256: null }));
  assert.equal(valid.status, 200);
  assert.equal(valid.body.selectedSha256, "a".repeat(64));
  assert.equal(audit.approve, 1);
  const disabled = await exports.PATCH(request({ approved: true, selectedSha256: null,
    expectedSha256: "a".repeat(64) }));
  assert.equal(disabled.status, 200);
  assert.equal(audit.approve, 2);
});

test("POST is explicit and the route never receives host/command parameters", async () => {
  assert.equal((await exports.GET()).body.ok, true);
  const imported = await exports.POST(request({}));
  assert.equal(imported.status, 200);
  assert.equal(audit.download, 1);
  assert.equal(imported.body.imported.sha256, "a".repeat(64));
  const huge = await exports.POST(request("x".repeat(513)));
  assert.equal(huge.status, 400);
  assert.equal(audit.download, 1);
});

test("the shared route matcher protects Debian status and changes behind admin auth and Origin", async () => {
  const built = compileServerModules(["auth-edge"]);
  try {
    const { isProtectedPath, isMutatingRequest, hasTrustedOrigin } = await import(built.url("auth-edge"));
    assert.equal(isProtectedPath("/api/settings/debian-tracker"), true);
    assert.equal(isMutatingRequest("POST"), true);
    assert.equal(isMutatingRequest("PATCH"), true);
    assert.equal(hasTrustedOrigin({
      headers: new Headers({ host: "localhost:3000", origin: "https://other.example" }),
      nextUrl: { origin: "http://localhost:3000" },
    }), false);
    assert.equal(hasTrustedOrigin({
      headers: new Headers({ host: "localhost:3000", origin: "http://localhost:3000" }),
      nextUrl: { origin: "http://localhost:3000" },
    }), true);
  } finally { rmSync(built.directory, { recursive: true, force: true }); }
});
