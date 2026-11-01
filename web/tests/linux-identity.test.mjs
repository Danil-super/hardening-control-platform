import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, symlinkSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["linux-identity", "asset-binding"]);
const { machineIdentityProbeCommand } = await import(compiled.url("linux-identity"));
const { machineIdentityHash } = await import(compiled.url("asset-binding"));
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test("POSIX identity probe prefers the canonical ID and reads D-Bus only when it is absent", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "hcp-linux-identity-"));
  const primary = path.join(directory, "primary ' id"), fallback = path.join(directory, "dbus-id");
  const original = "1234567890abcdef1234567890abcdef", other = "a".repeat(32);
  const run = () => execFileSync("/bin/sh", ["-c", machineIdentityProbeCommand([primary, fallback])], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  try {
    writeFileSync(fallback, other + "\n");
    assert.equal(run(), `HCP_MACHINE_ID=${other}\n`);
    writeFileSync(primary, original);
    assert.equal(run(), `HCP_MACHINE_ID=${original}\n`, "no trailing newline is accepted");
    writeFileSync(primary, original + "\n");
    assert.equal(run(), `HCP_MACHINE_ID=${original}\n`);
    writeFileSync(primary, "invalid-id\n");
    const invalid = run().trim().slice("HCP_MACHINE_ID=".length);
    assert.throws(() => machineIdentityHash(invalid));
    writeFileSync(primary, "");
    assert.throws(run, "an empty primary ID must not use another identity");
    rmSync(primary); symlinkSync(path.join(directory, "absent"), primary);
    assert.throws(run, "an unreadable existing primary link must not use another identity");
    rmSync(primary); rmSync(fallback);
    assert.throws(run, "no identity is created during a probe");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
