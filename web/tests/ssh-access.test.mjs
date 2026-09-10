import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, afterEach, beforeEach } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ssh-access"]);
const ssh = await import(compiled.url("ssh-access"));
const previous = { ...process.env };
let directory;
let publicKey;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "hcp-ssh-test-"));
  const privateKey = path.join(directory, "control key");
  execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-f", privateKey, "-q"]);
  publicKey = readFileSync(`${privateKey}.pub`, "utf8").trim();
  mkdirSync(path.join(directory, "bin"));
  writeFileSync(path.join(directory, "bin/ssh-keyscan"), '#!/bin/sh\nprintf "%s\\n" "$HCP_TEST_HOST_KEY_LINE"\n', { mode: 0o700 });
  process.env.PATH = `${directory}/bin:${previous.PATH}`;
  process.env.HCP_SSH_PRIVATE_KEY_PATH = privateKey;
  process.env.HCP_KNOWN_HOSTS_PATH = path.join(directory, "known hosts");
  process.env.HCP_TEST_HOST_KEY_LINE = `untrusted-output.example ${publicKey.split(/\s+/).slice(0, 2).join(" ")}`;
});
afterEach(() => {
  rmSync(directory, { recursive: true, force: true });
  for (const key of ["PATH", "HCP_SSH_PRIVATE_KEY_PATH", "HCP_KNOWN_HOSTS_PATH", "HCP_TEST_HOST_KEY_LINE"]) {
    if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key];
  }
});
after(() => rmSync(compiled.directory, { recursive: true, force: true }));

test("invalid ports and malformed IPs are rejected without falling back to SSH 22", () => {
  assert.equal(ssh.normalizeSshPort(undefined), 22);
  assert.equal(ssh.normalizeSshPort("2222"), 2222);
  for (const value of ["", "oops", 0, -1, 65536, 22.5]) assert.equal(ssh.normalizeSshPort(value), null);
  for (const value of ["999.1.1.1", "001.2.3.4", "-oProxyCommand=bad", "foo\nbar", ""]) assert.equal(ssh.isSafeSshHostAddress(value), false);
  assert.equal(ssh.isSafeSshHostAddress("192.0.2.10"), true);
});

test("wizard derives the public key actually matching its private key", async () => {
  writeFileSync(`${process.env.HCP_SSH_PRIVATE_KEY_PATH}.pub`, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHN0YWxl stale");
  const result = await ssh.getControlPublicKey();
  assert.equal(result.publicKey.split(/\s+/).slice(0, 2).join(" "), publicKey.split(/\s+/).slice(0, 2).join(" "));
  assert.match(result.fingerprint, /^SHA256:/);
  assert.match(ssh.ansibleSshArgs(), /UserKnownHostsFile=".*known hosts"/);
});

test("confirmed keys are bound to the requested host and nondefault port", async () => {
  const candidates = await ssh.scanHostKeys("192.0.2.10", 2222);
  assert.match(candidates[0].hostKeyLine, /^\[192\.0\.2\.10\]:2222 /);
  writeFileSync(process.env.HCP_KNOWN_HOSTS_PATH, "# existing file without final newline");
  const trusted = await ssh.trustHostKey({ address: "192.0.2.10", port: 2222, expectedFingerprint: candidates[0].fingerprint });
  assert.equal(trusted.alreadyTrusted, false);
  assert.match(readFileSync(process.env.HCP_KNOWN_HOSTS_PATH, "utf8"), /newline\n\[192\.0\.2\.10\]:2222 /);
  assert.equal((await ssh.trustHostKey({ address: "192.0.2.10", port: 2222, expectedFingerprint: candidates[0].fingerprint })).alreadyTrusted, true);
});

test("a mismatched fingerprint and a changed hashed known-host key are refused", async () => {
  const candidates = await ssh.scanHostKeys("192.0.2.10", 2222);
  await assert.rejects(ssh.trustHostKey({ address: "192.0.2.10", port: 2222, expectedFingerprint: "SHA256:incorrect" }), { code: "host_key_mismatch" });
  const oldKey = path.join(directory, "old-key");
  execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-f", oldKey, "-q"]);
  writeFileSync(process.env.HCP_KNOWN_HOSTS_PATH, `[192.0.2.10]:2222 ${readFileSync(`${oldKey}.pub`, "utf8")}`);
  execFileSync("ssh-keygen", ["-H", "-f", process.env.HCP_KNOWN_HOSTS_PATH], { stdio: "ignore" });
  await assert.rejects(ssh.trustHostKey({ address: "192.0.2.10", port: 2222, expectedFingerprint: candidates[0].fingerprint }), { code: "host_key_conflict" });
});
