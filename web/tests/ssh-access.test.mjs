import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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


test("saved server lookup is read-only and respects hashed hosts and nondefault ports", async () => {
  assert.equal(await ssh.hasSavedHostKey("192.0.2.10", 2222), false);
  const known = process.env.HCP_KNOWN_HOSTS_PATH;
  writeFileSync(known, `[192.0.2.10]:2222 ${publicKey}\n`);
  execFileSync("ssh-keygen", ["-H", "-f", known], { stdio: "pipe" });
  const before = readFileSync(known, "utf8");
  // Status must not attempt ssh-keyscan or change the file.
  rmSync(path.join(directory, "bin/ssh-keyscan"));
  assert.equal(await ssh.hasSavedHostKey("192.0.2.10", 2222), true);
  assert.equal(await ssh.hasSavedHostKey("192.0.2.10", 22), false);
  assert.equal(await ssh.hasSavedHostKey("192.0.2.11", 2222), false);
  assert.equal(readFileSync(known, "utf8"), before);
});

test("asset probe binds a negotiated saved key and reads machine-id without exposing raw output", async () => {
  writeFileSync(process.env.HCP_KNOWN_HOSTS_PATH, `192.0.2.10 ${publicKey}\n`);
  const fingerprint = execFileSync("ssh-keygen", ["-lf", `${process.env.HCP_SSH_PRIVATE_KEY_PATH}.pub`, "-E", "sha256"], { encoding: "utf8" }).split(/\s+/)[1];
  const capture = path.join(directory, "ssh-invocation.json");
  writeFileSync(path.join(directory, "bin/ssh"), `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2), rawTrust = args.find(value => value.startsWith('UserKnownHostsFile=')).slice('UserKnownHostsFile='.length), trust = rawTrust.startsWith('"') ? JSON.parse(rawTrust) : rawTrust;
fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({args,trust,bytes:fs.readFileSync(trust,'utf8')}));
// Change mutable global trust during the network await. The connection still
// uses the captured private file, and returns only its negotiated public key.
fs.writeFileSync(${JSON.stringify(process.env.HCP_KNOWN_HOSTS_PATH)}, ${JSON.stringify("# changed during probe\n")});
console.error(${JSON.stringify(`debug1: Server host key: ssh-ed25519 ${fingerprint}`)});
console.log('HCP_MACHINE_ID=1234567890abcdef1234567890abcdef');
`, { mode: 0o700 });
  const result = await ssh.probeTrustedAssetIdentity({ address: "192.0.2.10", port: 22, user: "audit", privateKeyPath: process.env.HCP_SSH_PRIVATE_KEY_PATH });
  assert.equal(result.sshHostKeyFingerprint, fingerprint);
  assert.match(result.hostKeyLine, /^192\.0\.2\.10 ssh-ed25519 /);
  assert.equal(result.hostKeyAlgorithms, "ssh-ed25519");
  assert.match(result.machineIdSha256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(result).includes("1234567890abcdef1234567890abcdef"), false);
  const invoked = JSON.parse(readFileSync(capture));
  assert.notEqual(invoked.trust, process.env.HCP_KNOWN_HOSTS_PATH);
  assert.ok(invoked.args.includes("StrictHostKeyChecking=yes"));
  assert.ok(invoked.args.includes("GlobalKnownHostsFile=/dev/null"));
  assert.match(invoked.bytes, /ssh-ed25519/);
  assert.equal(existsSync(invoked.trust), false, "temporary trust is removed after use");
  assert.equal(result.pythonVersion, undefined);
  assert.equal(invoked.args.at(-1).includes("HCP_PYTHON="), false, "identity-only callers do not add a Python protocol");
});

test("trusted identity and the configured Python version share one authenticated SSH command", async () => {
  const fingerprint = execFileSync("ssh-keygen", ["-lf", `${process.env.HCP_SSH_PRIVATE_KEY_PATH}.pub`, "-E", "sha256"], { encoding: "utf8" }).split(/\s+/)[1];
  const capture = path.join(directory, "python-probe.json");
  for (const output of ["HCP_PYTHON=3.14.0", "", "HCP_PYTHON=broken", "HCP_PYTHON=3.14.0\nHCP_PYTHON=3.11.9"]) {
    writeFileSync(process.env.HCP_KNOWN_HOSTS_PATH, `192.0.2.10 ${publicKey}\n`);
    writeFileSync(path.join(directory, "bin/ssh"), `#!${process.execPath}
const fs = require('node:fs');
fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify(process.argv.slice(2)));
console.error(${JSON.stringify(`debug1: Server host key: ssh-ed25519 ${fingerprint}`)});
console.log('HCP_MACHINE_ID=1234567890abcdef1234567890abcdef');
console.log(${JSON.stringify(output)});
`, { mode: 0o700 });
    const result = await ssh.probeTrustedAssetIdentity({ address: "192.0.2.10", port: 22, user: "audit", privateKeyPath: process.env.HCP_SSH_PRIVATE_KEY_PATH, pythonInterpreter: "/opt/python3.14/bin/python3" });
    assert.equal(result.pythonInterpreter, "/opt/python3.14/bin/python3");
    assert.equal(result.pythonVersion, output === "HCP_PYTHON=3.14.0" ? "3.14.0" : null);
    assert.equal(result.sshHostKeyFingerprint, fingerprint);
    const args = JSON.parse(readFileSync(capture, "utf8"));
    assert.match(args.at(-1), /\/var\/lib\/dbus\/machine-id/);
    assert.match(args.at(-1), /'\/opt\/python3\.14\/bin\/python3' -c/);
    assert.ok(args.includes("StrictHostKeyChecking=yes"));
  }
  await assert.rejects(ssh.probeTrustedAssetIdentity({ address: "192.0.2.10", port: 22, user: "audit", privateKeyPath: process.env.HCP_SSH_PRIVATE_KEY_PATH, pythonInterpreter: "/tmp/python3; touch /tmp/marker" }), /абсолютный путь/);
});
