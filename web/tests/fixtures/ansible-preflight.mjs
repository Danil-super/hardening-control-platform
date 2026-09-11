#!/usr/bin/env node
// Controlled subprocess fixture for production HTTP preflight tests. No SSH.
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
if (args.includes("--version")) { console.log("ansible [core 2.14.18]"); process.exit(0); }
const stateFile = process.env.HCP_PREFLIGHT_FIXTURE;
if (!stateFile) throw new Error("This executable is only for isolated HTTP tests");
const scenario = readFileSync(stateFile, "utf8").trim();
const treeIndex = args.indexOf("--tree");
if (treeIndex < 0) throw new Error("Expected an Ansible tree result directory");
const tree = args[treeIndex + 1];
const alias = args[treeIndex + 2];
const stage = path.basename(tree);
appendFileSync(`${stateFile}.calls`, `${stage}\n`);
let data = { changed: false, stdout: "" };
if (stage === "ssh" && scenario === "unknown-key") data = { failed: true, msg: "No ED25519 host key is known for 192.0.2.10 and you have requested strict checking. Host key verification failed." };
if (stage === "python-version") data.stdout = "HCP_PYTHON=3.11.2\n";
if (stage === "setup") data.ansible_facts = { ansible_distribution: "Astra fixture", ansible_distribution_version: "fixture", ansible_python: { executable: "/usr/bin/python3" } };
if (stage === "sudo") {
  const elevatedModule = args[args.indexOf("-m") + 1] === "command" && args.includes("ansible_become=true");
  data = !elevatedModule ? { failed: true, msg: "Fixture requires an elevated Ansible module, not just raw sudo" }
    : scenario === "sudo-password" ? { failed: true, msg: "Missing sudo password" }
    : { changed: false, stdout: scenario === "non-root" ? "1000\n" : "0\n" };
}
if (stage === "readiness") data.stdout = JSON.stringify({
  schemaVersion: 1, osRelease: { ID: "astra", PRETTY_NAME: "Astra fixture" }, astraVersion: "fixture", kernel: "fixture",
  pythonVersion: "3.11.2", effectiveUid: args.includes("ansible_become=true") ? 0 : 1000, initSystem: "systemd",
  tools: { "dpkg-query": "/usr/bin/dpkg-query", ss: "/usr/bin/ss", sshd: "/usr/sbin/sshd", systemctl: "/usr/bin/systemctl" },
  firewall: { ufw: "inactive", firewalld: "missing", netfilterPersistent: "missing" }, errors: [],
});
mkdirSync(tree, { recursive: true });
writeFileSync(path.join(tree, alias), JSON.stringify(data));
console.log(JSON.stringify(data));
if (data.failed) process.exitCode = 2;
