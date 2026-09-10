import { execFileSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("firewall operations preserve ordering, dry-run, management endpoints and backup integrity", () => {
  const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  execFileSync("python3", ["-m", "unittest", "discover", "-s", "ansible/tests", "-p", "test_firewall.py"], { cwd: repository, timeout: 15000, stdio: "pipe" });
});
