import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

// This is a real local Ansible task timeout, not an invented callback payload.
// Its detached fixture task writes only inside the temporary test directory.
test("real Ansible task timeout cannot prove that a surviving command completed", { timeout: 30_000 }, async () => {
  const compiled = compileServerModules(["ansible-control"]);
  const directory = mkdtempSync(path.join(tmpdir(), "hcp-task-timeout-"));
  const saved = Object.fromEntries(["ANSIBLE_LOCAL_TEMP", "ANSIBLE_REMOTE_TEMP"].map((key) => [key, process.env[key]]));
  const target = path.join(directory, "target");
  const release = path.join(directory, "release");
  const done = path.join(directory, "done");
  const helper = path.join(directory, "controlled-task.py");
  const playbook = path.join(directory, "playbook.json");
  const childCode = `import pathlib,sys,time
root=pathlib.Path(sys.argv[1])
deadline=time.monotonic()+15
while not (root/'release').exists() and time.monotonic()<deadline:
    time.sleep(0.02)
if (root/'release').exists():
    (root/'target').write_text('late-change')
    (root/'done').write_text('completed')
`;
  writeFileSync(target, "baseline");
  writeFileSync(helper, `import pathlib,subprocess,sys,time
child=subprocess.Popen([sys.executable,'-c',${JSON.stringify(childCode)},sys.argv[1]],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
(pathlib.Path(sys.argv[1])/'launched').write_text(str(child.pid))
time.sleep(12)
`);
  writeFileSync(playbook, JSON.stringify([{ hosts: "all", connection: "local", become: false, gather_facts: false,
    tasks: [{ name: "Execute firewall operation or read-only preview", "ansible.builtin.command": {
      argv: ["/usr/bin/python3", helper, directory],
    }, timeout: 2 }],
  }]));
  process.env.ANSIBLE_LOCAL_TEMP = path.join(directory, "ansible-local");
  process.env.ANSIBLE_REMOTE_TEMP = path.join(directory, "ansible-remote");
  async function waitForCompletion() {
    const deadline = Date.now() + 5000;
    while (!existsSync(done) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(existsSync(done), true, "the controlled surviving task must finish before cleanup");
  }
  try {
    const { executeAnsiblePlaybook } = await import(compiled.url("ansible-control"));
    await assert.rejects(executeAnsiblePlaybook({ args: ["-i", "localhost,", playbook], timeout: 20_000 }), (error) => {
      assert.equal(error.code, 2);
      assert.equal(error.killed, false);
      assert.equal(error.signal, null);
      assert.match(error.stdout, /PLAY RECAP/);
      assert.equal(error.remoteOutcome, "unknown");
      return true;
    });
    assert.equal(existsSync(path.join(directory, "launched")), true);
    assert.equal(readFileSync(target, "utf8"), "baseline");
    writeFileSync(release, "continue");
    await waitForCompletion();
    assert.equal(readFileSync(target, "utf8"), "late-change");
  } finally {
    if (existsSync(path.join(directory, "launched")) && !existsSync(done)) {
      writeFileSync(release, "continue");
      await waitForCompletion();
    }
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
    rmSync(compiled.directory, { recursive: true, force: true });
  }
});
