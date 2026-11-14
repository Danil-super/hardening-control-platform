import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test, { after } from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["ansible-literal-vars", "astra-oval-config"]);
const { ansibleLiteralExtraVars } = await import(compiled.url("ansible-literal-vars"));
const { validateAstraOvalConfig, assertAstraOvalProvenance } = await import(compiled.url("astra-oval-config"));
const directory = mkdtempSync(path.join(tmpdir(), "hcp-literal-vars-"));
const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
after(() => {
  rmSync(compiled.directory, { recursive: true, force: true });
  rmSync(directory, { recursive: true, force: true });
});

test("real Ansible keeps metadata, policy paths, custom values and passwords literal", () => {
  const marker = path.join(directory, "lookup-must-not-run");
  const expression = `{{ lookup('ansible.builtin.pipe', 'touch ${marker}') }}`;
  const config = validateAstraOvalConfig({
    mode: "local", path: "/var/lib/{{ 6 * 7 }}/oval.xml", url: "", sha256: "a".repeat(64),
    releasePattern: "1.7.*", architectures: ["x86_64"], maxAgeDays: 30,
    sourceName: 'Источник "quote" \\ literal', sourceReference: expression,
    sourceReviewedAt: "2026-10-28T00:00:00Z",
  });
  assertAstraOvalProvenance(config);
  const datastream = `/profiles/${expression}/content.xml`;
  const custom = "{% set x = 42 %}{{ x }} ansible_connection=local";
  const password = 'sudo-{{ 6 * 7 }}-"quoted"-\\-пароль';
  // Extract the production chain, rather than test an invented safe template.
  const production = readFileSync(path.join(webDir, "..", "ansible/playbooks/astra-oval-audit.yml"), "utf8");
  const vars = ["oval_config_value", "oval_settings", "oval_config_json"].map((name) => {
    const line = production.split("\n").find((line) => line.startsWith(`    ${name}:`));
    assert.ok(line, `production variable ${name}`);
    return line;
  }).join("\n");
  const outputFile = path.join(directory, "values.json");
  const playbook = path.join(directory, "literal.yml");
  const writeValues = "import json,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:],ensure_ascii=False))";
  writeFileSync(playbook, `---
- hosts: localhost
  gather_facts: false
  become: false
  vars:
${vars}
  tasks:
    - name: Internal recovery flags remain strict booleans
      ansible.builtin.assert:
        that:
          - rollback_recovery_verified is boolean
          - rollback_recovery_verified == true
          - recovery_denied is boolean
          - recovery_denied == false
    - name: Observe values after actual Ansible templating
      ansible.builtin.command:
        argv:
          - /usr/bin/python3
          - -c
          - ${JSON.stringify(writeValues)}
          - ${JSON.stringify(outputFile)}
          - "{{ oval_config_json }}"
          - "{{ hcp_openscap_datastream }}"
          - "{{ user_value }}"
          - "{{ ansible_become_password }}"
      changed_when: false
`);
  for (const serializedConfig of [JSON.stringify(config), JSON.stringify(config).replaceAll("{{", "\\u007b\\u007b").replaceAll("}}", "\\u007d\\u007d")]) {
    const varsFile = path.join(directory, "vars.json");
    writeFileSync(varsFile, ansibleLiteralExtraVars({
      hcp_oval_config: serializedConfig, hcp_openscap_datastream: datastream,
      user_value: custom, ansible_become_password: password,
      rollback_recovery_verified: true, recovery_denied: false,
    }), { mode: 0o600 });
    execFileSync("ansible-playbook", ["-i", "localhost,", "-c", "local", playbook, "--extra-vars", `@${varsFile}`], {
      encoding: "utf8", timeout: 30_000,
      env: { ...process.env, ANSIBLE_LOCAL_TEMP: path.join(directory, "local-temp"), ANSIBLE_NOCOLOR: "1" },
    });
    const values = JSON.parse(readFileSync(outputFile, "utf8"));
    assert.deepEqual(JSON.parse(values[0]), config);
    assert.deepEqual(values.slice(1), [datastream, custom, password]);
    assert.equal(existsSync(marker), false, "no controller lookup may execute");
  }
});

test("invalid extra-var structures fail instead of becoming nested executable inputs", () => {
  assert.throws(() => ansibleLiteralExtraVars({ value: { __ansible_unsafe: "text" } }), /строковые/);
  assert.throws(() => ansibleLiteralExtraVars({ "bad key": "text" }), /имена/);
});

test("prepared OVAL validation proof remains JSON in the actual legacy and modern argv templates", () => {
  const production = readFileSync(path.join(webDir, "..", "ansible/playbooks/astra-oval-audit.yml"), "utf8");
  const variables = ["oval_config_value", "oval_settings", "oval_config_json"].map(name =>
    production.split("\n").find(line => line.startsWith("    " + name + ":"))).join("\n");
  const task = production.slice(production.indexOf("- name: Validate and evaluate OVAL locally on target"),
    production.indexOf("- name: Fetch normalized OVAL report"));
  const argument = name => {
    const lines = task.split("\n");const index = lines.findIndex(line => line.trim() === "- " + name);
    assert.ok(index >= 0);return lines[index + 1].trim().slice(2);
  };
  const proof = { sha256: "a".repeat(64), schemaExitCode: 0, schematronExitCode: 0, location: "control_node", validator: "OpenSCAP fixture" };
  const config = { mode: "online", sha256: proof.sha256, sourceName: "Fixture" };
  const capture = "import json,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))";
  const playbook = path.join(directory, "prepared-argv.yml"), output = path.join(directory, "prepared-argv.json");
  writeFileSync(playbook, ["---", "- hosts: localhost", "  gather_facts: false", "  vars:", variables,
    "    oval_download:", "      stdout: " + JSON.stringify(JSON.stringify({ sourceValidation: proof })),
    "  tasks:", "    - ansible.builtin.command:", "        argv:", "          - /usr/bin/python3",
    "          - -c", "          - " + JSON.stringify(capture), "          - " + JSON.stringify(output),
    "          - " + argument("--config"), "          - " + argument("--source-validation"), "      changed_when: false", ""].join("\n"));
  const varsFile = path.join(directory, "prepared-vars.json");
  const marker = path.join(directory, "proof-lookup-must-not-run");
  const literalProof = { ...proof, validator: "{{ lookup('ansible.builtin.pipe', 'touch " + marker + "') }}" };
  const cases = [
    { config, validation: proof, expected: proof },
    { config, validation: literalProof, expected: literalProof },
    { config, validation: null, expected: proof },
    { config: { ...config, mode: "local" }, validation: null, expected: {} },
  ];
  for (const item of cases) {
    writeFileSync(varsFile, ansibleLiteralExtraVars({ hcp_oval_config: JSON.stringify(item.config),
      hcp_oval_prepared_input: item.validation ? "/tmp/fixture-prepared.xml" : "",
      hcp_oval_source_validation: item.validation ? JSON.stringify(item.validation) : "" }), { mode: 0o600 });
    for (const binary of ["ansible-playbook", "/opt/hcp-tools/ansible-modern/bin/ansible-playbook"].filter(item => !item.startsWith("/") || existsSync(item))) {
      execFileSync(binary, ["-i", "localhost,", "-c", "local", playbook, "--extra-vars", "@" + varsFile], {
        timeout: 30_000, env: { ...process.env, ANSIBLE_LOCAL_TEMP: path.join(directory, "prepared-local"), ANSIBLE_NOCOLOR: "1" },
      });
      const values = JSON.parse(readFileSync(output, "utf8"));
      assert.deepEqual(JSON.parse(values[0]), item.config, binary);
      assert.deepEqual(JSON.parse(values[1]), item.expected, binary);
      assert.equal(existsSync(marker), false, "proof metadata must remain literal");
    }
  }
});
