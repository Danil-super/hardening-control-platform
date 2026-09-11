#!/usr/bin/env python3
"""Real OpenSCAP engine and production playbook acceptance on disposable Ubuntu.

The original baseline must return notapplicable on Ubuntu. A separately named,
modified identity fixture exercises the rules against Ubuntu observations. It
is never represented as an Astra VM result. A temporary passwd-mode fixture
proves pass/fail/restoration through actual SCE and ARF, without changing host
configuration. No fixture switch exists in production check.py.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET


REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "ansible/scap/astra"
PROFILE = "xccdf_org.hcp_profile_astra_baseline"
BUILTIN = "/__hcp_builtin__/astra-baseline.xml"
RULE_PREFIX = "xccdf_org.hcp_rule_"
HOST = "hcp-astra-baseline-ci"
X = "{http://checklists.nist.gov/xccdf/1.2}"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def run(argv, output):
    process = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, timeout=360, env={**os.environ, "LC_ALL": "C.UTF-8",
                                                        "ANSIBLE_FORCE_COLOR": "false"})
    output.write_text(process.stdout)
    if process.returncode != 0:
        print(process.stdout[-16000:])
        raise RuntimeError("Command failed: %r (exit %s)" % (argv, process.returncode))
    return process


def raw_results(path):
    root = ET.parse(path).getroot()
    tests = root.findall(".//" + X + "TestResult")
    assert len(tests) == 1
    test = tests[0]
    assert test.get("end-time")
    assert test.find(X + "profile").get("idref") == PROFILE
    rows = test.findall(X + "rule-result")
    assert len(rows) == 18 and len({row.get("idref") for row in rows}) == 18
    results = {row.get("idref"): row.findtext(X + "result") for row in rows}
    evidence = {row.get("idref"): [entry.text or "" for entry in row.findall(".//" + X + "check-import")]
                for row in rows}
    for identifier, status in results.items():
        if identifier != RULE_PREFIX + "aslr" and status not in {"notapplicable", "notselected"}:
            assert any(entry.strip() for entry in evidence[identifier]), "Executed SCE stdout must be present in raw ARF"
    assert results.keys() == {node.get("id") for node in ET.parse(SOURCE / "astra-baseline.xml").findall(X + "Rule")}
    return results, evidence


def playbook(work, content, phase):
    reports = work / "artifacts/reports"
    variables = {
        "hcp_reports_dir": str(reports), "report_run_id": phase,
        "hcp_openscap_datastream": content, "hcp_openscap_profile": PROFILE,
        "hcp_openscap_policy_group": "ci-hcp-astra-baseline", "hcp_openscap_keep_arf": True,
    }
    var_path = work / (phase + ".json")
    write_json(var_path, variables)
    before = set(Path("/tmp").glob("hcp-openscap-*"))
    process = run(["ansible-playbook", "-i", str(work / "inventory.ini"),
                   str(REPO / "ansible/playbooks/openscap-audit.yml"),
                   "-e", "@" + str(var_path)], work / ("artifacts/" + phase + ".log"))
    assert process.returncode == 0
    assert set(Path("/tmp").glob("hcp-openscap-*")) == before, "Target temporary content was not cleaned"
    raw = reports / ("." + HOST + "-openscap-" + phase + ".xml")
    if not raw.is_file():
        print(process.stdout[-16000:])
        normalized = reports / (HOST + "-openscap-" + phase + ".json")
        if normalized.is_file():
            print(normalized.read_text()[:16000])
        diagnostics = Path(str(raw) + ".diagnostics.json")
        if diagnostics.is_file():
            print(diagnostics.read_text()[:36000])
            diagnostics.rename(work / ("artifacts/" + phase + ".diagnostics.json"))
        raise AssertionError("OpenSCAP did not produce ARF; inspect actual preparation/evaluation diagnostics above")
    visible = work / ("artifacts/" + phase + ".arf.xml")
    raw.rename(visible)
    report = json.loads((reports / (HOST + "-openscap-" + phase + ".json")).read_text())
    scanner = report["scanner"]
    results, evidence = raw_results(visible)
    assert scanner["ruleResultCounts"] == dict(Counter(results.values()))
    assert scanner["profile"] == PROFILE and scanner["datastream"] == content
    assert scanner["scannerExitCode"] in (0, 2)
    for finding in report["findings"]:
        identifier = finding["id"].removeprefix("openscap_")
        if identifier not in results:
            continue
        native = results[identifier]
        assert finding["status"] == ("passed" if native == "pass" else "failed" if native == "fail" else "manual")
        # The production adapter must preserve bounded SCE observation details.
        if identifier != RULE_PREFIX + "aslr" and native not in {"notapplicable", "notselected"}:
            assert any(fragment.strip() in finding["evidence"] for fragment in evidence[identifier] if fragment.strip()), finding
    if content == BUILTIN:
        evaluated = Path(str(raw) + ".datastream.xml")
        assert scanner["datastreamChecksum"] == "sha256:" + digest(evaluated)
        evaluated.rename(work / ("artifacts/" + phase + ".datastream.xml"))
    else:
        assert scanner["datastreamChecksum"] == "sha256:" + digest(Path(content))
    return report, results, evidence


def prepare_fixture(work):
    fixture = work / "identity-fixture"
    fixture.mkdir()
    shutil.copy2(SOURCE / "astra-baseline.xml", fixture / "astra-baseline.xml")
    shutil.copy2(SOURCE / "astra-cpe-dictionary.xml", fixture / "astra-cpe-dictionary.xml")
    identity = fixture / "os-release"
    identity.write_text('ID=astra\nVERSION_ID="controlled-identity-fixture-not-a-real-Astra-VM"\n')
    oval = ET.parse(SOURCE / "astra-platform-oval.xml")
    namespace = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
    variable = oval.find(namespace + "variables/" + namespace + "constant_variable")
    for value in variable.findall(namespace + "value"):
        variable.remove(value)
    ET.SubElement(variable, namespace + "value").text = str(identity)
    oval.write(fixture / "astra-platform-oval.xml", encoding="UTF-8", xml_declaration=True)
    passwd = fixture / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/sh\n")
    passwd.chmod(0o644)
    script = (SOURCE / "check.py").read_text()
    original = 'OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release")'
    assert script.count(original) == 1
    script = script.replace(original, "OS_RELEASE_PATHS = (%r,)" % str(identity))
    original_path = '"passwd_permissions": ("/etc/passwd", 0o644, False)'
    assert script.count(original_path) == 1
    script = script.replace(original_path, '"passwd_permissions": (%r, 0o644, False)' % str(passwd))
    (fixture / "check.py").write_text(script)
    (fixture / "check.py").chmod(0o700)
    run(["oscap", "xccdf", "validate", str(fixture / "astra-baseline.xml")], work / "artifacts/fixture-validation.log")
    stream = fixture / "fixture-ds.xml"
    run(["oscap", "ds", "sds-compose", str(fixture / "astra-baseline.xml"), str(stream)], work / "artifacts/fixture-compose.log")
    run(["oscap", "ds", "sds-add", str(fixture / "astra-cpe-dictionary.xml"), str(stream)], work / "artifacts/fixture-dictionary.log")
    run(["oscap", "ds", "sds-validate", str(stream)], work / "artifacts/fixture-ds-validation.log")
    return stream, passwd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Acceptance requires a disposable GitHub-hosted VM and root.")
    identity = Path("/etc/os-release").read_bytes()
    assert b"ID=ubuntu\n" in identity, "This is explicitly an Ubuntu engine acceptance."
    work = args.work_dir.resolve()
    (work / "artifacts/reports").mkdir(parents=True)
    (work / "inventory.ini").write_text("[linux_hosts]\n" + HOST + " ansible_connection=local ansible_python_interpreter=/usr/bin/python3\n")
    run(["oscap", "--version"], work / "artifacts/oscap-version.txt")
    run(["oscap", "xccdf", "validate", str(SOURCE / "astra-baseline.xml")], work / "artifacts/original-validation.log")
    run(["oscap", "oval", "validate", str(SOURCE / "astra-platform-oval.xml")], work / "artifacts/original-oval-validation.log")
    report, original, _ = playbook(work, BUILTIN, "original-ubuntu-notapplicable")
    assert set(original.values()) == {"notapplicable"}
    assert report["scanner"]["partial"] is True
    stream, passwd = prepare_fixture(work)
    _, baseline, evidence = playbook(work, str(stream), "identity-fixture-baseline")
    control = RULE_PREFIX + "passwd_permissions"
    assert baseline[control] == "pass"
    assert not {"notchecked", "error", "notselected"} & set(baseline.values())
    # Unavailable capabilities may be unknown/notapplicable. They are counted,
    # preserved and reported; no fixture converts scanner errors into pass.
    passwd.chmod(0o666)
    try:
        _, negative, _ = playbook(work, str(stream), "identity-fixture-permission-failure")
        assert negative[control] == "fail"
    finally:
        passwd.chmod(0o644)
    _, restored, _ = playbook(work, str(stream), "identity-fixture-restored")
    assert restored[control] == "pass"
    assert Path("/etc/os-release").read_bytes() == identity
    outcome = {
        "scope": "OpenSCAP/SCE and production playbook on Ubuntu; separate modified identity and temporary permission fixtures",
        "realAstraHostVerified": False, "vendorOrCisCertification": False,
        "originalContentSha256": digest(SOURCE / "astra-baseline.xml"), "originalCheckSha256": digest(SOURCE / "check.py"),
        "fixtureDatastreamSha256": digest(stream), "selectedRules": 18,
        "sceRules": 17, "nativeOvalRules": 1, "nativeCpeFamilyApplicability": True,
        "originalUbuntuCounts": dict(Counter(original.values())), "fixtureCounts": dict(Counter(baseline.values())),
        "permissionPassFailRestored": [baseline[control], negative[control], restored[control]],
        "nativeAndHcpResultsMatch": True, "compiledScriptCoveredByDatastreamChecksum": True,
        "targetTemporaryDirectoriesCleaned": True, "hostIdentityUnchanged": True,
    }
    write_json(work / "artifacts/acceptance.json", outcome)
    print(json.dumps(outcome, indent=2))


if __name__ == "__main__":
    main()
