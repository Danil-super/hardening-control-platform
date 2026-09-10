#!/usr/bin/env python3
"""Full official profile and controlled rule acceptance on disposable CI only.

The full run uses the original, checksum-pinned SSG datastream. A separate
six-rule profile reuses unchanged SSG rules for a small negative/restoration
test. A failing baseline control is a scan finding, not a failed test. Scanner
errors remain explicitly partial and are reported separately from compliance.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import xml.etree.ElementTree as ET


REPO = Path(__file__).resolve().parents[2]
PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"
CONTROL_PROFILE = "xccdf_org.hcp.content_profile_ci_six_rules"
HOST = "hcp-openscap-ci"
POLICY_GROUP = "ci-full-profile-acceptance"
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
CONTROL_RULE = RULE_PREFIX + "file_permissions_etc_passwd"
RULES = ["file_permissions_etc_passwd", "file_owner_etc_passwd",
         "file_groupowner_etc_passwd", "file_permissions_etc_shadow",
         "accounts_root_gid_zero", "accounts_no_uid_except_zero"]
XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"
IGNORED_RESULTS = {"notapplicable", "notselected", "informational"}
KNOWN_RESULTS = {"pass", "fail", "error", "unknown", "notchecked", *IGNORED_RESULTS, "fixed"}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o644)


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_runner(args):
    if not args.execute_on_disposable_runner or os.geteuid() != 0:
        raise RuntimeError("Requires root and --execute-on-disposable-runner.")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Refusing host permission changes outside a disposable GitHub-hosted VM.")
    release = Path("/etc/os-release").read_text()
    if not re.search(r'^ID=ubuntu$', release, re.M) or not re.search(r'^VERSION_ID="24\.04"$', release, re.M):
        raise RuntimeError("This acceptance procedure requires Ubuntu 24.04.")


def cleanup(work):
    recovery = work / "recovery.json"
    if not recovery.exists():
        return
    state = json.loads(recovery.read_text())
    if state.get("restored"):
        return
    path = Path("/etc/passwd")
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_ino != state["inode"] or checksum(path) != state["sha256"]:
        raise RuntimeError("/etc/passwd identity/content changed; refusing an ambiguous permission restore.")
    path.chmod(state["mode"])
    assert stat.S_IMODE(path.stat().st_mode) == state["mode"]
    state["restored"] = True
    write_json(recovery, state)
    write_json(work / "artifacts/cleanup.json", {"ok": True, "passwdMode": oct(state["mode"]), "contentsUnchanged": True})


def prepare(work):
    from lxml import etree

    original = work / "ssg-ubuntu2404-original-ds.xml"
    tree = etree.parse(str(original), etree.XMLParser(resolve_entities=False, no_network=True))
    benchmarks = tree.findall(f".//{XCCDF}Benchmark")
    assert len(benchmarks) == 1, "Expected exactly one benchmark in the official datastream"
    benchmark = benchmarks[0]
    profiles = benchmark.findall(f"{XCCDF}Profile")
    selected = [item for item in profiles if item.get("id") == PROFILE]
    assert len(selected) == 1, "Official CIS Level 1 Server profile is missing"
    all_rules = benchmark.findall(f".//{XCCDF}Rule")
    all_rule_ids = {item.get("id") for item in all_rules}
    assert len(all_rule_ids) == len(all_rules) and len(all_rules) > 100
    control_ids = {RULE_PREFIX + rule for rule in RULES}
    assert control_ids <= all_rule_ids
    for rule in all_rules:
        if rule.get("id") in control_ids:
            assert any(check.get("system") == "http://oval.mitre.org/XMLSchema/oval-definitions-5"
                       for check in rule.findall(f".//{XCCDF}check")), rule.get("id")
    # Only the separate negative/restoration content is tailored. The full
    # assessment always uses the exact original archive member, without --rule.
    profile = etree.Element(f"{XCCDF}Profile", id=CONTROL_PROFILE)
    etree.SubElement(profile, f"{XCCDF}title").text = "HCP controlled six-rule acceptance"
    etree.SubElement(profile, f"{XCCDF}description").text = "Negative and restored-state tests using unchanged official SSG rules."
    for rule in all_rules:
        etree.SubElement(profile, f"{XCCDF}select", idref=rule.get("id"),
                         selected="true" if rule.get("id") in control_ids else "false")
    benchmark.insert(benchmark.index(profiles[-1]) + 1, profile)
    controlled = work / "ssg-ubuntu2404-ci-six-rules-ds.xml"
    tree.write(str(controlled), encoding="UTF-8", xml_declaration=True)
    subprocess.run(["oscap", "ds", "sds-validate", str(original)], check=True, timeout=120)
    subprocess.run(["oscap", "ds", "sds-validate", str(controlled)], check=True, timeout=120)
    with (work / "artifacts/datastream-info.txt").open("w") as output:
        subprocess.run(["oscap", "info", str(original)], stdout=output, check=True, timeout=60)
    (work / "inventory.ini").write_text(f"[linux_hosts]\n{HOST} ansible_connection=local ansible_python_interpreter=/usr/bin/python3\n")
    provenance = {
        "scope": "full unmodified official CIS Level 1 Server profile on Ubuntu 24.04; separate six-rule negative/restoration checks",
        "source": f"https://github.com/ComplianceAsCode/content/releases/tag/v{os.environ['SSG_VERSION']}",
        "version": os.environ["SSG_VERSION"], "archiveSha256": os.environ["SSG_ARCHIVE_SHA256"],
        "originalDatastreamSha256": checksum(original), "profile": PROFILE,
        "profileTitle": selected[0].findtext(f"{XCCDF}title"),
        "controlDatastreamSha256": checksum(controlled), "controlProfile": CONTROL_PROFILE,
        "controlRuleIds": sorted(control_ids), "benchmarkRuleCount": len(all_rule_ids),
        "system": "Ubuntu 24.04 GitHub-hosted VM; no Astra compatibility claim",
    }
    write_json(work / "artifacts/provenance.json", provenance)
    return original, controlled, all_rule_ids, provenance


def run_audit(work, datastream, profile, phase, all_rule_ids, *, full=False):
    artifacts = work / "artifacts"
    reports = artifacts / "reports"
    variables = {
        "hcp_reports_dir": str(reports), "report_run_id": phase,
        "hcp_openscap_datastream": str(datastream), "hcp_openscap_profile": profile,
        "hcp_openscap_policy_group": POLICY_GROUP, "hcp_openscap_keep_arf": True,
    }
    var_path = work / f"vars-{phase}.json"
    write_json(var_path, variables)
    argv = ["ansible-playbook", "-i", str(work / "inventory.ini"),
            str(REPO / "ansible/playbooks/openscap-audit.yml"), "--limit", HOST,
            "-e", "@" + str(var_path)]
    # GNU timeout kills the entire process group, including a hung oscap. The
    # workflow's always() step also restores the controlled permission change.
    with (artifacts / f"playbook-{phase}.log").open("w") as output:
        result = subprocess.run(["timeout", "--signal=TERM", "--kill-after=15s",
                                 "1800s" if full else "240s", *argv], cwd=REPO,
                                stdout=output, stderr=subprocess.STDOUT,
                                env={**os.environ, "ANSIBLE_FORCE_COLOR": "false", "LC_ALL": "C.UTF-8"})
    if result.returncode:
        print((artifacts / f"playbook-{phase}.log").read_text()[-16000:])
        raise RuntimeError(f"Project playbook failed in {phase}: exit {result.returncode}")
    report_path = reports / f"{HOST}-openscap-{phase}.json"
    report = json.loads(report_path.read_text())
    raw_path = reports / f".{HOST}-openscap-{phase}.xml"
    assert raw_path.is_file(), "The actual raw ARF must be retained for independent comparison"
    # Use a visible artifact name; Actions deliberately excludes hidden files.
    arf_path = artifacts / f"{phase}.arf.xml"
    raw_path.rename(arf_path)
    tree = ET.parse(arf_path)
    results = tree.findall(f".//{XCCDF}TestResult")
    assert len(results) == 1, f"Expected one completed TestResult, got {len(results)}"
    test_result = results[0]
    assert test_result.get("end-time"), "OpenSCAP did not record completion"
    assert test_result.find(f"{XCCDF}profile").get("idref") == profile
    raw_rules = test_result.findall(f"{XCCDF}rule-result")
    raw_ids = {item.get("idref") for item in raw_rules}
    assert raw_ids == all_rule_ids, f"Raw result omitted benchmark rules: {all_rule_ids - raw_ids}"
    assert len(raw_rules) == len(raw_ids), "Unexpected duplicate rule results need explicit handling"
    pairs = [(item.get("idref"), item.findtext(f"{XCCDF}result", "").strip().lower()) for item in raw_rules]
    counts = Counter(status for _, status in pairs)
    assert counts.keys() <= KNOWN_RESULTS, counts
    scanner = report["scanner"]
    assert report["mode"] == "openscap" and report["inventoryHost"] == HOST
    assert scanner["available"] is True and scanner["scannerExitCode"] in (0, 2), scanner
    assert scanner["profile"] == profile and scanner["policyGroup"] == POLICY_GROUP
    assert scanner["datastream"] == str(datastream)
    assert scanner["datastreamChecksum"] == "sha256:" + checksum(datastream)
    assert float(scanner["datastreamLastModified"]) > 0
    assert scanner["ruleResultCounts"] == dict(counts), "Normalizer lost or changed raw results"
    expected_findings = Counter((identifier, status) for identifier, status in pairs if status not in IGNORED_RESULTS)
    actual_findings = Counter()
    for finding in report["findings"]:
        match = re.search(r"(?:^|;\s*)rule=([^;\s]+); result=([^;\s]+)", finding["evidence"])
        assert match, finding
        identifier, status = match.groups()
        actual_findings[(identifier, status)] += 1
        assert finding["source"] == "openscap"
        assert finding["status"] == ("passed" if status == "pass" else "failed" if status == "fail" else "manual")
    assert actual_findings == expected_findings, "Normalized findings differ from the actual raw ARF"
    selected = {identifier for identifier, status in pairs if status != "notselected"}
    if full:
        assert len(selected) > 100, "Expected the full official profile, not a small acceptance subset"
    else:
        assert selected == {RULE_PREFIX + rule for rule in RULES}
    manual = sum(counts[status] for status in counts if status not in {"pass", "fail", *IGNORED_RESULTS})
    assert scanner["partial"] is bool(manual), "Errors/manual checks must never become complete compliance"
    assert report["summary"]["total"] == sum(expected_findings.values())
    outcome = {
        "phase": phase, "profile": profile, "fullOfficialProfile": full,
        "selectedRules": len(selected), "benchmarkRules": len(raw_ids),
        "counts": dict(sorted(counts.items())), "scannerExitCode": scanner["scannerExitCode"],
        "partial": scanner["partial"], "normalizedMatchesRawArf": True,
        "arfSha256": checksum(arf_path),
    }
    write_json(artifacts / f"{phase}-acceptance.json", outcome)
    print(json.dumps(outcome, indent=2), flush=True)
    if manual:
        print(f"::warning::Full scan ran, but {manual} rules need manual review; report remains partial.", flush=True)
    return report, outcome


def control_finding(report):
    matches = [item for item in report["findings"] if item["id"] == "openscap_" + CONTROL_RULE]
    assert len(matches) == 1, "Expected one real file_permissions_etc_passwd result"
    return matches[0]


def verify_exception(work, report):
    path = work / "artifacts/exception-report.json"
    write_json(path, report)
    # Only external module dependencies are substituted. The production
    # selection/annotation, filesystem write, rename and idempotence run intact
    # against the real scanner report, with an explicit approved exception.
    program = r'''
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const root = process.argv[1];
const reportPath = process.argv[2];
const ruleId = process.argv[3];
const ts = require(path.join(root, "web/node_modules/typescript"));
const source = fs.readFileSync(path.join(root, "web/lib/openscap-policy.ts"), "utf8");
const code = ts.transpileModule(source, { compilerOptions: {
  target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true,
}}).outputText;
const stubs = {
  "@/lib/ansible-reports": { getReportsDir: () => path.dirname(reportPath) },
  "@/lib/inventory": {}, "@/lib/state-store": {},
};
const loaded = { exports: {} };
new Function("require", "module", "exports", code)(
  (name) => Object.hasOwn(stubs, name) ? stubs[name] : require(name), loaded, loaded.exports);
const before = JSON.parse(fs.readFileSync(reportPath, "utf8"));
const now = Date.now();
const approved = { id: "ci-real-failure", ruleId, groupName: "linux_hosts",
  reason: "Controlled CI permission violation, restored immediately after scanner verification",
  expiresAt: new Date(now + 3600000).toISOString() };
const args = { hostAlias: before.inventoryHost, reportId: path.basename(reportPath, ".json"),
  resolved: { groups: ["linux_hosts"], policy: null, source: "environment" },
  exceptions: [approved, { ...approved, id: "expired", expiresAt: new Date(now - 3600000).toISOString() },
    { ...approved, id: "unrelated", groupName: "unrelated" }] };
assert.equal(loaded.exports.applyOpenScapExceptions(args).applied, 1);
const first = fs.readFileSync(reportPath, "utf8");
const after = JSON.parse(first);
assert.deepEqual(after.summary, before.summary);
assert.deepEqual(after.scanner.ruleResultCounts, before.scanner.ruleResultCounts);
assert.equal(after.scanner.partial, before.scanner.partial);
assert.deepEqual(after.scanner.exceptionsApplied.map(item => item.id), [approved.id]);
assert.equal(after.findings.length, before.findings.length);
for (let i = 0; i < before.findings.length; i++) {
  const original = before.findings[i]; const annotated = after.findings[i];
  const { description: originalDescription, ...originalFields } = original;
  const { description: annotatedDescription, ...annotatedFields } = annotated;
  assert.deepEqual(annotatedFields, originalFields);
  if (original.id === "openscap_" + ruleId) {
    assert.equal(original.status, "failed"); assert.equal(annotated.status, "failed");
    assert.ok(annotatedDescription.includes(approved.reason));
  } else assert.equal(annotatedDescription, originalDescription);
}
assert.equal(loaded.exports.applyOpenScapExceptions(args).applied, 1);
assert.equal(fs.readFileSync(reportPath, "utf8"), first);
console.log(JSON.stringify({ ok: true, realFailedFinding: ruleId, exceptionPersisted: true,
  expiredAndUnrelatedIgnored: true, originalStatusRiskEvidenceAndTotalsPreserved: true,
  repeatedApplicationIdempotent: true }, null, 2));
'''
    result = subprocess.run(["node", "-e", program, str(REPO), str(path), CONTROL_RULE],
                            cwd=REPO, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"Production exception handling failed: {result.stdout}\n{result.stderr}")
    outcome = json.loads(result.stdout)
    write_json(work / "artifacts/exception-acceptance.json", outcome)
    print(json.dumps(outcome, indent=2), flush=True)
    return outcome


def verify(work):
    (work / "artifacts/reports").mkdir(parents=True, exist_ok=True)
    original, controlled, all_rule_ids, provenance = prepare(work)
    baseline, full_result = run_audit(work, original, PROFILE, "full-baseline", all_rule_ids, full=True)
    assert control_finding(baseline)["status"] == "passed", "Controlled rule must pass before introducing a violation"
    path = Path("/etc/passwd")
    details = path.lstat()
    assert stat.S_ISREG(details.st_mode), "/etc/passwd must be an ordinary file"
    original_mode = stat.S_IMODE(details.st_mode)
    assert not original_mode & stat.S_IXOTH
    write_json(work / "recovery.json", {"mode": original_mode, "inode": details.st_ino,
                                        "sha256": checksum(path), "restored": False})
    try:
        # Add only the execute bit for others. This violates the SSG maximum
        # mode without making the account database writable to another user.
        path.chmod(original_mode | stat.S_IXOTH)
        violated, negative_result = run_audit(work, controlled, CONTROL_PROFILE, "controlled-violation", all_rule_ids)
        failed = control_finding(violated)
        assert failed["status"] == "failed" and "result=fail" in failed["evidence"], failed
        assert violated["scanner"]["partial"] is False
        exception_result = verify_exception(work, violated)
    finally:
        cleanup(work)
    restored, restored_result = run_audit(work, controlled, CONTROL_PROFILE, "controlled-restored", all_rule_ids)
    assert control_finding(restored)["status"] == "passed"
    assert restored["scanner"]["partial"] is False
    outcome = {"ok": True, "scope": provenance["scope"], "fullProfile": full_result,
               "negativeControl": negative_result, "restoredControl": restored_result,
               "exception": exception_result,
               "limitation": "Only file_permissions_etc_passwd was deliberately perturbed; other baseline controls have no seeded accuracy test. Manual/error rules remain partial."}
    write_json(work / "artifacts/acceptance.json", outcome)
    print(json.dumps(outcome, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--execute-on-disposable-runner", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    require_runner(args)
    work = args.work_dir.resolve()
    if args.cleanup:
        cleanup(work)
        return
    verify(work)


if __name__ == "__main__":
    main()
