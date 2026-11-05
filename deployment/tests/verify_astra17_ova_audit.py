#!/usr/bin/env python3
"""Real HCP Ansible and 18-rule SCAP verification on a disposable native Astra OVA.

Only called from the explicitly enabled native CI mode AFTER verified real
guest SSH identity. All original ARF, datastream, key, machine-id and Ansible
logs remain in private RUNNER_TEMP, never in public artifacts. A restored rule
state does NOT establish a complete OS/firewall rollback.
"""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import stat

from verify_astra_vm import PROFILE, RULE, raw_results, verify_baseline_report

ROOT = Path(__file__).resolve().parents[2]
HOST = "hcp-real-astra"
PHASES = ("baseline", "violation", "restored")
SCAP_RULE_COUNT = 18


def demand(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def file_sha256(path):
    hashed = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1048576), b""):
            hashed.update(block)
    return hashed.hexdigest()


def load_private_json(path, limit=32 * 1024 * 1024):
    st = path.lstat()
    demand(path.is_file() and not path.is_symlink()
           and 0 < st.st_size <= limit, "original_report_missing_or_unbounded")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_native_three_stage(results):
    """Exact source-scope rule states; no missing, unknown or extra rules."""
    demand(type(results) is dict and set(results) == set(PHASES),
           "three_stage_phase_set_invalid")
    raw = [results[phase] for phase in PHASES]
    for observed in raw:
        demand(type(observed) is dict and len(observed) == SCAP_RULE_COUNT,
               "incomplete_native_18_rule_scope")
        demand(all(isinstance(x, str) and x.startswith("xccdf_org.hcp_rule_")
                   and status in ("pass", "fail")
                   for x, status in observed.items()),
               "native_rules_partial_or_unknown")
    demand(set(raw[0]) == set(raw[1]) == set(raw[2]),
           "rule_identity_drift")
    demand(RULE in raw[0] and
           [observed[RULE] for observed in raw] == ["pass", "fail", "pass"],
           "controlled_rule_did_not_flip")
    demand(raw[0] == raw[2], "restored_rules_differ_from_baseline")
    demand(all(raw[0][key] == raw[1][key] for key in raw[0] if key != RULE),
           "uncontrolled_rule_status_changed")
    counts = {}
    for phase, report in zip(PHASES, raw):
        counted = Counter(report.values())
        counts[phase] = {"passed": counted["pass"], "failed": counted["fail"]}
        demand(counts[phase]["passed"] + counts[phase]["failed"] == SCAP_RULE_COUNT,
               "native_rule_count_invalid")
    demand(counts["violation"]["failed"] == counts["baseline"]["failed"] + 1,
           "incorrect_one_rule_delta")
    return {
        "testedRules": SCAP_RULE_COUNT,
        "status": "same-18-rule-statuses-observed",
        "oneControlledPassedToFailed": True,
        "restoredMatchesBaseline18Rules": True,
        "counts": counts,
        "fullOsRollbackProven": False,
        "cveCoverageProven": False,
    }



def native_openscap_failure_observation(raw_arf, datastream, normalized):
    """Classify HCP/OpenSCAP prerequisites without exposing private evidence.

    The actual 1.7 guest can return a successful *playbook* whose own report
    says unavailable/partial; never treat an absent ARF as native acceptance.
    Only strictly known enums, booleans and small numeric return codes leave
    the runner. No scanner reason, stderr, raw XML or paths are returned.
    """
    def regular(path, limit):
        try:
            st = path.lstat()
            return stat.S_ISREG(st.st_mode) and st.st_size > 0 and st.st_size <= limit
        except OSError:
            return False
    report_exists = regular(normalized, 32 * 1024 * 1024)
    observation = {
        "rawArfPresent": regular(raw_arf, 64 * 1024 * 1024),
        "executedDatastreamPresent": regular(datastream, 64 * 1024 * 1024),
        "normalizedReportPresent": report_exists,
        "reportedScannerAvailable": None, "reportedPartial": None,
        "reportedScannerExitCode": None,
        "normalizedFindingCount": None,
        "preparationExitCodes": {},
        "reasonCategories": [],
        "status": "native-openscap-original-evidence-incomplete",
    }
    if not report_exists:
        return observation
    try:
        report = load_private_json(normalized)
    except (OSError, ValueError, UnicodeError, RuntimeError):
        observation["reasonCategories"] = ["normalized_report_unreadable"]
        return observation
    if type(report) is not dict or report.get("mode") != "openscap":
        observation["reasonCategories"] = ["report_scope_invalid"]
        return observation
    scanner = report.get("scanner")
    if type(scanner) is not dict:
        observation["reasonCategories"] = ["scanner_metadata_missing"]
        return observation
    for origin, target in (("available", "reportedScannerAvailable"),
                           ("partial", "reportedPartial")):
        if type(scanner.get(origin)) is bool:
            observation[target] = scanner[origin]
    code = scanner.get("scannerExitCode")
    if type(code) is int and -1 <= code <= 255:
        observation["reportedScannerExitCode"] = code
    findings = report.get("findings")
    if type(findings) is list and len(findings) <= 1000:
        observation["normalizedFindingCount"] = len(findings)
    # Read private reasons transiently; classify on the runner with fixed
    # patterns. Never return original strings/hostnames/URLs/commands.
    candidates = []
    for entry in (scanner.get("reason"), scanner.get("partialReasons")):
        if type(entry) is str:
            candidates.append(entry[:4096])
        elif type(entry) is list:
            candidates.extend(s[:2048] for s in entry[:8] if type(s) is str)
    for item in findings[:8] if type(findings) is list else []:
        if type(item) is dict:
            for key in ("description", "evidence"):
                value = item.get(key)
                if type(value) is str:
                    candidates.append(value[:1024])
    joined = "\n".join(candidates)[:16000]
    for key in ("compose", "dictionary", "validation"):
        match = re.search(r"(?:^|[^A-Za-z])" + key + r"=(-?[0-9]{1,3})\b", joined)
        if match:
            value = int(match.group(1))
            if -1 <= value <= 255:
                observation["preparationExitCodes"][key] = value
    patterns = {
        "sds_compose_failed": r"(?:compose=[1-9]|sds-compose|sds compose)",
        "sds_dictionary_failed": r"(?:dictionary=[1-9]|sds-add)",
        "sds_validation_failed": r"(?:validation=[1-9]|sds-validate|schema validation)",
        "sce_plugin_unavailable": r"(?:SCE[^.\n]{0,100}(?:not available|not found|missing|disabled|не найден|отсутств)|script check engine[^.\n]{0,80}(?:not|missing))",
        "openscap_unsupported_command": r"(?:Unknown command|Unrecognized option|Invalid option|Unknown option|unsupported operation)",
        "openscap_xml_invalid": r"(?:invalid XML|XML validation|schema.*failed|not valid according to)",
        "openscap_missing_file": r"(?:No such file or directory|cannot open file|file not found)",
        "openscap_permission_issue": r"(?:Permission denied|Operation not permitted|отказано в доступе)",
        "openscap_profile_missing": r"(?:Profile[^.\n]{0,100}(?:not found|unknown|не найден))",
        "openscap_missing_binary": r"(?:oscap не установлен|oscap: command not found)",
        "openscap_report_partial": r"(?:unable to parse ARF|не удалось прочитать XML|ошибка OpenSCAP|OpenSCAP.*error)",
    }
    observation["reasonCategories"] = sorted(
        key for key, expression in patterns.items()
        if re.search(expression, joined, re.IGNORECASE))
    return observation


def safe_ansible_ssh_args(pinned_hosts):
    """Preserve Git-managed host trust even when ansible.cfg sets ssh_args.

    OpenSSH honours the FIRST occurrence of many -o settings. HCP's
    ansible.cfg may otherwise choose ~/.ssh/known_hosts before the per-host
    ansible_ssh_common_args, making pinned local disposable SSH fail.
    """
    pinned_hosts = Path(pinned_hosts)
    info = pinned_hosts.lstat()
    demand(stat.S_ISREG(info.st_mode) and not pinned_hosts.is_symlink()
           and not (info.st_mode & 0o077), "ansible_ssh_pin_unsafe")
    return shlex.join([
        "-F", "/dev/null",
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(pinned_hosts),
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "ConnectTimeout=10",
    ])


def classify_ansible_failure(log):
    """Bounded, fixed-code diagnostic. Never return raw Ansible log text."""
    patterns = {
        "ssh_host_key_verification": r"Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED",
        "ssh_authentication_failed": r"Permission denied \(publickey|Authentication failed",
        "ssh_unreachable": r"UNREACHABLE!|Connection timed out|Connection refused|No route to host",
        "sudo_escalation_failed": r"sudo: a password is required|Missing sudo password|Incorrect sudo password|Failed to become",
        "target_python_unavailable": r"Python interpreter discovery|/usr/bin/python3: not found|ModuleNotFoundError",
        "remote_ansible_module_failed": r"MODULE FAILURE|FAILED!|FAILED! =>|module_stdout",
        "controller_ansible_config_failed": r"ERROR!|Unable to parse|AnsibleError",
        "python_syntax_or_version_failure": r"SyntaxError|invalid syntax|future feature|requires Python",
        "ansible_remote_tmp_failure": r"Failed to create temporary directory|remote_tmp|Failed to transfer file|Could not create remote file",
        "ansible_remote_command_failed": r"fatal: \[|FAILED\s*=>|Failed to execute",
        "ansible_module_payload_failure": r"Failed to import|No module named|AnsiballZ|Module result deserialization failed",
        "ansible_empty_module_response": r"No start of json char found|No JSON object could be decoded",
    }
    try:
        path = Path(log)
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > 16 * 1024 * 1024:
            return ["private_ansible_log_unavailable"]
        with path.open("rb") as stream:
            stream.seek(max(0, meta.st_size - 131072))
            data = stream.read(131072).decode("utf-8", "replace")
    except (OSError, UnicodeError):
        return ["private_ansible_log_unavailable"]
    return sorted(k for k, regex in patterns.items()
                  if re.search(regex, data, re.IGNORECASE))


def upstream_ansible_target_range(core_minor):
    """Documented managed-node Python3 support, not a heuristic OS version."""
    return {
        12: (5, 10), 13: (5, 10), 14: (5, 11), 15: (5, 11),
        16: (6, 12), 17: (7, 12), 18: (8, 13), 19: (8, 13),
        20: (9, 14), 21: (9, 14),
    }.get(core_minor)


def check_ansible_runtime_support(native_ssh, protocol):
    """Only report numeric versions; fail closed outside published support."""
    cmd = ("python3 -c " +
           shlex.quote("import sys; print('%d.%d' % sys.version_info[:2])"))
    try:
        python_version = native_ssh(cmd, timeout=30).strip()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        raise RuntimeError("native_guest_python_version_unavailable")
    demand(re.fullmatch(r"3\.(?:[0-9]|1[0-9])", python_version),
           "native_guest_python_version_invalid")
    match = re.fullmatch(r"3\.(\d{1,2})", python_version)
    python_minor = int(match.group(1))
    try:
        result = subprocess.run(
            ["ansible-playbook", "--version"], capture_output=True,
            text=True, check=False, timeout=20)
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise RuntimeError("ansible_controller_version_unavailable")
    match = re.search(r"ansible-playbook\s+\[core\s+(2\.\d{1,2}(?:\.\d+)?)\]",
                      result.stdout[:2048])
    demand(result.returncode == 0 and match is not None,
           "ansible_controller_version_invalid")
    observed_core_version = match.group(1)
    core_minor = int(observed_core_version.split(".")[1])
    lab_pin = os.environ.get("HCP_ASTRA17_CI_ANSIBLE_PIN")
    if lab_pin is not None:
        demand(lab_pin == "2.17.14" and
               os.environ.get("GITHUB_ACTIONS") == "true" and
               os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
               "lab_only_ansible_pin_context_invalid")
        path = shutil.which("ansible-playbook")
        expected = (Path(os.environ["RUNNER_TEMP"]) /
                    "hcp-astra17-ansible217/bin/ansible-playbook")
        demand(path is not None and Path(path).resolve() == expected.resolve(),
               "lab_ansible_binary_not_isolated")
        demand(observed_core_version == lab_pin,
               "lab_ansible_version_not_pinned")
    bounds = upstream_ansible_target_range(core_minor)
    proof = {
        "targetPython": python_version,
        "ansibleCore": "2.%d" % core_minor,
        "ansibleCoreExactVersion": observed_core_version,
        "isolatedLabAnsibleVersionPinVerified": bool(lab_pin),
        "labOnlyUnsupportedAnsibleEol": bool(lab_pin and core_minor == 17),
        "upstreamTargetPythonRangeRecognized": bounds is not None,
        "targetWithinUpstreamSupportedRange": (
            bounds is not None and bounds[0] <= python_minor <= bounds[1]),
        "upstreamMatrixIsNotRuntimeSuccessProof": True,
    }
    protocol["nativeHcp"]["pythonAnsibleCompatibility"] = proof
    demand(bounds is not None, "unsupported_ansible_core_version_unknown")
    demand(bounds[0] <= python_minor <= bounds[1],
           "target_python_outside_upstream_ansible_support")
    return proof


def native_ansible_transport_preflight(work, protocol):
    """Separate SSH, Python-module and sudo stages without raw-log disclosure."""
    inventory = str(work / "private-inventory.json")
    opts = safe_ansible_ssh_args(work / "known_hosts")
    stages = (
        ("ssh_raw", "ansible.builtin.raw", "true", False),
        ("python_module", "ansible.builtin.ping", "", False),
        ("privileged_python_module", "ansible.builtin.ping", "", True),
    )
    protocol["nativeHcp"]["ansibleTransportStages"] = []
    for stage, module, args, become in stages:
        cmd = ["ansible", "-i", inventory, HOST, "-m", module,
               "-e", "ansible_become=" + ("true" if become else "false")]
        if args:
            cmd.extend(["-a", args])
        logfile = work / ("private-transport-" + stage + ".log")
        with logfile.open("wb") as sink:
            try:
                result = subprocess.run(
                    cmd, stdout=sink, stderr=subprocess.STDOUT, timeout=90,
                    check=False, env={**os.environ,
                        "ANSIBLE_HOST_KEY_CHECKING": "True",
                        "ANSIBLE_SSH_ARGS": opts})
            except (OSError, subprocess.TimeoutExpired):
                protocol["nativeHcp"]["ansibleTransportFailedAt"] = stage
                raise RuntimeError("ansible_transport_probe_unavailable")
        if result.returncode != 0:
            protocol["nativeHcp"]["ansibleTransportFailedAt"] = stage
            protocol["nativeHcp"]["ansibleFailureClass"] = classify_ansible_failure(logfile)
            protocol["nativeHcp"]["ansibleFailureReturnCode"] = result.returncode
            raise RuntimeError("ansible_transport_probe_failed")
        protocol["nativeHcp"]["ansibleTransportStages"].append(stage)
    protocol["nativeHcp"]["ansibleTransportComplete"] = True


def run_playbook(work, reports, name, phase, variables, protocol):
    protocol["nativeHcp"]["stage"] = name + ":" + phase
    args = work / ("private-vars-" + phase + ".json")
    args.write_text(json.dumps({
        "hcp_reports_dir": str(reports), "report_run_id": phase, **variables
    }))
    args.chmod(0o600)
    command = ["ansible-playbook", "-i", str(work / "private-inventory.json"),
               str(ROOT / "ansible" / "playbooks" / (name + ".yml")),
               "-e", "@" + str(args)]
    logs = work / ("private-ansible-" + phase + ".log")
    # Explicit early SSH option prevents ansible.cfg's ~/.ssh/known_hosts
    # from overriding this private, first-connected disposable guest pin.
    args_ssh = safe_ansible_ssh_args(work / "known_hosts")
    with logs.open("wb") as sink:
        try:
            task = subprocess.run(
                command, stdout=sink, stderr=subprocess.STDOUT,
                check=False, timeout=1200,
                env={**os.environ,
                     "ANSIBLE_HOST_KEY_CHECKING": "True",
                     "ANSIBLE_SSH_ARGS": args_ssh})
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("ansible_execution_unavailable")
    if task.returncode != 0:
        protocol["nativeHcp"]["ansibleFailureClass"] = classify_ansible_failure(logs)
        protocol["nativeHcp"]["ansibleFailedStep"] = name
        protocol["nativeHcp"]["ansibleFailureReturnCode"] = task.returncode
        # Never upload/echo raw ansible commands, stdout, stderr or IPs.
        raise RuntimeError("ansible_playbook_failed")


def run_native_audit(work, protocol, *, port, known_hosts, ssh_options,
                     password, original_identity, observation,
                     safe_command, parse_identity):
    """Uses actual HCP playbooks and original scanner outputs on the owned VM."""
    protocol["nativeHcp"] = {
        "stage": "initial", "status": "running",
        "realFactsCollected": False, "realPackageInventoryCollected": False,
        "real18RuleThreeStageObserved": False, "fullOvalEvaluated": False,
        "productionHcpEnrollmentPerformed": False,
        "rawArfPublished": False, "realHostFirewallChanged": False,
    }
    def stage(label):
        protocol["nativeHcp"]["stage"] = label
        print("NATIVE HCP STAGE: " + label, flush=True)

    stage("disposable_ssh_key_enrollment")
    key = work / "ci-host-client"
    safe_command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                  "-f", str(key)], timeout=30)
    key.chmod(0o600)
    pub = (work / "ci-host-client.pub").read_text(encoding="ascii").strip()
    demand(pub.startswith("ssh-ed25519 ") and len(pub) < 2000,
           "new_ephemeral_public_key_invalid")

    # One password bootstrap against the owned disposable factory guest;
    # do NOT use this for real customer enrollment or change sudoers.
    install_key = (
        "set -eu; umask 077; mkdir -p \"$HOME/.ssh\"; "
        "chmod 700 \"$HOME/.ssh\"; "
        "touch \"$HOME/.ssh/authorized_keys\"; "
        "chmod 600 \"$HOME/.ssh/authorized_keys\"; "
        "printf '%s\\n' " + shlex.quote(pub) +
        " >> \"$HOME/.ssh/authorized_keys\""
    )
    safe_command(["sshpass", "-f", str(password), "ssh",
                  *ssh_options, "astra@127.0.0.1", install_key], timeout=35)
    key_opts = [
        "-F", "/dev/null", "-i", str(key), "-p", str(port),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(known_hosts),
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "UpdateHostKeys=no", "-o", "ConnectTimeout=10",
    ]
    def native_ssh(command, timeout=45):
        return safe_command(["ssh", *key_opts, "astra@127.0.0.1",
                             command], timeout=timeout)

    observed = native_ssh(observation)
    demand(observed == original_identity, "native_identity_changed_after_key_enrollment")
    demand(parse_identity(observed)["osId"] == "astra",
           "native_ssh_asset_identity_unverified")
    native_ssh("sudo -n true", timeout=25)
    protocol["nativeHcp"]["perHostEphemeralKeyVerified"] = True

    inventory = {
        "linux_hosts": {"hosts": {HOST: {
            "ansible_host": "127.0.0.1",
            "ansible_port": port,
            "ansible_user": "astra",
            "ansible_become": True,
            "ansible_become_method": "sudo",
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": str(key),
            "ansible_ssh_common_args": shlex.join([
                "-F", "/dev/null", "-o", "BatchMode=yes",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + str(known_hosts),
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "HostKeyAlgorithms=ssh-ed25519",
                "-o", "UpdateHostKeys=no",
            ]),
        }}}}
    inventory_file = work / "private-inventory.json"
    inventory_file.write_text(json.dumps(inventory), encoding="utf-8")
    inventory_file.chmod(0o600)
    reports = work / "private-native-reports"
    reports.mkdir(mode=0o700)

    stage("native_ansible_and_python_compatibility")
    check_ansible_runtime_support(native_ssh, protocol)
    stage("native_ansible_ssh_module_and_sudo_transport")
    native_ansible_transport_preflight(work, protocol)
    stage("real_ansible_facts")
    run_playbook(work, reports, "collect-facts", "facts", {}, protocol)
    facts_file = reports / (HOST + "-facts-facts.json")
    facts = load_private_json(facts_file)
    demand(facts.get("inventoryHost") == HOST
           and "astra" in str(facts.get("os", "")).lower()
           and facts.get("architecture") == "x86_64",
           "native_ansible_facts_not_astra")
    protocol["nativeHcp"]["realFactsCollected"] = True
    protocol["nativeHcp"]["factsSha256"] = file_sha256(facts_file)

    stage("real_package_inventory")
    run_playbook(work, reports, "package-inventory", "packages", {}, protocol)
    package_file = reports / (HOST + "-packages-packages.json")
    packages = load_private_json(package_file)
    demand(packages.get("inventoryHost") == HOST
           and "astra" in str(packages.get("os", "")).lower()
           and isinstance(packages.get("packages"), list)
           and len(packages["packages"]) > 0,
           "native_installed_packages_missing")
    protocol["nativeHcp"]["realPackageInventoryCollected"] = True
    protocol["nativeHcp"]["installedPackageCount"] = len(packages["packages"])
    protocol["nativeHcp"]["packageReportSha256"] = file_sha256(package_file)

    stage("native_openscap_capability")
    try:
        native_ssh("command -v oscap", timeout=25)
    except RuntimeError:
        # Installation is strictly limited to the isolated CI guest. If the
        # real vendor repositories are not usable, fail and record that scope.
        stage("native_openscap_install_on_disposable_vm")
        native_ssh("sudo -n apt-get update -o Acquire::Retries=2",
                   timeout=900)
        native_ssh(
            "if apt-cache show openscap-scanner >/dev/null 2>&1; "
            "then sudo -n apt-get install -y --no-install-recommends openscap-scanner; "
            "else sudo -n apt-get install -y --no-install-recommends libopenscap8; fi",
            timeout=900)
    oscap_about = native_ssh("oscap --version", timeout=30)
    protocol["nativeHcp"]["nativeOpenScapBinaryVerified"] = True
    # Informative only: the engine string varies between native packages.
    # Missing wording must not be treated as evidence of disabled SCE.
    protocol["nativeHcp"]["sceMentionedInOpenScapAbout"] = (
        bool(re.search(r"\bSCE\b|Script Check Engine", oscap_about,
                       re.IGNORECASE)))

    protocol["nativeHcp"]["controllerSideSdsSchemaValidationRequested"] = True
    stage("18_rule_three_stage_experiment")
    original = native_ssh("stat -c '%a' /etc/passwd", timeout=25).strip()
    demand(re.fullmatch(r"[0-7]{3,4}", original)
           and (int(original, 8) & 0o001) == 0,
           "passwd_mode_not_suitable_for_safe_control")
    observed_rules = {}
    evidence = {}
    try:
        for phase in PHASES:
            if phase == "violation":
                native_ssh("sudo -n chmod o+x /etc/passwd")
            if phase == "restored":
                native_ssh("sudo -n chmod " + shlex.quote(original)
                           + " /etc/passwd")
            stage("original_hcp_openscap_" + phase)
            run_playbook(work, reports, "openscap-audit", phase, {
                "hcp_openscap_datastream": "/__hcp_builtin__/astra-baseline.xml",
                "hcp_openscap_profile": PROFILE,
                "hcp_openscap_policy_group": "ci-real-astra17-ova",
                "hcp_openscap_keep_arf": True,
                # Source composition and strict XSD validation happen on the
                # controller, not on this older Astra OpenSCAP build. The
                # *exact* compiled bytes must match target SHA before eval.
                "hcp_openscap_compose_on_controller": True,
            }, protocol)
            raw = reports / ("." + HOST + "-openscap-" + phase + ".xml")
            datastream = Path(str(raw) + ".datastream.xml")
            report_file = reports / (HOST + "-openscap-" + phase + ".json")
            if not (raw.is_file() and datastream.is_file()
                    and report_file.is_file()):
                protocol["nativeHcp"]["failedNativeStage"] = (
                    "original_hcp_openscap_" + phase)
                protocol["nativeHcp"]["openscapFailureObservation"] = (
                    native_openscap_failure_observation(
                        raw, datastream, report_file))
                raise RuntimeError("native_openscap_original_evidence_missing")
            xccdf, sce = raw_results(raw)
            normal = load_private_json(report_file)
            verify_baseline_report(
                normal, xccdf, sce, file_sha256(datastream))
            observed_rules[phase] = xccdf
            evidence[phase] = {
                "rawArfSha256": file_sha256(raw),
                "executedDatastreamSha256": file_sha256(datastream),
                "normalizedJsonSha256": file_sha256(report_file),
                "sourceBundleIdentity": normal["scanner"].get("contentIdentity"),
            }
    finally:
        # If the guest is unavailable this raises and the entire CI remains
        # FAIL. No return path claims restoration from a failed SSH operation.
        stage("restore_original_passwd_mode")
        protocol["nativeHcp"]["originalModeRestoreAttempted"] = True
        native_ssh("sudo -n chmod " + shlex.quote(original) + " /etc/passwd")
        restored_mode = native_ssh("stat -c '%a' /etc/passwd").strip()
        demand(restored_mode == original, "passwd_original_mode_not_restored")
        protocol["nativeHcp"]["originalModeRestoredVerified"] = True

    stage("source_scope_and_restoration_verification")
    actual_mode = native_ssh("stat -c '%a' /etc/passwd").strip()
    demand(actual_mode == original, "passwd_original_mode_not_restored")
    demand(native_ssh(observation) == original_identity,
           "native_asset_identity_changed_after_restore")
    rules = validate_native_three_stage(observed_rules)
    bundle = [evidence[p]["sourceBundleIdentity"] for p in PHASES]
    demand(all(isinstance(x, str) and
               re.fullmatch(r"bundle-sha256:[a-f0-9]{64}", x) for x in bundle)
           and len(set(bundle)) == 1, "source_bundle_not_stable")
    protocol["nativeHcp"].update({
        "stage": "complete",
        "status": "native-18-rule-three-stage-observed",
        "real18RuleThreeStageObserved": True,
        "scope": "exact-HCP-Astra-18-rules-one-native-1.7.6.15-base",
        "ruleMeasurements": rules,
        "sourceBundleIdentity": bundle[0],
        "phaseEvidenceSha256": evidence,
        "freshSshSameGuestAfterRestore": True,
        "originalPasswdModeRestored": True,
        "fullOvalEvaluated": False,
        "productionHcpEnrollmentPerformed": False,
        "entireOsRollbackProven": False,
    })
    protocol["checks"].append("native_astra17_hcp_three_stage_18_rule_measured")
    print("NATIVE HCP STAGE: complete original 18-rule observation", flush=True)
