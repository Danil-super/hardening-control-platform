#!/usr/bin/env python3
"""Boot the REAL pinned Astra SE 1.7.6.UU2 cloud-init VM on a disposable runner.

No synthetic OS identity, emulated reports or invented OVAL values. The control
is limited to the built-in 18-rule HCP baseline and one exact Astra 1.7 OVAL XML.
All SSH keys and raw machine-id stay in the private CI working directory.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import subprocess
import time
import xml.etree.ElementTree as ET

from verify_astra_vm import (
    download, run, write_json, raw_results, verify_baseline_report,
    record_failure, PROFILE, RULE,
)
from verify_astra_17_experiment import EXPECTED_RELEASE

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "deployment/astra-vm/sources-17.json"
HOST = "hcp-real-astra"
NS_DEFINITION = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition"


def classify_private_cloud_init_errors(output):
    """Return only known machine-generated module names; never private log text."""
    accepted = {
        "users_groups", "ssh", "set_hostname", "update_hostname",
        "update_etc_hosts", "growpart", "resizefs", "mounts",
        "package_update_upgrade_install", "runcmd", "scripts_user",
        "scripts_per_boot", "scripts_per_instance", "scripts_per_once",
        "final_message", "phone_home", "ssh_import_id", "network",
        "write_files", "timezone", "locale",
    }
    names = set(re.findall(r"'([a-z][a-z0-9_]{1,70})'\s*,", output))
    stage_failures = re.findall(
        r"finish:\s+[-a-z0-9_]+/config-([a-z0-9_-]+):\s+FAIL",
        output, flags=re.IGNORECASE)
    names.update(name.replace("-", "_").lower() for name in stage_failures)
    return sorted(names & accepted)


def full_oval_definition_count(path):
    # Stream a genuine XML source, not a hand-picked vulnerability excerpt.
    count = 0
    for _, element in ET.iterparse(str(path), events=("end",)):
        if element.tag == NS_DEFINITION:
            count += 1
        element.clear()
    assert count > 0, "Full Astra 1.7 OVAL must contain real definitions"
    return count


def verify_native_oval_report(report, source, count):
    scanner = report.get("scanner")
    assert report.get("mode") == "astra-oval" and isinstance(scanner, dict)
    identity = scanner.get("hostIdentity")
    assert isinstance(identity, dict) and identity.get("id") == "astra"
    assert identity.get("astraVersion") == EXPECTED_RELEASE
    database = scanner.get("database")
    assert isinstance(database, dict)
    assert database.get("sha256") == source["sha256"]
    assert database.get("checksumVerified") is True
    assert scanner.get("available") is True
    assert scanner.get("evaluationPerformed") is True, scanner.get("partialReasons")
    assert type(scanner.get("exitCode")) is int and scanner["exitCode"] in (0, 2)
    assert scanner.get("definitionCount") == count
    assert scanner.get("evaluatedDefinitionCount") == count
    results = scanner.get("definitionResults")
    assert isinstance(results, list) and len(results) == count
    assert len({r.get("id") for r in results if isinstance(r, dict)}) == count
    assert scanner.get("partial") is False and report.get("partial") is not True, scanner.get("partialReasons")
    assert report.get("summary", {}).get("score") is None
    return {"definitions": count, "evaluated": count,
            "partial": False, "sourceSha256": source["sha256"],
            "sourcePublisherSignatureIndependent": False,
            "fullCveRecallVerified": False}


def execute(args, work, artifacts, reports, sources, protocol):
    image = sources["images"][args.level]
    oval = sources["oval"]

    def checkpoint(name, detail):
        protocol["checks"].append({"name": name, "detail": detail})
        write_json(artifacts / "protocol.json", protocol)
        print("PASS: " + name, flush=True)

    write_json(artifacts / "protocol.json", protocol)
    cache_string = os.environ.get("HCP_ASTRA17_IMAGE_CACHE_DIR", "")
    cache_file = None
    if cache_string:
        cache_root = Path(cache_string).resolve()
        runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
        assert cache_root != runner_temp and cache_root.is_relative_to(runner_temp)
        cache_file = cache_root / "source.qcow2"
    download(image, work / "source.qcow2", max_seconds=2400,
             cache_path=cache_file)
    metadata = json.loads(run(["qemu-img", "info", "--output=json",
                               str(work / "source.qcow2")]).stdout)
    assert metadata["format"] == "qcow2" and not metadata.get("backing-filename")
    assert 2 * 1024**3 < metadata["virtual-size"] <= 50 * 1024**3
    checkpoint("Official fixed Astra 1.7.6.UU2 image bytes match source catalog",
               {"sourceSha256": image["sha256"], "bytes": image["bytes"],
                "levelCandidate": args.level, "publisherSignatureVerified": False})

    for name in ("client", "server"):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / name)])
    user_data = {
        "hostname": HOST,
        "ssh_pwauth": False,
        "disable_root": True,
        "users": ["default", {
            "name": "hcp-ci", "groups": ["astra-admin"],
            "sudo": "ALL=(ALL) NOPASSWD:ALL", "lock_passwd": True,
            "parsec_user_max_ilev": "high",
            "ssh_authorized_keys": [(work / "client.pub").read_text().strip()],
        }],
        "ssh_keys": {
            "ed25519_private": (work / "server").read_text(),
            "ed25519_public": (work / "server.pub").read_text(),
        },
        # The upstream 1.7.6.UU2 image has reached SSH but cloud-init
        # reported a failing scripts_per_once stage. Its documented runtime
        # directory must exist even when user-data contains no per-once
        # scripts. Only make the directory on our disposable CI guest:
        # never disable, skip or rewrite the vendor's cloud-init modules.
        "bootcmd": [["mkdir", "-p", "/var/lib/cloud/scripts/per-once"]],
        "growpart": {"mode": "auto", "devices": ["/"]},
        "resize_rootfs": True,
    }
    seed_data = work / "user-data"
    seed_data.write_text("#cloud-config\n" + json.dumps(user_data))
    seed_data.chmod(0o600)
    write_json(work / "meta-data", {"instance-id": "hcp-astra17-" + args.level,
                                   "local-hostname": HOST})
    run(["cloud-localds", str(work / "seed.iso"), str(seed_data),
         str(work / "meta-data")])
    (work / "seed.iso").chmod(0o600)
    run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
         "-b", str(work / "source.qcow2"), str(work / "guest.qcow2")])
    run(["qemu-img", "resize", str(work / "guest.qcow2"), "12G"])

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    public = " ".join((work / "server.pub").read_text().split()[:2])
    known_hosts = work / "known_hosts"
    known_hosts.write_text("[127.0.0.1]:{} {}\n".format(port, public))
    known_hosts.chmod(0o600)
    options = [
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "ConnectTimeout=8", "-o", "UserKnownHostsFile=" + str(known_hosts),
    ]
    ssh = ["ssh", "-F", "/dev/null", "-i", str(work / "client"),
           "-p", str(port)] + options + ["hcp-ci@127.0.0.1"]

    def remote(command, **kwargs):
        return run(ssh + [command], **kwargs)

    acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    protocol["acceleration"] = acceleration
    qemu_args = [
        "qemu-system-x86_64", "-machine", "q35,accel=" + acceleration,
        "-m", "4096", "-smp", "2", "-display", "none",
        "-monitor", "none", "-serial", "file:" + str(artifacts / "guest-console.log"),
        "-no-reboot",
        "-drive", "file=" + str(work / "guest.qcow2") + ",if=virtio,format=qcow2",
        "-drive", "file=" + str(work / "seed.iso") + ",if=virtio,format=raw,readonly=on",
        "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:" + str(port) + "-:22",
        "-device", "virtio-net-pci,netdev=net0",
    ]
    if acceleration == "kvm":
        qemu_args.extend(["-cpu", "host"])

    with (artifacts / "qemu.log").open("w") as log:
        process = subprocess.Popen(qemu_args, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + (420 if acceleration == "kvm" else 900)
            while time.monotonic() < deadline:
                assert process.poll() is None, "Guest exited before SSH readiness"
                if remote("true", accepted=(0, 255), timeout=12).returncode == 0:
                    break
                time.sleep(3)
            else:
                raise RuntimeError("Actual Astra 1.7 guest did not pass SSH readiness")
            # A genuine 1.7.6.UU2 guest has reached SSH. Cloud-init may
            # still fail one module, so collect only bounded, non-secret
            # module/stage diagnostics in private runner state before refusing
            # an incomplete initialization. Never echo raw user-data,
            # cloud-init.log or the original guest identity into CI artifacts.
            init_status = remote("sudo cloud-init status --wait",
                                 accepted=(0, 1, 2), timeout=300)
            write_json(work / "cloud-init-private-status.json", {
                "exitCode": init_status.returncode,
                "outputSha256": hashlib.sha256(init_status.stdout.encode()).hexdigest(),
            })
            if init_status.returncode != 0:
                status_detail = remote("sudo cloud-init status --long",
                                       accepted=(0, 1, 2), timeout=30)
                # Cloud-init can include operator-defined user-data in its
                # messages. Emit only a strict enumeration, never raw text.
                # Read cloud-init phase markers only. Full guest log text
                # may contain cloud-user-data or SSH secrets; it stays in a
                # private subprocess buffer and is never printed/uploaded.
                module_trace = remote(
                    "sudo grep 'finish:' /var/log/cloud-init.log | tail -70",
                    accepted=(0, 1), timeout=25)
                status_lines = status_detail.stdout.splitlines()
                diagnostic = {
                    "status": "failed",
                    "initExitCode": init_status.returncode,
                    "nativeSshReachable": True,
                    "cloudInitStatusLongSha256": hashlib.sha256(
                        status_detail.stdout.encode()).hexdigest(),
                    "errorLineCount": sum(bool(re.match(
                        r"^\\s*(?:errors|recoverable_errors|error|detail)\\s*:", line))
                        for line in status_lines),
                    "reportedModuleNames": sorted(set(
                        classify_private_cloud_init_errors(status_detail.stdout)
                        + classify_private_cloud_init_errors(module_trace.stdout))),
                    "notes": "Cloud-init error is blocking; guest logs and seed remain private.",
                }
                checkpoint("Native guest cloud-init failure; no audit claimed", diagnostic)
                raise RuntimeError("Native Astra cloud-init failed; private diagnostics recorded")
            checkpoint("Actual native guest cloud-init completed", {
                "status": "done", "exitCode": 0,
            })
            identity_command = (
                "cat /etc/os-release; printf '\\nRELEASE='; cat /etc/astra_version; "
                "printf '\\nKERNEL='; uname -r; printf 'MACHINE_ID='; "
                "cat /etc/machine-id"
            )
            identity = remote(identity_command).stdout
            (work / "native-identity-private.txt").write_text(identity)
            assert ('ID=astra\n' in identity or 'ID="astra"\n' in identity)
            assert "RELEASE=1.7.6.15" in identity
            assert "KERNEL=" + os.uname().release not in identity
            machine = re.search(r"^MACHINE_ID=([a-f0-9]{32})$", identity, re.MULTILINE)
            assert machine and machine.group(1) != "0" * 32
            fingerprint = run(["ssh-keygen", "-E", "sha256", "-lf",
                               str(work / "server.pub")]).stdout.split()[1]
            write_json(work / "asset-observation.json", {
                "alias": HOST, "machineId": machine.group(1),
                "sshHostKeyFingerprint": fingerprint,
                "observedAt": datetime.now(timezone.utc).isoformat(),
                "connection": {"address": "127.0.0.1", "port": port, "user": "hcp-ci"},
            })
            checkpoint("Genuine Astra SE 1.7.6.15 guest kernel and SSH key verified",
                       {"observedRelease": "1.7.6.15",
                        "kernel": re.search(r"^KERNEL=(.+)$", identity, re.MULTILINE).group(1),
                        "identitySha256": hashlib.sha256(identity.encode()).hexdigest(),
                        "hasNativeMachineId": True,
                        "publisherSignatureVerified": False})
            # Only disposable guest instrumentation. HCP never installs
            # scanners on a customer's target without authorization.
            remote("if ! command -v oscap >/dev/null; then set -e; "
                   "sudo apt-get update -o Acquire::Retries=2; "
                   "if apt-cache show openscap-scanner >/dev/null 2>&1; then "
                   "sudo apt-get install -y --no-install-recommends openscap-scanner; "
                   "else sudo apt-get install -y --no-install-recommends libopenscap8; fi; fi",
                   output=artifacts / "guest-oscap-install.log", timeout=900)
            remote("oscap --version", output=artifacts / "guest-oscap-version.txt")
            inventory = {"linux_hosts": {"hosts": {HOST: {
                "ansible_host": "127.0.0.1", "ansible_port": port,
                "ansible_user": "hcp-ci", "ansible_become": True,
                "ansible_python_interpreter": "/usr/bin/python3",
                "ansible_ssh_private_key_file": str(work / "client"),
                "ansible_ssh_common_args": shlex.join(options),
            }}}}
            write_json(work / "inventory.json", inventory)

            def playbook(name, phase, extra=None, timeout=600):
                variables = {"hcp_reports_dir": str(reports),
                             "report_run_id": phase, **(extra or {})}
                args_file = work / ("vars-" + phase + ".json")
                write_json(args_file, variables)
                run([
                    "ansible-playbook", "-i", str(work / "inventory.json"),
                    str(ROOT / "ansible/playbooks" / (name + ".yml")),
                    "-e", "@" + str(args_file),
                ], output=artifacts / (phase + ".log"), timeout=timeout,
                   env={**os.environ, "ANSIBLE_SSH_ARGS": shlex.join(options)})

            playbook("collect-facts", "facts")
            playbook("package-inventory", "packages")
            packages = json.loads(
                (reports / (HOST + "-packages-packages.json")).read_text())
            assert packages.get("packages") and "astra" in packages.get("os", "").lower()
            checkpoint("Real Astra 1.7 native facts and installed packages",
                       {"packageCount": len(packages["packages"]),
                        "releaseSource": packages["os"]})

            original_mode = remote("stat -c '%a' /etc/passwd").stdout.strip()
            assert re.fullmatch(r"[0-7]{3,4}", original_mode)
            statuses = []
            try:
                for phase in ("baseline", "violation", "restored"):
                    if phase == "violation":
                        remote("sudo chmod o+x /etc/passwd")
                    if phase == "restored":
                        remote("sudo chmod " + shlex.quote(original_mode) + " /etc/passwd")
                    playbook("openscap-audit", phase, {
                        "hcp_openscap_datastream": "/__hcp_builtin__/astra-baseline.xml",
                        "hcp_openscap_profile": PROFILE,
                        "hcp_openscap_policy_group": "ci-real-astra-17",
                        "hcp_openscap_keep_arf": True,
                    }, timeout=900)
                    raw = reports / ("." + HOST + "-openscap-" + phase + ".xml")
                    xccdf, evidence = raw_results(raw)
                    raw.rename(artifacts / (phase + ".arf.xml"))
                    normalized = json.loads(
                        (reports / (HOST + "-openscap-" + phase + ".json")).read_text())
                    datastream = Path(str(raw) + ".datastream.xml")
                    verify_baseline_report(
                        normalized, xccdf, evidence,
                        hashlib.sha256(datastream.read_bytes()).hexdigest())
                    datastream.rename(artifacts / (phase + ".datastream.xml"))
                    selected = [entry for entry in normalized.get("findings", [])
                                if entry.get("id") == "openscap_" + RULE]
                    assert len(selected) == 1
                    assert selected[0]["status"] == (
                        "failed" if phase == "violation" else "passed")
                    statuses.append(xccdf[RULE])
            finally:
                remote("sudo chmod " + shlex.quote(original_mode) + " /etc/passwd")
            assert statuses == ["pass", "fail", "pass"]
            # New independent connection after rollback, still bound to the
            # exact pinned SSH host key and same native guest identity.
            restored_identity = remote(identity_command).stdout
            assert restored_identity == identity
            assert remote("stat -c '%a' /etc/passwd").stdout.strip() == original_mode
            checkpoint("Real Astra 1.7.6.15 source-bound pass/fail/restore",
                       {"testRule": RULE, "states": statuses,
                        "postRestoreFreshSshIdentityMatched": True})

            bound = artifacts / "three-stage-bound-reports"
            run([
                "node", str(ROOT / "deployment/tests/verify_astra_vm_three_stage_publication.mjs"),
                str(work / "asset-observation.json"), str(bound),
                *(str(reports / (HOST + "-openscap-" + phase + ".json"))
                  for phase in ("baseline", "violation", "restored")),
            ], output=artifacts / "source-bound-publication.log",
               env={**os.environ, "HCP_REPORTS_DIR": str(work / "source-bound-reports"),
                    "HCP_STATE_DIR": str(work / "source-bound-state")})
            metrics = artifacts / "three-stage-metrics.json"
            run([
                "python3", str(ROOT / "deployment/tests/measure_astra_baseline.py"),
                "--before", str(bound / "baseline.json"),
                "--after", str(bound / "violation.json"),
                "--restored", str(bound / "restored.json"),
                "--output", str(metrics),
            ], output=artifacts / "metrics.log")
            measured = json.loads(metrics.read_text())
            assert measured["completeComparableRuleCount"] == 18
            assert measured["restorationMatchesBaseline18Rules"] is True
            assert measured["baselineToChanged"]["observedPassedToFailed"] == 1
            assert measured["changedToRestored"]["observedFailedToPassed"] == 1
            checkpoint("Actual 18-rule original HCP source-bound measurement",
                       {"baselineFailures": measured["baselineToChanged"]["beforeFailed"],
                        "changedFailures": measured["baselineToChanged"]["afterFailed"],
                        "restoredFailures": measured["changedToRestored"]["afterFailed"],
                        "metricsSha256": hashlib.sha256(metrics.read_bytes()).hexdigest()})

            download(oval, work / "vendor.xml", max_seconds=2400)
            count = full_oval_definition_count(work / "vendor.xml")
            checkpoint("Complete Astra 1.7 publisher OVAL XML checksum and structure",
                       {"ovalXmlBytes": oval["bytes"],
                        "ovalSha256": oval["sha256"], "definitionCount": count,
                        "independentPublisherSignatureVerified": False})
            oval_policy = {
                "mode": "online", "url": oval["url"], "sha256": oval["sha256"],
                "releasePattern": "1.7.*", "architectures": ["amd64"],
                "maxAgeDays": 90, "sourceName": "Astra 1.7 vendor OVAL snapshot",
                "sourceReference": oval["metadataUrl"],
                "sourceReviewedAt": sources["reviewedAt"],
            }
            playbook("astra-oval-audit", "vendor-oval", {
                "hcp_oval_config": oval_policy,
            }, timeout=2700)
            report_id = HOST + "-astra-oval-vendor-oval"
            native_report = json.loads(
                (reports / (report_id + ".json")).read_text())
            oval_result = verify_native_oval_report(native_report, oval, count)
            checkpoint("Genuine Astra 1.7 full native OVAL evaluation",
                       oval_result)
            run([
                "node", str(ROOT / "deployment/tests/verify_astra17_vm_normalization.mjs"),
                report_id, str(reports / (report_id + ".json")),
                str(work / "asset-observation.json"),
                str(artifacts / "oval-normalization.json"),
            ], output=artifacts / "oval-normalization.log",
               env={**os.environ,
                    "HCP_REPORTS_DIR": str(work / "oval-published-reports"),
                    "HCP_STATE_DIR": str(work / "oval-state")})
            checkpoint("Production normalization retains original Astra 1.7 OVAL",
                       {"reportSha256": hashlib.sha256(
                           (reports / (report_id + ".json")).read_bytes()).hexdigest(),
                        "exactSourceScope": "Astra 1.7 amd64",
                        "partial": oval_result["partial"]})
            protocol["status"] = "passed"
            write_json(artifacts / "protocol.json", protocol)
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--level", choices=("base", "adv", "max"),
                        required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    work = args.work_dir.resolve()
    runner = Path(os.environ["RUNNER_TEMP"]).resolve()
    assert work != runner and work.is_relative_to(runner) and not work.exists()
    work.mkdir(mode=0o700)
    artifacts = work / "artifacts"
    reports = artifacts / "reports"
    reports.mkdir(parents=True)
    sources = json.loads(SOURCE.read_text())
    protocol = {
        "status": "running", "realAstraHostVerified": False,
        "syntheticIdentity": False, "level": args.level,
        "source": {"imageSha256": sources["images"][args.level]["sha256"],
                   "ovalSha256": sources["oval"]["sha256"]},
        "limitations": [
            "One exact Astra SE 1.7.6.UU2 cloud image in the selected security level only",
            "Source digests from the same Artifactory are not independent publisher signatures",
            "Only 18 HCP configuration rules and Astra vendor OVAL; no all-CVE recall claim",
            "A temporary file-permissions change is not evidence of HCP applying remediation",
            "A rule-state match and SSH access do not imply total OS or firewall restoration",
        ],
        "checks": [],
    }

    def interrupted(_signal, _frame):
        raise InterruptedError("Operator-disposable CI VM was interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        execute(args, work, artifacts, reports, sources, protocol)
    except BaseException as error:
        try:
            record_failure(artifacts, protocol, error)
        except OSError:
            pass
        raise


if __name__ == "__main__":
    main()
