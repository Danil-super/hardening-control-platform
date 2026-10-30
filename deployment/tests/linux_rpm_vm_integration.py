#!/usr/bin/env python3
"""Real RPM VM acceptance: native collectors, firewalld and enforcing SELinux.

Only an owned, checksum-pinned QEMU guest receives configuration changes.
Controller artifacts exclude guest disks, cloud-init seeds and SSH private keys.
The labelled system rule and CVE pairs establish specific controls, not overall
scanner recall or compatibility with all RPM distributions and releases.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
HOST = "hcp-rpm-ci"
PORT = 8088
# Official publisher CHECKSUM files and image sizes reviewed 2026-10-30.
# Keep immutable filenames and reviewed SHA-256 values; never resolve "latest".
SOURCES = {
    "almalinux": {
        "url": "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-9.8-20261005.x86_64.qcow2",
        "sha256": "25942b554efaac077e2f60d6bb27bd3332c171454cc21bbd33e5f79244d7570f",
        "bytes": 572850176,
        "checksumUrl": "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/CHECKSUM",
    },
    "rocky": {
        "url": "https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2",
        "sha256": "92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8",
        "bytes": 645988352,
        "checksumUrl": "https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2.CHECKSUM",
    },
}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n")
    path.chmod(0o600)


def run(argv, output=None, timeout=120, accepted=(0,), env=None):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout, env=env)
    if output:
        output.write_text(result.stdout)
    if result.returncode not in accepted:
        raise RuntimeError("Command failed (exit {}): {}\n{}".format(result.returncode, argv[0], result.stdout[-8000:]))
    return result


def download_image(source, target):
    start, size, digest = time.monotonic(), 0, hashlib.sha256()
    temporary = target.with_suffix(".download")
    try:
        with urllib.request.urlopen(source["url"], timeout=60) as response, temporary.open("xb") as stream:
            if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                raise RuntimeError("Refusing an image redirect outside HTTPS.")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                size += len(chunk)
                if size > source["bytes"] or time.monotonic() - start > 600:
                    raise RuntimeError("Image download exceeded its pinned byte/time limit.")
                digest.update(chunk)
                stream.write(chunk)
        if size != source["bytes"] or digest.hexdigest() != source["sha256"]:
            raise RuntimeError("Image differs from its pinned publisher SHA-256 or byte count.")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def boot_and_verify(distribution, work, artifacts, protocol):
    source = SOURCES[distribution]
    reports = artifacts / "reports"
    reports.mkdir()

    def checkpoint(name, detail):
        protocol["checks"].append({"name": name, "detail": detail})
        write_json(artifacts / "protocol.json", protocol)
        print("PASS: " + name, flush=True)

    download_image(source, work / "source.qcow2")
    info = json.loads(run(["qemu-img", "info", "--output=json", str(work / "source.qcow2")]).stdout)
    if info["format"] != "qcow2" or info.get("backing-filename") or info["virtual-size"] > 64 * 1024**3:
        raise RuntimeError("Unexpected image format, backing file or virtual size.")
    checkpoint("Pinned official guest image verified", source)
    for name in ("client", "server"):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / name)])
    config = {"hostname": HOST, "ssh_pwauth": False, "disable_root": True,
              "users": ["default", {"name": "hcp-ci", "groups": ["wheel"], "sudo": "ALL=(ALL) NOPASSWD:ALL",
                                     "lock_passwd": True, "ssh_authorized_keys": [(work / "client.pub").read_text().strip()]}],
              "ssh_keys": {"ed25519_private": (work / "server").read_text(), "ed25519_public": (work / "server.pub").read_text()},
              "growpart": {"mode": "auto", "devices": ["/"]}, "resize_rootfs": True}
    (work / "user-data").write_text("#cloud-config\n" + json.dumps(config))
    (work / "user-data").chmod(0o600)
    write_json(work / "meta-data", {"instance-id": "hcp-rpm-" + distribution, "local-hostname": HOST})
    run(["cloud-localds", str(work / "seed.iso"), str(work / "user-data"), str(work / "meta-data")])
    (work / "seed.iso").chmod(0o600)
    run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(work / "source.qcow2"), str(work / "guest.qcow2")])
    run(["qemu-img", "resize", str(work / "guest.qcow2"), str(max(info["virtual-size"], 16 * 1024**3))])
    with socket.socket() as ssh_listener, socket.socket() as http_listener:
        ssh_listener.bind(("127.0.0.1", 0))
        http_listener.bind(("127.0.0.1", 0))
        ssh_port, http_port = ssh_listener.getsockname()[1], http_listener.getsockname()[1]
    public = " ".join((work / "server.pub").read_text().split()[:2])
    (work / "known_hosts").write_text("[127.0.0.1]:{} {}\n".format(ssh_port, public))
    ssh_options = ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=8",
                   "-o", "UserKnownHostsFile=" + str(work / "known_hosts"),
                   "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no"]
    ssh = ["ssh", "-i", str(work / "client"), "-p", str(ssh_port)] + ssh_options + ["hcp-ci@127.0.0.1"]

    def remote(command, **kwargs):
        return run(ssh + [command], **kwargs)

    def remote_python(code, arguments=(), **kwargs):
        return remote("sudo python3 - " + " ".join(map(shlex.quote, arguments)) + " <<'HCP_NATIVE_PY'\n" + code + "\nHCP_NATIVE_PY", **kwargs)

    qemu_args = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-m", "4096", "-smp", "2",
                 "-display", "none", "-monitor", "none", "-serial", "file:" + str(artifacts / "guest-console.log"), "-no-reboot",
                 "-drive", "file=" + str(work / "guest.qcow2") + ",if=virtio,format=qcow2",
                 "-drive", "file=" + str(work / "seed.iso") + ",if=virtio,format=raw,readonly=on",
                 "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:{}-:22,hostfwd=tcp:127.0.0.1:{}-:{}".format(ssh_port, http_port, PORT),
                 "-device", "virtio-net-pci,netdev=net0"]
    with (artifacts / "qemu.log").open("w") as log:
        process = subprocess.Popen(qemu_args, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 420
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Guest exited before SSH readiness; inspect QEMU and console logs.")
                if remote("true", accepted=(0, 255), timeout=12).returncode == 0:
                    break
                time.sleep(3)
            else:
                raise RuntimeError("Guest SSH readiness timed out.")
            remote("sudo cloud-init status --wait", output=artifacts / "cloud-init-status.txt", timeout=300)
            identity = json.loads(remote_python(r'''
import json, os, platform, shlex, subprocess
from pathlib import Path
release = {}
for line in Path("/etc/os-release").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        key, value = line.split("=", 1)
        release[key] = shlex.split(value)[0] if value else ""
print(json.dumps({"osRelease": release, "kernel": platform.release(), "architecture": platform.machine(),
    "pid1": Path("/proc/1/comm").read_text().strip(), "machineId": Path("/etc/machine-id").read_text().strip(),
    "selinux": subprocess.check_output(["getenforce"], universal_newlines=True).strip()}))
''').stdout)
            if (identity["osRelease"].get("ID") != distribution or not identity["osRelease"].get("VERSION_ID", "").startswith("9.")
                    or identity["pid1"] != "systemd" or identity["architecture"] != "x86_64"
                    or identity["kernel"] == os.uname().release or identity["selinux"] != "Enforcing"
                    or not re.fullmatch(r"[a-f0-9]{32}", identity["machineId"])):
                raise RuntimeError("Guest identity, independent kernel, PID1 or enforcing SELinux does not match the native test.")
            identity.pop("machineId")
            identity["machineIdFormatVerified"] = True
            write_json(artifacts / "guest-identity.json", identity)
            checkpoint("Genuine RPM guest with independent kernel and enforcing SELinux", identity)
            remote("sudo dnf -y --setopt=retries=2 --setopt=timeout=30 install python3 firewalld iproute nftables curl policycoreutils",
                   output=artifacts / "guest-provision.log", timeout=600)
            remote("test \"$(getenforce)\" = Enforcing && test \"$(cat /proc/1/comm)\" = systemd")
            # A separate private source copy lets native metadata/crash tests
            # import the same production helper. No user secrets are copied.
            with tarfile.open(str(work / "helpers.tar"), "w") as archive:
                archive.add(str(ROOT / "ansible/scripts"), arcname="ansible/scripts", filter=lambda member: None if "__pycache__" in member.name else member)
                archive.add(str(ROOT / "ansible/tests/native_selinux_firewall_acceptance.py"), arcname="ansible/tests/native_selinux_firewall_acceptance.py")
                archive.add(str(ROOT / "ansible/tests/native_rpm_inventory_diagnostics.py"), arcname="ansible/tests/native_rpm_inventory_diagnostics.py")
            run(["scp", "-i", str(work / "client"), "-P", str(ssh_port)] + ssh_options + [str(work / "helpers.tar"), "hcp-ci@127.0.0.1:/home/hcp-ci/helpers.tar"])
            remote("mkdir -m 700 /home/hcp-ci/hcp-source && tar -xf /home/hcp-ci/helpers.tar -C /home/hcp-ci/hcp-source")
            guest_source = "/home/hcp-ci/hcp-source/ansible/scripts/hcp-firewall.py"
            remote(r'''set -e
sudo systemctl enable --now firewalld.service
sudo firewall-cmd --set-default-zone=public
sudo firewall-cmd --permanent --zone=public --add-service=ssh
sudo firewall-cmd --permanent --zone=public --add-port=8088/tcp
interface=$(ip -4 route show default | awk 'NR == 1 { for (i=1;i<=NF;i++) if ($i == "dev") { print $(i+1); exit } }')
test -n "$interface"
sudo firewall-cmd --permanent --zone=public --change-interface="$interface"
sudo firewall-cmd --zone=public --change-interface="$interface"
sudo firewall-cmd --reload
test "$(sudo firewall-cmd --get-zone-of-interface="$interface")" = public
test "$(getenforce)" = Enforcing
''', output=artifacts / "firewall-baseline-setup.log")
            inventory = {"linux_hosts": {"hosts": {HOST: {"ansible_host": "127.0.0.1", "ansible_port": ssh_port,
                "ansible_user": "hcp-ci", "ansible_become": True, "ansible_python_interpreter": "/usr/bin/python3",
                "ansible_ssh_private_key_file": str(work / "client"), "ansible_ssh_common_args": shlex.join(ssh_options)}}}}
            write_json(work / "inventory.json", inventory)
            transaction = "txn-ci-firewalld-" + uuid.uuid4().hex

            def playbook(name, phase, extra=None, check=False, expected_error=None):
                variables = {"hcp_reports_dir": str(reports), "report_run_id": phase,
                             "transaction_id": transaction, "remediation_action": "closePort", "target_port": PORT,
                             "target_protocol": "tcp", **(extra or {})}
                var_file = work / ("vars-" + phase + ".json")
                write_json(var_file, variables)
                argv = ["ansible-playbook", "-i", str(work / "inventory.json"), str(ROOT / "ansible/playbooks" / (name + ".yml")),
                        "--limit", HOST, "-e", "@" + str(var_file)]
                if check:
                    argv.append("--check")
                result = run(argv, output=artifacts / (phase + ".log"), timeout=360, accepted=(2,) if expected_error else (0,),
                             env={**os.environ, "ANSIBLE_SSH_ARGS": shlex.join(ssh_options), "ANSIBLE_FORCE_COLOR": "false"})
                if expected_error and expected_error not in result.stdout:
                    raise RuntimeError("Request failed for a different reason than the expected protection: " + phase)
                return result.stdout

            playbook("collect-facts", "facts")
            facts = json.loads((reports / (HOST + "-facts-facts.json")).read_text())
            if facts["kernel"] != identity["kernel"] or facts["architecture"] != "x86_64":
                raise RuntimeError("Production Ansible facts do not describe the native guest.")
            playbook("package-inventory", "packages")
            package_path = reports / (HOST + "-packages-packages.json")
            packages = json.loads(package_path.read_text())
            coverage = packages["packageInventory"]
            if (coverage.get("manager") != "rpm" or coverage.get("error") or coverage.get("partial") is not False
                    or coverage.get("osRelease", {}).get("ID") != distribution or not packages.get("packages")
                    or coverage.get("collectorVersion") != 2 or coverage.get("managerSelection") != "os-id"
                    or coverage.get("packageCount") != len(packages["packages"])):
                # Preserve the failing production report. Additional read-only
                # queries explain SQLite/WAL changes; they cannot make this
                # inventory complete or bypass the original acceptance gate.
                remote("sudo python3 /home/hcp-ci/hcp-source/ansible/tests/native_rpm_inventory_diagnostics.py",
                       output=artifacts / "native-rpm-inventory-diagnostics.json", timeout=300)
                raise RuntimeError("Native RPM package inventory is missing, partial or identifies a different distribution: "
                                   + json.dumps(coverage, sort_keys=True))
            if not all(item.get("manager") == "rpm" and item.get("name") and item.get("version") and item.get("arch") for item in packages["packages"]):
                raise RuntimeError("RPM inventory omitted package identity fields.")
            query = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"
            native_records = remote("rpm -qa --qf " + shlex.quote(query), output=artifacts / "native-rpm-records.txt").stdout
            expected_records = []
            for line in native_records.splitlines():
                name, epoch, version, arch, source_rpm = line.split("\t")
                expected_records.append((name, (epoch + ":" if epoch not in ("0", "(none)", "") else "") + version,
                                         "None" if arch == "(none)" else arch, "" if source_rpm == "(none)" else source_rpm))
            observed_records = [(item["name"], item["version"], item["arch"], item.get("sourceRpm", "")) for item in packages["packages"]]
            if Counter(observed_records) != Counter(expected_records):
                raise RuntimeError("Collected binary RPM EVR/architecture/source records differ from the native RPM database.")
            checkpoint("Production SSH facts and complete native RPM collection", {"count": len(packages["packages"]), "manager": coverage["manager"]})
            readiness = json.loads(remote("sudo python3 /home/hcp-ci/hcp-source/ansible/scripts/hcp-host-readiness.py",
                                         output=artifacts / "host-readiness.json").stdout)
            if (readiness["osRelease"].get("ID") != distribution or readiness.get("serviceManager") != "systemd"
                    or readiness.get("securityModules", {}).get("selinux") != "enforcing"
                    or not readiness.get("tools", {}).get("rpm") or readiness.get("firewall", {}).get("firewalld") != "active"):
                raise RuntimeError("Readiness did not retain the native service manager and SELinux state.")
            # A native pass/fail/restored control uses an owned temporary child
            # of /var/tmp, one of the production profile's inspected roots.
            control = "/var/tmp/hcp-world-writable-" + uuid.uuid4().hex
            remote("sudo mkdir -m 1777 " + shlex.quote(control))
            states = []
            try:
                for phase, mode in (("system-baseline", "1777"), ("system-violation", "0777"), ("system-restored", "1777")):
                    remote("sudo chmod " + mode + " " + shlex.quote(control))
                    playbook("agentless-audit", phase, {"audit_profile": "basic_linux"})
                    report = json.loads((reports / (HOST + "-basic_linux-" + phase + ".json")).read_text())
                    agentless = report["agentless"]
                    if agentless.get("serviceManager") != "systemd" or not agentless.get("serviceManagerEvidence"):
                        raise RuntimeError("Agentless report omitted observed systemd evidence.")
                    observations = agentless.get("serviceObservations", [])
                    if not any(item.get("service") in ("ssh", "sshd") and item.get("state") == "active" for item in observations):
                        raise RuntimeError("Native sshd service was not detected through its distro alias.")
                    if report["scanner"].get("partial") and report["summary"].get("score") is not None:
                        raise RuntimeError("Incomplete native checks produced an unqualified score.")
                    finding = [item for item in report["findings"] if item["id"] == "world_writable_dirs"]
                    if len(finding) != 1 or finding[0]["status"] != ("failed" if mode == "0777" else "passed"):
                        raise RuntimeError("Native sticky-bit control produced the wrong agentless finding.")
                    if mode == "0777" and control not in finding[0].get("evidence", ""):
                        raise RuntimeError("Native violation report omitted the actual affected directory.")
                    states.append(finding[0]["status"])
            finally:
                remote("sudo chmod 1777 " + shlex.quote(control) + " && sudo rmdir " + shlex.quote(control))
            checkpoint("Native agentless pass/fail/restored rule and honest coverage", states)
            native_labels = json.loads(remote("sudo python3 /home/hcp-ci/hcp-source/ansible/tests/native_selinux_firewall_acceptance.py",
                                              output=artifacts / "native-selinux-metadata.json", timeout=240).stdout)
            if not native_labels.get("ok") or native_labels.get("selinux") != "Enforcing" or not native_labels.get("realSecuritySelinuxXattrs"):
                raise RuntimeError("Native SELinux metadata acceptance did not establish success.")
            checkpoint("Native enforcing SELinux metadata and crash recovery", native_labels)
            verify_firewall(remote, remote_python, playbook, checkpoint, artifacts, guest_source, transaction, http_port)
            run(["node", str(ROOT / "deployment/tests/verify_linux_packages.mjs"), str(package_path), str(artifacts / "package-matching")],
                output=artifacts / "package-matching.log", timeout=900,
                env={**os.environ, "HCP_TRIVY_CACHE_DIR": str(work / "trivy-cache")})
            matching = json.loads((artifacts / "package-matching/protocol.json").read_text())
            if matching.get("status") != "passed" and matching.get("ok") is not True:
                raise RuntimeError("Native SBOM and vendor CVE controls did not report verified success.")
            checkpoint("Native inventory through production SBOM and Trivy vendor controls", matching)
            remote("test \"$(getenforce)\" = Enforcing && sudo firewall-cmd --state && test \"$(cat /proc/1/comm)\" = systemd",
                   output=artifacts / "final-native-state.txt")
            protocol["status"] = "passed"
            write_json(artifacts / "protocol.json", protocol)
        except BaseException:
            try:
                remote("sudo journalctl -u firewalld --no-pager -n 80; sudo ausearch -m AVC,USER_AVC -ts boot | tail -n 80; getenforce",
                       output=artifacts / "failure-guest-diagnostics.log", timeout=20, accepted=(0, 1, 127, 255))
            except Exception:
                pass
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def verify_firewall(remote, remote_python, playbook, checkpoint, artifacts, guest_source, transaction, http_port):
    token = "hcp-native-rpm-" + uuid.uuid4().hex
    remote("mkdir -m 700 /home/hcp-ci/hcp-http && printf %s " + shlex.quote(token) + " > /home/hcp-ci/hcp-http/health")
    remote("nohup python3 -m http.server 8088 --bind 0.0.0.0 --directory /home/hcp-ci/hcp-http > /home/hcp-ci/http.log 2>&1 < /dev/null &")
    url = "http://127.0.0.1:{}/health".format(http_port)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def probe(expected):
        try:
            with opener.open(url, timeout=4) as response:
                if response.status != 200 or response.read(4096).decode() != token:
                    raise RuntimeError("Native HTTP probe reached an unexpected service or response.")
                reachable = True
        except urllib.error.HTTPError as error:
            raise RuntimeError("Native HTTP probe received an unexpected HTTP error: " + str(error)) from error
        except OSError:
            reachable = False
        if reachable != expected:
            raise RuntimeError("Native forwarded HTTP probe had unexpected reachability: {}".format(reachable))
        remote("test \"$(getenforce)\" = Enforcing && printenv SSH_CONNECTION")

    for attempt in range(30):
        try:
            probe(True)
            break
        except RuntimeError:
            if attempt == 29:
                raise
            time.sleep(0.2)

    snapshot_code = r'''
import importlib.util, json, os, subprocess, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("native_firewall_snapshot", sys.argv[1])
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
tree = Path("/etc/firewalld")
labels = {str(path.relative_to(tree)): os.getxattr(str(path), "security.selinux", follow_symlinks=False).hex()
          for path in [tree] + list(tree.rglob("*"))}
runtime = {name: subprocess.check_output(["firewall-cmd"] + args, universal_newlines=True)
           for name, args in (("zones", ["--list-all-zones"]), ("policies", ["--list-all-policies"]),
                              ("direct", ["--direct", "--get-all-rules"]))}
print(json.dumps({"manifest": fw.tree_digest(tree), "labels": labels, "runtime": runtime}, sort_keys=True))
'''

    def snapshot(label):
        return json.loads(remote_python(snapshot_code, (guest_source,), output=artifacts / (label + ".json")).stdout)

    baseline = snapshot("firewall-baseline")
    playbook("backup-remediation", "firewall-backup")
    playbook("close-port", "firewall-reject-ssh", {"target_port": 22}, expected_error="management SSH port cannot be closed")
    playbook("close-port", "firewall-preview", check=True)
    if snapshot("firewall-after-preview") != baseline:
        raise RuntimeError("Rejected management request or preview modified native firewall state or labels.")
    probe(True)
    playbook("close-port", "firewall-apply")
    probe(False)
    remote("test \"$(curl --silent --fail --max-time 3 http://127.0.0.1:8088/health)\" = " + shlex.quote(token))
    applied = snapshot("firewall-applied")
    repeated = playbook("close-port", "firewall-repeat-apply")
    if not re.search(HOST + r"\s+:.*changed=0\b", repeated) or snapshot("firewall-repeated") != applied:
        raise RuntimeError("Native firewall repeated apply was not idempotent.")
    remote("sudo firewall-cmd --reload")
    probe(False)
    checkpoint("Native firewalld preview, management guard, incoming deny and persistent idempotence", {"port": PORT})
    interrupted = json.loads(remote_python(r'''
import json, signal, subprocess, sys
from pathlib import Path
code = """
import argparse, importlib.util, os, signal, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('native_firewall_crash', sys.argv[1])
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
original = Path.rename
def interrupted(source, target):
    result = original(source, target)
    if source == Path('/etc/firewalld'):
        os.kill(os.getpid(), signal.SIGKILL)
    return result
Path.rename = interrupted
fw.execute_operation(argparse.Namespace(operation='rollback', transaction=sys.argv[2], check=False, recovery_verified=False))
"""
result = subprocess.run([sys.executable, "-c", code, sys.argv[1], sys.argv[2]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
if result.returncode != -signal.SIGKILL or Path("/etc/firewalld").exists():
    raise RuntimeError("Native rollback did not reach its expected killed/missing-directory boundary: " + repr(result.stderr))
journal = json.loads((Path("/var/lib/hcp-backups") / sys.argv[2] / "rollback-state.json").read_text())
if journal.get("phase") != "move_old_intent" or journal.get("transactionId") != sys.argv[2]:
    raise RuntimeError("Native rollback lost its durable intent.")
staging = Path("/etc") / journal["stagingName"]
if not (staging / "previous").is_dir():
    raise RuntimeError("Native rollback lost the previous tree.")
print(json.dumps(journal, sort_keys=True))
''', (guest_source, transaction), output=artifacts / "firewall-interrupted-journal.json").stdout)
    probe(False)
    playbook("rollback-remediation", "firewall-rollback")
    probe(True)
    if snapshot("firewall-restored") != baseline:
        raise RuntimeError("Native rollback did not restore exact configuration, SELinux labels and runtime state.")
    replay = playbook("rollback-remediation", "firewall-replayed-rollback")
    if not re.search(HOST + r"\s+:.*changed=0\b", replay) or snapshot("firewall-replayed") != baseline:
        raise RuntimeError("Native rollback replay changed the restored state.")
    checkpoint("Native SIGKILL rollback resumes with exact SELinux labels and restored traffic", {"phase": interrupted["phase"], "replayed": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distribution", choices=tuple(SOURCES), required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Only an owned disposable GitHub-hosted runner is supported.")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("KVM is required; unavailable native virtualization cannot produce a passing result.")
    work, runner_temp = args.work_dir.resolve(), Path(os.environ["RUNNER_TEMP"]).resolve()
    if work == runner_temp or runner_temp not in work.parents or work.exists():
        raise RuntimeError("Require a new private work directory below RUNNER_TEMP.")
    work.mkdir(mode=0o700)
    artifacts = work / "artifacts"
    artifacts.mkdir(mode=0o755)
    protocol = {"status": "running", "distribution": args.distribution, "image": SOURCES[args.distribution],
                "acceleration": "kvm", "syntheticOsIdentity": False,
                "limitations": ["Pinned x86_64 RPM base images only; other releases require native acceptance",
                                "Incoming traffic control is IPv4 over QEMU forwarding; no IPv6 coverage claim",
                                "Native SELinux validation uses the image's policy; no claim about every custom MLS/MCS policy",
                                "Labelled controls establish specific behavior, not overall vulnerability recall"], "checks": []}
    write_json(artifacts / "protocol.json", protocol)

    def interrupted(_signum, _frame):
        raise InterruptedError("CI cancellation")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        boot_and_verify(args.distribution, work, artifacts, protocol)
    except BaseException as error:
        protocol["status"] = "cancelled" if isinstance(error, (InterruptedError, KeyboardInterrupt)) else "failed"
        protocol["error"] = {"type": type(error).__name__, "message": str(error)[-4000:]}
        write_json(artifacts / "protocol.json", protocol)
        raise


if __name__ == "__main__":
    main()
