#!/usr/bin/env python3
"""Genuine Alpine/OpenRC acceptance; changes only an owned disposable CI guest.

The image and SHA-512 are from the publisher's metadata reviewed 2026-10-30:
https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/alpine-3.22.6-x86_64-bios-cloudinit-r0.yaml
This proves this image/architecture, not every Alpine release or CVE recall.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
HOST = "hcp-alpine"
IMAGE = {
    "url": "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/alpine-3.22.6-x86_64-bios-cloudinit-r0.qcow2",
    "sha512": "864ad8b9e3d14272d592f380c814c647bb6666fcd5b73c86dc21528da71306a93f2ce29b89ea8e6099b76786bb7835f0e27ca1824ec7f4b0b243160a13ba262d",
    "bytes": 166658048,
}

# This runs in the disposable guest after cloud-init config. In particular,
# report only a classification of the shadow entry, never its password/hash.
# Serial diagnostics remain available when SSH itself cannot authenticate.
BOOT_DIAGNOSTICS = r'''
import json, os, pathlib, pwd, subprocess
result = {}
try:
    account = pwd.getpwnam("hcp-ci")
    result["account"] = {"uid": account.pw_uid, "shell": account.pw_shell,
                         "shellExecutable": os.access(account.pw_shell, os.X_OK)}
    shadow = next(line.split(":")[1] for line in pathlib.Path("/etc/shadow").read_text().splitlines()
                  if line.split(":", 1)[0] == "hcp-ci")
    result["account"]["shadowState"] = ("locked" if shadow.startswith("!") else
        "unusable-password" if shadow.startswith("*") else "empty" if not shadow else "password-hash")
    keys = pathlib.Path(account.pw_dir) / ".ssh/authorized_keys"
    result["account"]["authorizedKeyCount"] = sum(1 for line in keys.read_text().splitlines()
                                                   if line.strip() and not line.lstrip().startswith("#"))
    result["account"]["authorizedKeysMode"] = oct(keys.stat().st_mode & 0o777)
except Exception as error:
    result["accountError"] = type(error).__name__
for name, command in (
    ("sshdConfig", ["/usr/sbin/sshd", "-T"]),
    ("sshdService", ["rc-service", "sshd", "status"]),
    ("hostKeyFingerprint", ["ssh-keygen", "-l", "-f", "/etc/ssh/ssh_host_ed25519_key.pub"]),
    ("network", ["ip", "-brief", "address", "show"]),
):
    try:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, timeout=10)
        lines = response.stdout.splitlines()
        if name == "sshdConfig":
            allowed = {"usepam", "passwordauthentication", "kbdinteractiveauthentication",
                       "pubkeyauthentication", "authenticationmethods", "authorizedkeysfile",
                       "permitrootlogin", "allowusers", "allowgroups", "denyusers", "denygroups",
                       "listenaddress", "port"}
            lines = [line for line in lines if line.split(" ", 1)[0] in allowed]
        result[name] = {"exitCode": response.returncode, "output": "\n".join(lines)[-4000:]}
    except Exception as error:
        result[name] = {"error": type(error).__name__}
with open("/dev/ttyS0", "w") as serial:
    serial.write("\nHCP-CI BOOT DIAGNOSTICS " + json.dumps(result, sort_keys=True) + "\n")
'''


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    path.chmod(0o600)


def run(argv, output=None, timeout=120, accepted=(0,), env=None):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, env=env)
    if output:
        output.write_text(result.stdout)
    if result.returncode not in accepted:
        raise RuntimeError("Command failed (exit %s): %r\n%s" % (result.returncode, argv, result.stdout[-12000:]))
    return result


def download_image(target):
    total, digest, start = 0, hashlib.sha512(), time.monotonic()
    with urllib.request.urlopen(IMAGE["url"], timeout=60) as response, target.open("xb") as stream:
        assert response.geturl().startswith("https://")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            assert total <= IMAGE["bytes"] and time.monotonic() - start < 600, "Image download exceeds bounds"
            digest.update(chunk)
            stream.write(chunk)
    assert total == IMAGE["bytes"] and digest.hexdigest() == IMAGE["sha512"], "Publisher image digest mismatch"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "Disposable GitHub runner required"
    work, runner_temp = args.work_dir.resolve(), Path(os.environ["RUNNER_TEMP"]).resolve()
    assert work != runner_temp and work.is_relative_to(runner_temp) and not work.exists()
    work.mkdir(mode=0o700)
    artifacts, reports = work / "artifacts", work / "artifacts/reports"
    reports.mkdir(parents=True)
    protocol = {"status": "running", "image": IMAGE, "architecture": "x86_64", "syntheticIdentity": False,
                "limitations": ["One real Alpine 3.22.6 OpenRC VM; not all releases/architectures", "A missing scanner or unavailable database fails the gate; limited host evidence remains partial"], "checks": []}
    process = None

    def checkpoint(name, detail):
        protocol["checks"].append({"name": name, "detail": detail})
        write_json(artifacts / "protocol.json", protocol)

    def interrupted(_signum, _frame):
        raise InterruptedError("CI cancellation")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        download_image(work / "source.qcow2")
        checkpoint("Official image pinned by SHA-512 and exact byte count", IMAGE)
        for name in ("client", "server"):
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / name)])
        config = {
            "hostname": HOST, "ssh_pwauth": False, "disable_root": True,
            "users": [{"name": "hcp-ci", "groups": ["wheel"], "shell": "/bin/ash", "lock_passwd": True,
                       "sudo": "ALL=(ALL) NOPASSWD:ALL", "ssh_authorized_keys": [(work / "client.pub").read_text().strip()]}],
            "ssh_keys": {"ed25519_private": (work / "server").read_text(), "ed25519_public": (work / "server.pub").read_text()},
            "package_update": True, "packages": ["python3", "sudo", "iproute2", "openssh-sftp-server"],
            "growpart": {"mode": "auto", "devices": ["/"]}, "resize_rootfs": True,
            "runcmd": [["python3", "-c", BOOT_DIAGNOSTICS]],
        }
        (work / "user-data").write_text("#cloud-config\n" + json.dumps(config))
        (work / "user-data").chmod(0o600)
        write_json(work / "meta-data", {"instance-id": "hcp-alpine-3.22.6", "local-hostname": HOST})
        run(["cloud-localds", str(work / "seed.iso"), str(work / "user-data"), str(work / "meta-data")])
        (work / "seed.iso").chmod(0o600)
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(work / "source.qcow2"), str(work / "guest.qcow2")])
        run(["qemu-img", "resize", str(work / "guest.qcow2"), "8G"])
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        public = " ".join((work / "server.pub").read_text().split()[:2])
        (work / "known_hosts").write_text("[127.0.0.1]:%s %s\n" % (port, public))
        options = ["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=8", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UserKnownHostsFile=" + str(work / "known_hosts")]
        ssh = ["ssh", "-i", str(work / "client"), "-p", str(port)] + options + ["hcp-ci@127.0.0.1"]

        def remote(command, **kwargs):
            return run(ssh + [command], **kwargs)

        acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        qemu = ["qemu-system-x86_64", "-machine", "q35,accel=" + acceleration, "-m", "2048", "-smp", "2", "-display", "none", "-monitor", "none",
                "-serial", "file:" + str(artifacts / "guest-console.log"), "-no-reboot", "-drive", "file=" + str(work / "guest.qcow2") + ",if=virtio,format=qcow2",
                "-drive", "file=" + str(work / "seed.iso") + ",if=virtio,format=raw,readonly=on", "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:" + str(port) + "-:22", "-device", "virtio-net-pci,netdev=net0"]
        if acceleration == "kvm":
            qemu += ["-cpu", "host"]
        with (artifacts / "qemu.log").open("w") as log:
            process = subprocess.Popen(qemu, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + (420 if acceleration == "kvm" else 900)
        while time.monotonic() < deadline:
            assert process.poll() is None, "Guest stopped before SSH; inspect console"
            attempt = remote("true", accepted=(0, 255), timeout=12)
            # Retain the latest exact SSH refusal (auth, pinned key, network)
            # without logging userdata, private keys, or verbose key traces.
            (artifacts / "ssh-readiness.txt").write_text(attempt.stdout[-4000:])
            if attempt.returncode == 0:
                break
            time.sleep(3)
        else:
            raise RuntimeError("Guest SSH readiness timeout; inspect ssh-readiness.txt and guest-console.log")
        remote("sudo cloud-init status --wait", output=artifacts / "cloud-init-status.txt", timeout=300)
        # This is the unchanged production readiness program running inside
        # the guest, not a fabricated /etc/os-release fixture.
        readiness = json.loads(remote("sudo python3 -c " + shlex.quote((ROOT / "ansible/scripts/hcp-host-readiness.py").read_text())).stdout)
        assert readiness["osRelease"]["ID"] == "alpine" and readiness["osRelease"]["VERSION_ID"].startswith("3.22.")
        assert readiness["serviceManager"] == "openrc" and readiness["initSystem"] in ("init", "openrc-init")
        assert readiness["kernel"] != os.uname().release
        write_json(artifacts / "readiness.json", readiness)
        checkpoint("Native Alpine kernel, Python, APK and active OpenRC", readiness)
        variables = {"ansible_host": "127.0.0.1", "ansible_port": port, "ansible_user": "hcp-ci", "ansible_become": True,
                     "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": str(work / "client"), "ansible_ssh_common_args": shlex.join(options)}
        write_json(work / "inventory.json", {"linux_hosts": {"hosts": {HOST: variables}}})

        def playbook(name, phase, extra=None):
            extra_file = work / (phase + ".json")
            write_json(extra_file, {"hcp_reports_dir": str(reports), "report_run_id": phase, **(extra or {})})
            run(["ansible-playbook", "-i", str(work / "inventory.json"), str(ROOT / "ansible/playbooks" / (name + ".yml")), "-e", "@" + str(extra_file)],
                output=artifacts / (phase + ".log"), timeout=600, env={**os.environ, "ANSIBLE_SSH_ARGS": shlex.join(options)})

        playbook("package-inventory", "packages")
        package_file = reports / (HOST + "-packages-packages.json")
        packages = json.loads(package_file.read_text())
        assert packages["packageInventory"]["manager"] == "apk" and packages["packages"]
        assert all(item["manager"] == "apk" for item in packages["packages"])
        assert packages["packageInventory"]["packageCount"] == len(packages["packages"])
        checkpoint("Production APK collection", {"packageCount": len(packages["packages"]), "inventory": packages["packageInventory"]})
        # A real service is started/stopped and a permission error is inserted
        # only in this guest; production audit must distinguish all states.
        remote("sudo mkdir -p /var/tmp/hcp-permission-control; sudo chmod 1777 /var/tmp/hcp-permission-control; sudo rc-service crond start", output=artifacts / "controls-setup.log")
        states = []
        try:
            for phase in ("baseline", "violation", "restored"):
                if phase == "violation":
                    remote("sudo chmod 0777 /var/tmp/hcp-permission-control; sudo rc-service crond stop")
                elif phase == "restored":
                    remote("sudo chmod 1777 /var/tmp/hcp-permission-control; sudo rc-service crond start")
                playbook("agentless-audit", phase, {"audit_profile": "basic_linux"})
                report = json.loads((reports / (HOST + "-basic_linux-" + phase + ".json")).read_text())
                assert report["agentless"]["serviceManager"] == "openrc"
                cron = next(row for row in report["agentless"]["serviceObservations"] if row["service"] == "cron")
                assert cron["state"] == ("inactive" if phase == "violation" else "active"), cron
                finding = next(row for row in report["findings"] if row["id"] == "world_writable_dirs")
                assert finding["status"] == ("failed" if phase == "violation" else "passed"), finding
                if report["scanner"]["partial"]:
                    assert report["summary"]["score"] is None
                states.append({"phase": phase, "cron": cron["state"], "filesystem": finding["status"], "partial": report["scanner"]["partial"]})
        finally:
            remote("sudo chmod 1777 /var/tmp/hcp-permission-control; sudo rc-service crond start")
        checkpoint("Real OpenRC and filesystem pass/fail/restored controls", states)
        marker = "Failed password for hcp-native-alpine-event-control"
        remote("sudo rc-service syslog start && logger -p auth.warning -t hcp-ci " + shlex.quote(marker))
        # Syslog writes asynchronously; wait for this owned marker, boundedly.
        for attempt in range(20):
            if remote("sudo grep -F " + shlex.quote(marker) + " /var/log/messages", accepted=(0, 1), timeout=10).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Native Alpine syslog did not persist the event control")
        playbook("collect-security-events", "events")
        events = json.loads((reports / (HOST + "-events-events.json")).read_text())
        assert events["mode"] == "events"
        assert any(row["source"] == "auth_failed" and marker in row["message"] for row in events["events"]), "Default Alpine auth source was skipped"
        checkpoint("Portable production event collection", {"events": len(events["events"]), "scanner": events.get("scanner")})
        run(["node", str(ROOT / "deployment/tests/verify_linux_packages.mjs"), str(package_file), str(artifacts / "package-matching")],
            output=artifacts / "package-matching.log", timeout=900)
        checkpoint("Native inventory to production SBOM and labelled Trivy controls", "See package-matching artifacts")
        protocol["status"] = "passed"
    except BaseException as error:
        protocol["status"] = "cancelled" if isinstance(error, (KeyboardInterrupt, InterruptedError)) else "failed"
        protocol["error"] = {"type": type(error).__name__, "message": str(error)[-4000:]}
        raise
    finally:
        write_json(artifacts / "protocol.json", protocol)
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=10)


if __name__ == "__main__":
    main()
