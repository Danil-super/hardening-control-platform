#!/usr/bin/env python3
"""Genuine, exact-pinned Astra 1.7.6.UU2 base QEMU guest SSH identity preflight.

This is a CI-only read-only test on a disposable VM. It does not prove HCP
enrollment, OpenSCAP, OVAL, firewall rollback, or production readiness.
Untrusted guest outputs and private logs never enter public CI artifacts.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.request

from download_astra17_ova import NoRedirect
from verify_astra_vm import download, verified_pinned_file

NAME = "alse-1.7.6.uu2-base-qemu-mg15.3.1-amd64.qcow2"
SOURCE = {
    "url": "https://registry.astralinux.ru/artifactory/mg-generic/alse/qemu/" + NAME,
    "metadataUrl": "https://registry.astralinux.ru/artifactory/api/storage/mg-generic/alse/qemu/" + NAME,
    "bytes": 402259968,
    "sha256": "75d247c79beecd468ab9da777c1c90ca273f20ece748dc2575e7d091eb3e87b4",
}
MAX_TEXT = 131072


def demand(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def safely_run(argv, *, timeout=60, allowed=(0,)):
    """Never print private subprocess output or raw argv on failure."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True,
                                check=False, timeout=timeout)
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise RuntimeError("command_unavailable_or_timeout")
    demand(result.returncode in allowed, "command_nonzero")
    demand(len(result.stdout.encode("utf-8")) <= MAX_TEXT, "command_output_unbounded")
    return result.stdout


def identity_proof(raw):
    demand(type(raw) is str and len(raw.encode("utf-8")) <= MAX_TEXT,
           "native_identity_unbounded")
    lines = raw.splitlines()
    def single(prefix):
        values = [line[len(prefix):].strip().strip('"').strip("'")
                  for line in lines if line.startswith(prefix)]
        return values[0] if len(values) == 1 else None
    osid, release, build = single("ID="), single("HCP_RELEASE="), single("HCP_BUILD=")
    arch, kernel, machine = single("HCP_ARCH="), single("HCP_KERNEL="), single("HCP_MACHINE_ID=")
    demand(osid == "astra", "native_os_not_astra")
    demand(release == "1.7.6", "native_point_release_wrong")
    demand(build == "1.7.6.15", "native_full_build_wrong")
    demand(arch == "x86_64", "native_architecture_wrong")
    demand(type(kernel) is str and re.fullmatch(r"[A-Za-z0-9_.+:-]{1,120}", kernel),
           "native_kernel_unverified")
    demand(type(machine) is str and re.fullmatch(r"[a-f0-9]{32}", machine)
           and machine != "0" * 32, "native_machine_id_unverified")
    return {
        "osId": osid, "pointRelease": release, "fullBuild": build,
        "architecture": arch, "realKernelObserved": True,
        "privateMachineIdObserved": True,
        "privateIdentityNotExported": True,
    }


def key_line(raw, port):
    lines = [line for line in raw.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    demand(len(lines) == 1, "host_key_not_unique")
    items = lines[0].split()
    demand(len(items) >= 3 and items[0] == "[127.0.0.1]:%d" % port
           and items[1] == "ssh-ed25519"
           and re.fullmatch(r"[A-Za-z0-9+/=]{50,200}", items[2]),
           "host_key_invalid")
    return " ".join(items[:3]) + "\n"


def check_vm(work, protocol):
    original = work / "source.qcow2"
    opener = urllib.request.build_opener(NoRedirect()).open
    print("STAGE 1: verify exact manufacturer-pinned QEMU image bytes", flush=True)
    download(SOURCE, original, opener=opener, max_seconds=2400)
    demand(verified_pinned_file(original, SOURCE), "image_source_digest_unverified")
    image_info = json.loads(safely_run(["qemu-img", "info", "--output=json", str(original)]))
    demand(image_info.get("format") == "qcow2"
           and not image_info.get("backing-filename")
           and type(image_info.get("virtual-size")) is int
           and 2 * 1024 ** 3 < image_info["virtual-size"] <= 50 * 1024 ** 3,
           "image_format_or_size_invalid")
    protocol["checks"].append("original_qcow2_sha256_and_image_structure_verified")
    print("STAGE 2: prepare private writable overlay and pinned local SSH", flush=True)
    overlay = work / "overlay.qcow2"
    safely_run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                "-b", str(original), str(overlay)])
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    accelerate = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    protocol["acceleration"] = accelerate
    qemu = [
        "qemu-system-x86_64", "-machine", "pc,accel=" + accelerate,
        "-m", "4096", "-smp", "2", "-display", "none", "-monitor", "none",
        "-serial", "file:" + str(work / "private-console.log"), "-no-reboot",
        "-drive", "file=" + str(overlay) + ",format=qcow2,if=virtio",
        "-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:%d-:22" % port,
        "-device", "virtio-net-pci,netdev=n0",
    ]
    if accelerate == "kvm":
        qemu.extend(["-cpu", "host"])
    with (work / "private-qemu.log").open("wb") as sink:
        process = subprocess.Popen(qemu, stdout=sink, stderr=subprocess.STDOUT)
        try:
            # Official Astra UBI QEMU image ships a public factory test account;
            # use only against our own disposable VM. Never use it for HCP ops.
            password = work / "factory-password"
            password.write_text("astra\n", encoding="ascii")
            password.chmod(0o600)
            known_hosts = work / "known_hosts"
            sshopts = [
                "-F", "/dev/null", "-p", str(port),
                "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + str(known_hosts),
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "UpdateHostKeys=no",
                "-o", "HostKeyAlgorithms=ssh-ed25519",
                "-o", "ConnectTimeout=6", "-o", "ConnectionAttempts=1",
            ]
            observe = (
                "set -eu; cat /etc/os-release; "
                "printf '\\nHCP_RELEASE='; cat /etc/astra_version; "
                "printf '\\nHCP_BUILD='; cat /etc/astra/build_version; "
                "printf '\\nHCP_ARCH='; uname -m; "
                "printf 'HCP_KERNEL='; uname -r; "
                "printf 'HCP_MACHINE_ID='; cat /etc/machine-id"
            )
            previous = None
            stable_key = None
            print("STAGE 3: boot actual Astra Linux and read SSH identity", flush=True)
            deadline = time.monotonic() + (420 if accelerate == "kvm" else 900)
            next_notice = time.monotonic() + 60
            while time.monotonic() < deadline:
                demand(process.poll() is None, "guest_exited_before_identity")
                try:
                    scan = safely_run(["ssh-keyscan", "-T", "5", "-t", "ed25519",
                                       "-p", str(port), "127.0.0.1"], timeout=12)
                    candidate = key_line(scan, port)
                    if not known_hosts.exists():
                        fd = os.open(known_hosts, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                        with os.fdopen(fd, "w", encoding="ascii") as f:
                            f.write(candidate)
                    demand(known_hosts.read_text(encoding="ascii") == candidate,
                           "local_guest_host_key_changed")
                    raw = safely_run([
                        "sshpass", "-f", str(password), "ssh", *sshopts,
                        "astra@127.0.0.1", observe], timeout=20)
                    previous = identity_proof(raw)
                    stable_key = hashlib.sha256(candidate.encode("ascii")).hexdigest()
                    break
                except RuntimeError as exc:
                    if str(exc) in ("local_guest_host_key_changed", "host_key_invalid",
                                    "host_key_not_unique"):
                        raise
                    time.sleep(4)
                    if time.monotonic() >= next_notice:
                        print("Guest SSH bootstrapping in progress; no acceptance claimed", flush=True)
                        next_notice = time.monotonic() + 60
            demand(previous is not None, "native_guest_ssh_identity_unavailable")
            protocol["checks"].append("native_astra_17_identity_observed_over_ssh")
            print("STAGE 4: independent fresh pinned SSH reconnection", flush=True)
            repeated = safely_run([
                "sshpass", "-f", str(password), "ssh", *sshopts,
                "astra@127.0.0.1", observe], timeout=20)
            demand(identity_proof(repeated) == previous,
                   "native_identity_drift_on_second_ssh")
            protocol["checks"].append("fresh_pinned_ssh_identity_identical")
            protocol["nativeGuest"] = {
                **previous, "sshHostKeyLineSha256": stable_key,
                "sshTrustModel": "disposable_QEMU_bootstrap_only",
                "hcpHostEnrollmentPerformed": False,
            }
            protocol["status"] = "native-astra17-qemu-ssh-only"
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--public-result", required=True)
    args = parser.parse_args()
    demand(os.environ.get("GITHUB_ACTIONS") == "true"
           and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
           "only_disposable_github_runner")
    root = Path(os.environ["RUNNER_TEMP"]).resolve()
    work, result = Path(args.work_dir).resolve(), Path(args.public_result).resolve()
    demand(root in work.parents and root in result.parents and
           work != root and result != root and
           not work.exists() and not result.exists(), "private_output_paths_invalid")
    work.mkdir(mode=0o700)
    protocol = {
        "schemaVersion": 1,
        "status": "running",
        "checks": [],
        "source": {**SOURCE, "publisherSignatureVerified": False,
                   "fullCveRecallVerified": False},
        "recordedAtUtc": datetime.now(timezone.utc).isoformat(),
        "scope": "isolated_native_Astra17_base_QEMU_SSH_only",
        "nativeOpenScap18RulesVerified": False,
        "nativeOval17Evaluated": False,
        "nativeRollbackVerified": False,
        "operatorProductionAccepted": False,
        "limitations": [
            "One exactly pinned official QEMU base image; no adv/max guarantee.",
            "SHA-256 from vendor Artifactory, not an independently authenticated signature.",
            "Factory SSH credentials used only for isolated bootstrapping, never HCP production.",
            "No 18-rule, OVAL, CVE recall, rollback or production-readiness claim.",
        ],
    }
    try:
        check_vm(work, protocol)
    except BaseException as error:
        known = {
            "image_source_digest_unverified", "image_format_or_size_invalid",
            "guest_exited_before_identity", "native_guest_ssh_identity_unavailable",
            "host_key_not_unique", "host_key_invalid", "local_guest_host_key_changed",
            "native_os_not_astra", "native_point_release_wrong",
            "native_full_build_wrong", "native_architecture_wrong",
            "native_kernel_unverified", "native_machine_id_unverified",
            "native_identity_drift_on_second_ssh", "command_unavailable_or_timeout",
            "command_nonzero", "command_output_unbounded",
        }
        reason = str(error) if isinstance(error, RuntimeError) else "unknown"
        protocol["status"] = "native-astra17-qemu-ssh-unverified"
        protocol["failureClass"] = reason if reason in known else "source_or_guest_failure"
        raise
    finally:
        fd = os.open(result, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(protocol, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())


if __name__ == "__main__":
    main()
