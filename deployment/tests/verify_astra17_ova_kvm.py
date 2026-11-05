#!/usr/bin/env python3
"""Official Astra 1.7.6.UU2 OVA SSH and explicitly selected native HCP audit.

Smoke-only is the default. Optional genuine OpenSCAP/OVAL experiments run
solely on a disposable GitHub Actions VM and cannot establish production
readiness, universal CVE coverage, or publisher attestation.
No raw guest logs, disk, credentials or machine-id leave private runner paths.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import stat
import subprocess
import tarfile
import time
import urllib.request

from download_astra17_ova import download, FILENAMES, NoRedirect
from verify_astra_vm import verified_pinned_file

EXPECTED_BYTES = 427995648
EXPECTED_SHA256 = "72ccb335f4c46b5b6d1410cfe0c08f648f95a5e6fd1026f6e0b2d65d8b7ebf6e"
MAX_MEMBERS = 20
MAX_VMDK_BYTES = 8 * 1024 ** 3


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def run(argv, *, timeout=120):
    """Capture private stderr and stdout, expose only a bounded safe error code."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           check=False, timeout=timeout)
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise RuntimeError("subprocess_unavailable_or_timeout")
    require(p.returncode == 0, "subprocess_failed")
    require(len(p.stdout.encode("utf-8")) < 131072, "subprocess_output_unbounded")
    return p.stdout


def permitted_ova_disk(archive):
    members = archive.getmembers()
    require(2 <= len(members) <= MAX_MEMBERS, "ova_member_count_invalid")
    disks, ovf = [], []
    for entry in members:
        name = entry.name
        path = PurePosixPath(name)
        require(isinstance(name, str) and 0 < len(name) <= 256
                and not path.is_absolute()
                and all(p not in ("..", ".") for p in path.parts)
                and "\\" not in name and not name.startswith("/"),
                "ova_member_name_unsafe")
        require(entry.isfile() or entry.isdir(), "ova_member_type_unsafe")
        if entry.isdir():
            continue
        require(0 < entry.size <= MAX_VMDK_BYTES, "ova_member_size_invalid")
        if name.lower().endswith(".vmdk"):
            disks.append(entry)
        elif name.lower().endswith(".ovf"):
            ovf.append(entry)
        else:
            require(name.lower().endswith(".mf"), "ova_member_extension_unsafe")
    require(len(disks) == 1 and len(ovf) == 1, "ova_requires_one_vmdk_and_ovf")
    return disks[0]


def extract_vmdk(ova_path, target):
    """Only private streaming extraction; never tar.extract/all."""
    with tarfile.open(ova_path, "r:*") as archive:
        entry = permitted_ova_disk(archive)
        source = archive.extractfile(entry)
        require(source is not None, "ova_disk_unreadable")
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                remaining = entry.size
                while remaining:
                    block = source.read(min(1048576, remaining))
                    require(block and len(block) <= remaining, "ova_disk_truncated")
                    output.write(block)
                    remaining -= len(block)
                output.flush()
                os.fsync(output.fileno())
        finally:
            source.close()
    return entry.size


def observed_native_identity(raw):
    require(isinstance(raw, str) and len(raw.encode("utf-8")) <= 131072,
            "guest_identity_unbounded")
    lines = raw.splitlines()
    def value(prefix):
        found = [line[len(prefix):].strip().strip('"').strip("'")
                 for line in lines if line.startswith(prefix)]
        return found[0] if len(found) == 1 else None
    osid = value("ID=")
    release = value("HCP_RELEASE=")
    build = value("HCP_BUILD=")
    arch = value("HCP_ARCH=")
    kernel = value("HCP_KERNEL=")
    machine = value("HCP_MACHINE_ID=")
    require(osid == "astra", "guest_not_astra")
    require(release == "1.7.6", "guest_wrong_point_release")
    require(build == "1.7.6.15", "guest_wrong_full_build")
    require(arch == "x86_64", "guest_wrong_architecture")
    require(isinstance(kernel, str) and
            re.fullmatch(r"[A-Za-z0-9_.+:-]{1,120}", kernel),
            "guest_kernel_unverified")
    require(isinstance(machine, str) and
            re.fullmatch(r"[a-f0-9]{32}", machine) and machine != "0" * 32,
            "guest_machine_id_unverified")
    return {
        "osId": "astra", "pointRelease": release, "fullBuild": build,
        "architecture": arch, "kernelObserved": True, "machineIdObserved": True,
        "privateIdentitySha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    }


def trusted_local_scan(raw, port):
    entries = [line for line in raw.splitlines() if line and not line.startswith("#")]
    require(len(entries) == 1, "local_vm_host_key_ambiguous")
    parts = entries[0].split()
    require(len(parts) >= 3 and parts[0] == f"[127.0.0.1]:{port}"
            and parts[1] == "ssh-ed25519"
            and re.fullmatch(r"[A-Za-z0-9+/=]{50,200}", parts[2]),
            "local_vm_host_key_invalid")
    return " ".join(parts[:3]) + "\n"


def exact_pinned_original_ova(work, opener, progress, fetch=download):
    """Cache only immutable *public* official OVA, never guest state.

    A cache hit is fully rehashed and the exclusive 0600 private copy is
    independently rehashed. The checksum originates from the same vendor,
    not an independent publisher signature.
    """
    original = work / FILENAMES["base"]
    cache_arg = os.environ.get("HCP_ASTRA17_PUBLIC_OVA_CACHE_DIR")
    pin = {"bytes": EXPECTED_BYTES, "sha256": EXPECTED_SHA256}
    cached = None
    if cache_arg:
        require(os.environ.get("GITHUB_ACTIONS") == "true" and
                os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                "ova_cache_only_allowed_on_owned_ci")
        cache_dir = Path(cache_arg)
        root = Path(os.environ["RUNNER_TEMP"]).resolve()
        canonical = cache_dir.resolve()
        require(canonical != root and root in canonical.parents and
                not cache_dir.is_symlink(), "ova_cache_path_invalid")
        cache_dir.mkdir(mode=0o700, exist_ok=True)
        st = cache_dir.lstat()
        require(stat.S_ISDIR(st.st_mode) and not (st.st_mode & 0o077),
                "ova_cache_permissions_invalid")
        cached = cache_dir / FILENAMES["base"]
        if cached.exists() or cached.is_symlink():
            require(verified_pinned_file(cached, pin),
                    "ova_cached_sha256_not_exact")
            with cached.open("rb") as source:
                fd = os.open(original, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as destination:
                    shutil.copyfileobj(source, destination, 1048576)
                    destination.flush()
                    os.fsync(destination.fileno())
            require(verified_pinned_file(original, pin),
                    "ova_copied_sha256_not_exact")
            return {"sha256": EXPECTED_SHA256, "bytes": EXPECTED_BYTES,
                    "publisherSignatureVerified": False, "cacheReused": True}
    observed = fetch("base", work, opener=opener, progress=progress,
                     max_seconds=2400, expected_sha256=EXPECTED_SHA256,
                     expected_bytes=EXPECTED_BYTES)
    require(verified_pinned_file(original, pin), "ova_downloaded_sha256_not_exact")
    if cached is not None:
        os.link(original, cached, follow_symlinks=False)
    return {**observed, "cacheReused": False}


def record_native_hcp_three_stage_success(protocol):
    """Mark native success only after the real evidence contract has passed.

    A one-file restoration is not a whole-OS rollback, complete vendor OVAL
    evaluation, host enrollment, or production acceptance.
    """
    native = protocol.get("nativeHcp")
    measurements = native.get("ruleMeasurements") if isinstance(native, dict) else None
    require(
        isinstance(native, dict)
        and native.get("realFactsCollected") is True
        and native.get("realPackageInventoryCollected") is True
        and native.get("real18RuleThreeStageObserved") is True
        and native.get("originalModeRestoredVerified") is True
        and native.get("freshSshSameGuestAfterRestore") is True
        and isinstance(measurements, dict)
        and type(measurements.get("testedRules")) is int
        and measurements["testedRules"] == 18
        and measurements.get("restoredMatchesBaseline18Rules") is True,
        "native_three_stage_public_claim_unverified",
    )
    protocol["realNative18RuleThreeStageObserved"] = True
    protocol["status"] = "native-astra17-ova-hcp-three-stage-only"
    protocol["experiment"] = "exact-native-Astra17-OVA-HCP-18-rule-three-stage-only"
    protocol["limitations"] = [
        "Only one official disposable Astra 1.7.6.15 base OVA, not adv/max or production enrollment",
        "Real original OpenSCAP 18-rule baseline, controlled /etc/passwd violation and one-file restoration only; not a whole-OS/firewall rollback",
        "Full original Astra 1.7 vendor OVAL/CVE evaluation not performed in this experiment",
        "Factory-password bootstrap is prohibited in production",
        "Same-vendor checksum does not cryptographically attest publisher",
        "Raw machine identity, guest disks and private logs remain on runner",
    ]


def experiment(work, protocol, *, native_hcp_three_stage=False,
               native_vendor_oval=False):
    fixed = work / FILENAMES["base"]
    origin = exact_pinned_original_ova(
        work, opener=urllib.request.build_opener(NoRedirect()).open,
        progress=lambda *_: None)
    require(fixed.is_file() and origin["sha256"] == EXPECTED_SHA256
            and origin["bytes"] == EXPECTED_BYTES, "official_ova_digest_mismatch")
    protocol["checks"].append("official_ova_exact_sha256_and_bytes")
    protocol["originalImage"] = {
        "filename": FILENAMES["base"], "sha256": EXPECTED_SHA256,
        "bytes": EXPECTED_BYTES, "publisherSignatureVerified": False,
        "origin": "same_vendor_artifactory_not_independent_signature",
        "cachedPublicSourceByteVerified": origin["cacheReused"],
    }
    vmdk = work / "source.vmdk"
    protocol["originalImage"]["vmdkBytes"] = extract_vmdk(fixed, vmdk)
    protocol["checks"].append("safe_ova_tar_member_validation")
    info = json.loads(run(["qemu-img", "info", "--output=json", "-f", "vmdk",
                           str(vmdk)]))
    require(info.get("format") == "vmdk" and not info.get("backing-filename")
            and isinstance(info.get("virtual-size"), int)
            and 2 * 1024 ** 3 < info["virtual-size"] <= 50 * 1024 ** 3,
            "vmdk_format_invalid")
    base = work / "converted.qcow2"
    run(["qemu-img", "convert", "-f", "vmdk", "-O", "qcow2",
         str(vmdk), str(base)], timeout=900)
    checked = json.loads(run(["qemu-img", "info", "--output=json", str(base)]))
    require(checked.get("format") == "qcow2"
            and not checked.get("backing-filename")
            and checked.get("virtual-size") == info["virtual-size"],
            "converted_source_disk_invalid")
    overlay = work / "overlay.qcow2"
    run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
         "-b", str(base), str(overlay)])
    protocol["checks"].append("qemu_source_conversion_and_private_overlay")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    protocol["acceleration"] = acceleration
    qemu = ["qemu-system-x86_64", "-machine", "pc,accel=" + acceleration,
            "-m", "4096", "-smp", "2", "-display", "none",
            "-monitor", "none", "-no-reboot",
            "-serial", "file:" + str(work / "private-console.log"),
            "-drive", "file=" + str(overlay) + ",format=qcow2,if=virtio",
            "-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:"
            + str(port) + "-:22", "-device", "virtio-net-pci,netdev=n0"]
    if acceleration == "kvm":
        qemu.extend(["-cpu", "host"])
    with (work / "private-qemu.log").open("wb") as qemu_output:
        process = subprocess.Popen(qemu, stdout=qemu_output,
                                   stderr=subprocess.STDOUT)
        try:
            pwd = work / "public-factory-password"
            pwd.write_text("astra\n", encoding="ascii")
            pwd.chmod(0o600)
            known = work / "known_hosts"
            options = ["-F", "/dev/null", "-p", str(port),
                       "-o", "StrictHostKeyChecking=yes",
                       "-o", "UserKnownHostsFile=" + str(known),
                       "-o", "GlobalKnownHostsFile=/dev/null",
                       "-o", "UpdateHostKeys=no",
                       "-o", "HostKeyAlgorithms=ssh-ed25519",
                       "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1"]
            observation = ("set -eu; cat /etc/os-release; "
                           "printf '\\nHCP_RELEASE='; cat /etc/astra_version; "
                           "printf '\\nHCP_BUILD='; cat /etc/astra/build_version; "
                           "printf '\\nHCP_ARCH='; uname -m; "
                           "printf 'HCP_KERNEL='; uname -r; "
                           "printf 'HCP_MACHINE_ID='; cat /etc/machine-id")
            first, pinned = None, None
            deadline = time.monotonic() + (360 if acceleration == "kvm" else 900)
            while time.monotonic() < deadline:
                require(process.poll() is None, "guest_exited_before_ssh")
                try:
                    scan = run(["ssh-keyscan", "-T", "5", "-t", "ed25519",
                                "-p", str(port), "127.0.0.1"], timeout=12)
                    keyline = trusted_local_scan(scan, port)
                    if not known.exists():
                        fd = os.open(known, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "w", encoding="ascii") as stream:
                            stream.write(keyline)
                    require(known.read_text() == keyline,
                            "guest_host_key_changed_during_boot")
                    native = run(["sshpass", "-f", str(pwd), "ssh", *options,
                                  "astra@127.0.0.1", observation], timeout=20)
                    first = observed_native_identity(native)
                    pinned = hashlib.sha256(keyline.encode("ascii")).hexdigest()
                    break
                except RuntimeError:
                    time.sleep(4)
            require(first is not None, "guest_ssh_preflight_unavailable")
            protocol["checks"].append("real_guest_astra_point_build_and_ssh_observed")
            protocol["nativeGuest"] = {
                **first, "sshHostKeyLineSha256": pinned,
                "sshTrustModel": "isolated_disposable_guest_tofu",
                "hcpEnrollmentVerified": False,
            }
            second = run(["sshpass", "-f", str(pwd), "ssh", *options,
                          "astra@127.0.0.1", observation], timeout=20)
            require(first == observed_native_identity(second),
                    "fresh_ssh_guest_identity_changed")
            protocol["checks"].append("fresh_pinned_ssh_identity_stable")
            if native_hcp_three_stage:
                # Deliberate CI-only extension on the owned disposable guest.
                from verify_astra17_ova_audit import run_native_audit
                run_native_audit(
                    work, protocol, port=port, known_hosts=known,
                    ssh_options=options, password=pwd,
                    original_identity=second, observation=observation,
                    safe_command=run, parse_identity=observed_native_identity,
                    native_vendor_oval=native_vendor_oval)
                record_native_hcp_three_stage_success(protocol)
                if native_vendor_oval:
                    require(protocol.get("nativeHcp", {}).get("fullOvalEvaluated") is True,
                            "native_oval_full_selected_scope_not_verified")
                    protocol["status"] = "native-astra17-ova-hcp-and-full-oval-scope"
                    protocol["experiment"] = (
                        "exact-native-Astra17-HCP-18-rule-and-selected-vendor-OVAL-only"
                    )
                    protocol["limitations"] = [
                        "Only official disposable Astra 1.7.6.15 base OVA, not adv/max or production enrollment",
                        "Original 18-rule three-stage experiment, not a whole-OS/firewall rollback",
                        "Full exact selected vendor OVAL definition scope only; universal CVE recall and applicability not established",
                        "Normalized OVAL report omits verbose auxiliary XML evidence explicitly, preserving all raw definition IDs and states",
                        "Factory-password bootstrap is prohibited in production",
                        "Same-vendor checksum does not authenticate publisher independently",
                        "Raw machine identity, guest disks and private logs remain on runner",
                    ]
            else:
                protocol["status"] = "genuine-astra17-ova-ssh-preflight-only"
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--public-protocol", required=True)
    parser.add_argument("--native-hcp-three-stage", action="store_true",
                        help="Run real HCP audit only on own disposable CI VM")
    parser.add_argument("--native-vendor-oval", action="store_true",
                        help="Require complete original Astra 1.7 OVAL on that same guest")
    args = parser.parse_args()
    require(not args.native_vendor_oval or args.native_hcp_three_stage,
            "full_oval_requires_native_hcp_three_stage")
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "unsafe_runner")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    work, public = Path(args.work_dir).resolve(), Path(args.public_protocol).resolve()
    require(work != temp and temp in work.parents and
            public != temp and temp in public.parents and
            not work.exists() and not public.exists(),
            "private_paths_invalid")
    work.mkdir(mode=0o700)
    report = {
        "schemaVersion": 1, "status": "pending",
        "experiment": "exact-native-Astra17-OVA-SSH-only",
        "observedAtUtc": datetime.now(timezone.utc).isoformat(),
        "checks": [], "fullNative18RuleAcceptance": False,
        "realNative18RuleThreeStageObserved": False,
        "realHcpNativeExperimentRequested": args.native_hcp_three_stage,
        "nativeVendorOval17Requested": args.native_vendor_oval,
        "nativeVendorOval17Evaluated": False,
        "ovalEvaluationPerformed": False, "hardenedProdReady": False,
        "publisherSignatureIndependentlyVerified": False,
        "limitations": [
            "Only official base OVA and temporary local SSH smoke test",
            "No OpenSCAP/OVAL baseline, no rollback, no real HCP host enrollment",
            "Factory-password bootstrap is prohibited in production",
            "Same-vendor checksum does not cryptographically attest publisher",
            "Raw machine identity, guest disks and private logs remain on runner",
        ],
    }
    try:
        experiment(work, report,
                   native_hcp_three_stage=args.native_hcp_three_stage,
                   native_vendor_oval=args.native_vendor_oval)
        report["nativeVendorOval17Evaluated"] = bool(
            args.native_vendor_oval
            and report.get("nativeHcp", {}).get("fullOvalEvaluated") is True)
    except BaseException as exc:
        allowed = {
            "ova_member_count_invalid", "ova_member_name_unsafe",
            "ova_member_type_unsafe", "ova_member_size_invalid",
            "ova_member_extension_unsafe", "ova_requires_one_vmdk_and_ovf",
            "ova_disk_unreadable", "ova_disk_truncated",
            "official_ova_digest_mismatch", "vmdk_format_invalid",
            "converted_source_disk_invalid", "guest_exited_before_ssh",
            "guest_host_key_changed_during_boot", "guest_ssh_preflight_unavailable",
            "guest_not_astra", "guest_wrong_point_release",
            "guest_wrong_full_build", "guest_wrong_architecture",
            "guest_kernel_unverified", "guest_machine_id_unverified",
            "local_vm_host_key_ambiguous", "local_vm_host_key_invalid",
            "fresh_ssh_guest_identity_changed", "unsafe_runner",
            "private_paths_invalid", "subprocess_failed",
            "native_identity_changed_after_key_enrollment",
            "native_ssh_asset_identity_unverified",
            "new_ephemeral_public_key_invalid",
            "native_ansible_facts_not_astra",
            "native_installed_packages_missing",
            "original_report_missing_or_unbounded",
            "ansible_execution_unavailable", "ansible_playbook_failed",
            "native_openscap_original_evidence_missing",
            "incomplete_native_18_rule_scope", "native_rules_partial_or_unknown",
            "passwd_mode_not_suitable_for_safe_control",
            "passwd_original_mode_not_restored",
            "native_asset_identity_changed_after_restore",
            "source_bundle_not_stable",
            "native_three_stage_public_claim_unverified",
            "native_oval_full_selected_scope_not_verified",
            "native_oval_normalized_report_missing",
            "native_oval_normalized_report_empty",
            "native_oval_normalized_report_unsafe_type",
            "native_oval_normalized_report_oversized",
            "native_oval_bounded_projection_not_attested",
            "native_oscap_schema_probe_unparseable",
            "native_scap_schema_provision_forbidden_outside_ci",
            "native_scap_required_schema_missing_despite_installed_package",
            "native_vendor_scap_schema_package_unavailable",
            "native_required_scap_schema_still_missing_after_vendor_install",
            "native_openscap_evaluation_form_misrepresented",
            "full_oval_requires_native_hcp_three_stage",
            "oval_source_id_invalid_or_duplicate",
            "oval_source_too_many_definitions", "oval_source_has_no_definitions",
            "oval_original_source_digest_invalid",
            "native_oval_report_scope_invalid", "native_oval_scanner_metadata_missing",
            "native_oval_wrong_observed_guest", "native_oval_source_sha_missing_or_mismatch",
            "native_oval_scanner_not_completed", "native_oval_partial_or_unavailable",
            "native_oval_unresolved_partial_reasons",
            "oval_source_definition_count_mismatch",
            "oval_evaluated_definition_count_mismatch",
            "native_oval_definition_results_incomplete",
            "native_oval_definition_result_invalid",
            "native_oval_unknown_or_duplicate_definition",
            "native_oval_unrecognized_result",
            "native_oval_definition_unresolved_or_error",
            "native_oval_source_result_set_differs",
            "native_oval_raw_results_sha_missing",
            "native_oval_fabricated_security_score",
            "subprocess_unavailable_or_timeout", "subprocess_output_unbounded",
        }
        reason = str(exc) if isinstance(exc, RuntimeError) else ""
        report["status"] = "native-ova-preflight-failed"
        report["failureCode"] = reason if reason in allowed else "unclassified"
        raise
    finally:
        fd = os.open(public, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(report, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())


if __name__ == "__main__":
    main()
