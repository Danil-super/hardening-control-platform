#!/usr/bin/env python3
"""Native SELinux metadata acceptance on an enforcing RPM-family VM.

Run as root with SELinux Enforcing and firewalld installed:
    python3 ansible/tests/native_selinux_firewall_acceptance.py

All writes are inside a private temporary fixture. /etc/firewalld and /etc/passwd
are read solely as sources of valid policy contexts. The production backup,
manifest, restoration and recovery code performs real xattr and filesystem I/O.
Firewall commands are explicitly fixture I/O; a separate VM network acceptance
must verify the real firewalld service and connectivity. No setenforce, relabel
of /etc, policy change or xattr emulation is used here. A disabled/permissive
SELinux host is an error, never a passing or skipped native acceptance result.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/hcp-firewall.py"
TRANSACTION = "txn-native-selinux-12345678"


def helper():
    spec = importlib.util.spec_from_file_location("native_selinux_firewall", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_enforcing():
    if os.geteuid() != 0:
        raise RuntimeError("Native SELinux acceptance requires root on an enforcing VM.")
    if subprocess.check_output(["getenforce"]).strip() != b"Enforcing":
        raise RuntimeError("Native SELinux acceptance requires Enforcing; no policy changes are made.")


def fixture_helper(root):
    root = root.resolve()
    if not root.name.startswith("hcp-selinux-acceptance-") or Path(tempfile.gettempdir()).resolve() not in root.parents:
        raise RuntimeError("Refusing non-temporary acceptance fixture.")
    if root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077 or (root / "fixture-owner").read_text() != TRANSACTION:
        raise RuntimeError("Refusing unrecognized acceptance fixture.")
    module = helper()
    module.CONFIG_ROOT, module.BACKUP_ROOT = root / "etc", root / "backups"
    module.backend = lambda: "firewalld"
    module.persistent_firewalld = lambda: None

    def fixture_command(*argv, **kwargs):
        if argv != ("firewall-cmd", "--reload"):
            raise AssertionError("Unexpected fixture command: {}".format(argv))
        with (root / "reloads").open("a") as stream:
            stream.write("reload\n")
            stream.flush()
            os.fsync(stream.fileno())
        return subprocess.CompletedProcess(argv, 0, "", "")

    module.run = fixture_command
    return module


def child(root, operation, failpoint):
    require_enforcing()
    module = fixture_helper(root)
    arguments = argparse.Namespace(operation=operation, transaction=TRANSACTION, check=False, recovery_verified=True)
    original_rename = Path.rename

    def rename(source, target):
        result = original_rename(source, target)
        stage = "after_move_old" if source == module.CONFIG_ROOT / "firewalld" else "after_install"
        if failpoint == stage:
            os.kill(os.getpid(), signal.SIGKILL)
        return result

    original_checkpoint = module.rollback_checkpoint

    def checkpoint(directory, state, phase):
        original_checkpoint(directory, state, phase)
        if failpoint == "after_prepared" and phase == "prepared":
            os.kill(os.getpid(), signal.SIGKILL)

    Path.rename = rename
    module.rollback_checkpoint = checkpoint
    try:
        print(json.dumps(module.execute_operation(arguments), sort_keys=True))
    except (module.FirewallError, OSError, ValueError, KeyError) as error:
        print(json.dumps({"ok": False, "error": str(error), "outcomeUnknown": module.outcome_is_unknown(arguments, error)}, sort_keys=True))
        return 1
    return 0


def invoke(root, operation, failpoint=""):
    return subprocess.run([sys.executable, str(Path(__file__).resolve()), "--child-root", str(root),
                           "--operation", operation, "--failpoint", failpoint],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=45)


def successful(result):
    if result.returncode != 0:
        raise AssertionError("Acceptance child failed: {} {}".format(result.stdout, result.stderr))
    value = json.loads(result.stdout)
    if not value.get("ok"):
        raise AssertionError("Acceptance child reported failure: {}".format(result.stdout))
    return value


def inventory(module, tree):
    paths = [tree] + sorted(tree.rglob("*"))
    return {str(path.relative_to(tree)): os.getxattr(str(path), module.SELINUX_LABEL, follow_symlinks=False).hex() for path in paths}


def acceptance():
    require_enforcing()
    directory_context = os.getxattr("/etc/firewalld", "security.selinux", follow_symlinks=False)
    file_context = os.getxattr("/etc/passwd", "security.selinux", follow_symlinks=False)
    checks = []
    for failpoint in ("", "after_move_old", "after_install", "after_prepared"):
        with tempfile.TemporaryDirectory(prefix="hcp-selinux-acceptance-") as temporary:
            root = Path(temporary)
            (root / "fixture-owner").write_text(TRANSACTION)
            tree = root / "etc/firewalld"
            (tree / "zones").mkdir(parents=True)
            (root / "etc/machine-id").write_text("native-selinux-temporary-target")
            rules = tree / "zones/owned.xml"
            rules.write_text("<zone><short>owned acceptance fixture</short></zone>\n")
            module = fixture_helper(root)
            for path in (tree, tree / "zones", rules):
                value = directory_context if path.is_dir() else file_context
                os.setxattr(str(path), module.SELINUX_LABEL, value, follow_symlinks=False)
                if os.getxattr(str(path), module.SELINUX_LABEL, follow_symlinks=False) != value:
                    raise AssertionError("Native SELinux context bytes did not round trip.")
            expected, expected_labels = module.tree_digest(tree), inventory(module, tree)
            successful(invoke(root, "backup"))
            directory = root / "backups" / TRANSACTION
            metadata = module.read_control_json(directory / "metadata.json")
            if metadata.get("securityLabels") != "pax-v2" or metadata.get("filesystemMetadata") != "posix-security-v2":
                raise AssertionError("Backup omitted the versioned SELinux manifest.")
            with tarfile.open(str(directory / "firewall-state.tar.gz")) as archive:
                module.validate_archive_labels(archive, metadata)
                if module.archive_digest(archive, "firewalld") != expected:
                    raise AssertionError("Native archive does not match the original label manifest.")
            rules.write_text("<zone><short>modified fixture</short></zone>\n")
            if failpoint:
                killed = invoke(root, "rollback", failpoint)
                if killed.returncode != -signal.SIGKILL:
                    raise AssertionError("Rollback did not reach the requested kill point: {} {}".format(killed.stdout, killed.stderr))
                if failpoint == "after_prepared":
                    journal = module.read_control_json(directory / "rollback-state.json")
                    prepared_rule = root / "etc" / journal["stagingName"] / "etc/firewalld/zones/owned.xml"
                    if directory_context == file_context:
                        raise AssertionError("Acceptance needs distinct native directory and file contexts for tampering.")
                    os.setxattr(str(prepared_rule), module.SELINUX_LABEL, directory_context, follow_symlinks=False)
                    rejected = invoke(root, "rollback")
                    if rejected.returncode != 1 or "saved manifest" not in json.loads(rejected.stdout).get("error", ""):
                        raise AssertionError("SELinux-only prepared tree tampering was not rejected.")
                    if (root / "reloads").exists() or "modified fixture" not in rules.read_text():
                        raise AssertionError("Tampered restore replaced live fixture or submitted a reload.")
                    os.setxattr(str(prepared_rule), module.SELINUX_LABEL, file_context, follow_symlinks=False)
            successful(invoke(root, "rollback"))
            if module.tree_digest(tree) != expected or inventory(module, tree) != expected_labels:
                raise AssertionError("Native SELinux labels or configuration changed during recovery.")
            replay = successful(invoke(root, "rollback"))
            if replay.get("changed") or (root / "reloads").read_text().splitlines() != ["reload"]:
                raise AssertionError("Completed rollback was not idempotently replayed.")
            require_enforcing()
            checks.append(failpoint or "round_trip")
    print(json.dumps({"ok": True, "selinux": "Enforcing", "realSecuritySelinuxXattrs": True,
                      "filesystemAndCrashRecoveryChecks": checks,
                      "firewallIO": "isolated fixture; native service/traffic acceptance is separate",
                      "directoryContextHex": directory_context.hex(), "fileContextHex": file_context.hex()}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child-root", type=Path)
    parser.add_argument("--operation", choices=("backup", "rollback"))
    parser.add_argument("--failpoint", default="", choices=("", "after_move_old", "after_install", "after_prepared"))
    args = parser.parse_args()
    if args.child_root:
        if not args.operation:
            parser.error("--operation is required with --child-root")
        return child(args.child_root, args.operation, args.failpoint)
    acceptance()
    return 0


if __name__ == "__main__":
    sys.exit(main())
