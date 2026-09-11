#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HCP-authored read-only SCE baseline, Python 3.5+.

Only XCCDF_VALUE_check_id chooses among fixed checks. No command, path, fixture
root, or OS override is accepted from the environment. Checks deliberately cover
local accounts, global SSH configuration and current kernel values, not every
possible identity source, SSH Match context, boot setting or Astra MAC policy.
"""
from __future__ import print_function

import errno
import grp
import json
import os
import re
import shutil
import stat
import subprocess
import sys


PASS, FAIL, ERROR, UNKNOWN, NOT_APPLICABLE = 101, 102, 103, 104, 105
MAX_BYTES = 1024 * 1024
OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release")
FILE_CHECKS = {
    "passwd_permissions": ("/etc/passwd", 0o644, False),
    "group_permissions": ("/etc/group", 0o644, False),
    "shadow_permissions": ("/etc/shadow", 0o640, False),
    "gshadow_permissions": ("/etc/gshadow", 0o640, True),
}
SSH_CHECKS = {
    "ssh_root_login": ("permitrootlogin", ("no",)),
    "ssh_empty_passwords": ("permitemptypasswords", ("no",)),
    "ssh_max_auth_tries": ("maxauthtries", ("1", "2", "3", "4")),
    "ssh_x11_forwarding": ("x11forwarding", ("no",)),
}
SYSCTL_CHECKS = {
    "protected_hardlinks": ("fs.protected_hardlinks", (1,)),
    "protected_symlinks": ("fs.protected_symlinks", (1,)),
    "ptrace_scope": ("kernel.yama.ptrace_scope", (1, 2, 3)),
    "kptr_restrict": ("kernel.kptr_restrict", (1, 2)),
    "dmesg_restrict": ("kernel.dmesg_restrict", (1,)),
}
CHECK_IDS = frozenset(FILE_CHECKS) | frozenset(SSH_CHECKS) | frozenset(SYSCTL_CHECKS) | frozenset((
    "root_account", "unique_uid_zero", "empty_local_passwords", "auditd_running"))


def result(code, **details):
    return code, details


def read_text(path):
    # /etc/os-release is commonly a symlink; following it is intentional.
    # NONBLOCK + fstat avoids hanging on a replaced FIFO/device. All expected
    # ordinary files and proc sysctl nodes identify as regular files.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("inspection requires a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            data = stream.read(MAX_BYTES + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(data) > MAX_BYTES:
        raise ValueError("file exceeds inspection limit")
    return data.decode("utf-8", "strict")


def astra_identity():
    """Astra family identity, without executing os-release or guessing release."""
    for path in OS_RELEASE_PATHS:
        try:
            source = read_text(path)
        except OSError as error:
            if error.errno == errno.ENOENT:
                continue
            raise
        fields = {}
        for line in source.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator:
                continue
            if key in ("ID", "ID_LIKE"):
                if key in fields:
                    raise ValueError("ambiguous OS identity")
                fields[key] = value.strip().strip("\"'")
        if not fields.get("ID"):
            raise ValueError("OS ID is absent")
        return fields["ID"].lower() == "astra" or "astra" in fields.get("ID_LIKE", "").lower().split()
    raise ValueError("OS identity unavailable")


def command(argv):
    # Fixed argv only; no shell and no caller-supplied commands. Diagnostics
    # never include sshd output wholesale or local shadow/password contents.
    process = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=20,
                             env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if len(process.stdout) > MAX_BYTES or len(process.stderr) > MAX_BYTES:
        raise ValueError("command output exceeds inspection limit")
    return process


def file_permissions(identifier):
    path, allowed, optional = FILE_CHECKS[identifier]
    try:
        metadata = os.lstat(path)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return result(NOT_APPLICABLE if optional else UNKNOWN, path=path, reason="file_missing")
        raise
    if not stat.S_ISREG(metadata.st_mode):
        return result(UNKNOWN, path=path, reason="not_a_regular_file_or_is_symlink")
    groups = {0}
    if identifier in ("shadow_permissions", "gshadow_permissions"):
        try:
            groups.add(grp.getgrnam("shadow").gr_gid)
        except KeyError:
            pass
    mode = stat.S_IMODE(metadata.st_mode)
    ok = metadata.st_uid == 0 and metadata.st_gid in groups and (mode & ~allowed) == 0
    return result(PASS if ok else FAIL, path=path, mode=oct(mode), ownerUid=metadata.st_uid,
                  groupGid=metadata.st_gid, maximumMode=oct(allowed), allowedGroupGids=sorted(groups))


def local_accounts(identifier):
    path = "/etc/shadow" if identifier == "empty_local_passwords" else "/etc/passwd"
    rows = []
    expected = 9 if path == "/etc/shadow" else 7
    for line in read_text(path).splitlines():
        if not line.strip():
            continue
        row = line.split(":")
        if len(row) != expected or not re.match(r"^[^:\s]+$", row[0]):
            return result(UNKNOWN, path=path, reason="malformed_local_account_file")
        # NIS compatibility rows do not enumerate the remote identities.
        if row[0].startswith(("+", "-")):
            return result(UNKNOWN, path=path, reason="external_account_expansion_not_evaluated")
        rows.append(row)
    if not rows or len({row[0] for row in rows}) != len(rows):
        return result(UNKNOWN, path=path, reason="empty_or_duplicate_local_accounts")
    if identifier == "empty_local_passwords":
        empty = sorted(row[0] for row in rows if row[1] == "")
        return result(FAIL if empty else PASS, scope="local_shadow_entries", emptyPasswordAccounts=empty)
    try:
        ids = [(row[0], int(row[2]), int(row[3])) for row in rows]
    except ValueError:
        return result(UNKNOWN, path=path, reason="malformed_uid_or_gid")
    if any(uid < 0 or gid < 0 for _, uid, gid in ids):
        return result(UNKNOWN, path=path, reason="invalid_uid_or_gid")
    if identifier == "root_account":
        root = [entry for entry in ids if entry[0] == "root"]
        ok = root == [("root", 0, 0)]
        return result(PASS if ok else FAIL, scope="local_passwd_entries", rootUidGid=root)
    owners = sorted(name for name, uid, _ in ids if uid == 0)
    return result(PASS if owners == ["root"] else FAIL, scope="local_passwd_entries", uidZeroAccounts=owners)


def ssh_configuration(identifier):
    executable = shutil.which("sshd", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable:
        present = os.path.exists("/etc/ssh/sshd_config")
        return result(UNKNOWN if present else NOT_APPLICABLE, reason="sshd_executable_missing")
    process = command([executable, "-T"])
    if process.returncode != 0:
        return result(UNKNOWN, scope="global_sshd_T", reason="effective_configuration_unavailable",
                      commandExitCode=process.returncode)
    setting, accepted = SSH_CHECKS[identifier]
    values = [line.split(None, 1)[1].strip().lower() for line in process.stdout.splitlines()
              if len(line.split(None, 1)) == 2 and line.split(None, 1)[0].lower() == setting]
    if len(values) != 1:
        return result(UNKNOWN, setting=setting, reason="effective_setting_missing_or_ambiguous")
    return result(PASS if values[0] in accepted else FAIL, scope="global_sshd_T_without_Match_contexts",
                  setting=setting, actual=values[0], accepted=list(accepted))


def kernel_setting(identifier):
    setting, accepted = SYSCTL_CHECKS[identifier]
    path = "/proc/sys/" + setting.replace(".", "/")
    try:
        value = int(read_text(path).strip())
    except OSError as error:
        if error.errno == errno.ENOENT:
            return result(NOT_APPLICABLE, setting=setting, reason="kernel_interface_unavailable")
        raise
    return result(PASS if value in accepted else FAIL, scope="running_kernel_not_boot_persistence",
                  setting=setting, actual=value, accepted=list(accepted))


def audit_service():
    executable = shutil.which("systemctl", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable or not os.path.isdir("/run/systemd/system"):
        return result(UNKNOWN, reason="audit_service_state_requires_systemd")
    process = command([executable, "show", "auditd.service", "--property=LoadState", "--property=ActiveState"])
    if process.returncode != 0:
        return result(UNKNOWN, reason="audit_service_query_failed", commandExitCode=process.returncode)
    fields = dict(line.split("=", 1) for line in process.stdout.splitlines() if "=" in line)
    if fields.get("LoadState") == "not-found":
        return result(FAIL, reason="auditd_not_installed", loadState="not-found")
    if fields.get("LoadState") not in ("loaded", "masked") or not fields.get("ActiveState"):
        return result(UNKNOWN, reason="audit_service_state_unavailable")
    return result(PASS if fields["ActiveState"] == "active" else FAIL,
                  scope="auditd_service_running_not_rule_completeness", activeState=fields["ActiveState"])


def evaluate(identifier):
    if identifier not in CHECK_IDS:
        return result(UNKNOWN, reason="unrecognized_check")
    try:
        if not astra_identity():
            return result(NOT_APPLICABLE, reason="host_is_not_astra_family")
        if os.geteuid() != 0:
            return result(UNKNOWN, reason="root_required_for_complete_observation")
        if identifier in FILE_CHECKS:
            return file_permissions(identifier)
        if identifier in SSH_CHECKS:
            return ssh_configuration(identifier)
        if identifier in SYSCTL_CHECKS:
            return kernel_setting(identifier)
        if identifier == "auditd_running":
            return audit_service()
        return local_accounts(identifier)
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as error:
        return result(UNKNOWN, reason="observation_failed", errorType=type(error).__name__)


def main():
    identifier = os.environ.get("XCCDF_VALUE_check_id", "")
    code, details = evaluate(identifier)
    details["check"] = identifier
    print(json.dumps(details, ensure_ascii=True, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
