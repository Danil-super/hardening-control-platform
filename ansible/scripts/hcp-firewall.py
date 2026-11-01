#!/usr/bin/env python3
"""Validated firewall operations used by HCP. Never enables a firewall implicitly."""
import argparse
import contextlib
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid

CONFIG_ROOT = Path("/etc")
BACKUP_ROOT = Path("/var/lib/hcp-backups")
SECURITY_LABEL = "security.PDPL"
LABEL_HEADER = "HCP.security.PDPL"
SELINUX_LABEL = "security.selinux"
SELINUX_HEADER = "HCP.security.selinux"
LABEL_HEADERS = {SECURITY_LABEL: LABEL_HEADER, SELINUX_LABEL: SELINUX_HEADER}
LEGACY_FILESYSTEM_METADATA = "posix-pdpl-v1"
FILESYSTEM_METADATA = "posix-security-v2"
STATE_NAME = ".operation-state.json"
ROLLBACK_PHASES = {"preparing", "prepared", "move_old_intent", "old_saved", "install_intent", "installed",
                   "reload_intent", "reload_unknown", "reload_failed", "reload_completed", "completed"}

class FirewallError(RuntimeError):
    def __init__(self, message, outcome_unknown=False):
        super().__init__(message)
        self.outcome_unknown = outcome_unknown


def run(*args, acceptable=(0,)):
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45,
                                env={**os.environ, "LC_ALL": "C"})
        result.stdout = result.stdout.decode("utf-8", "replace") if isinstance(result.stdout, bytes) else result.stdout
        result.stderr = result.stderr.decode("utf-8", "replace") if isinstance(result.stderr, bytes) else result.stderr
    except subprocess.TimeoutExpired as error:
        # Killing a local client does not cancel an in-flight daemon request
        # or prove that a descendant stopped changing the firewall.
        raise FirewallError(str(error), outcome_unknown=True) from error
    except OSError as error:
        raise FirewallError(str(error)) from error
    if result.returncode not in acceptable:
        raise FirewallError('{}: {}'.format(' '.join(args), result.stderr.strip() or result.stdout.strip()), outcome_unknown=result.returncode < 0)
    return result


def backend():
    ufw = shutil.which("ufw") is not None and "Status: active" in run("ufw", "status").stdout
    firewalld = shutil.which("firewall-cmd") is not None and run("firewall-cmd", "--state", acceptable=(0, 252)).stdout.strip() == "running"
    if ufw == firewalld:
        raise FirewallError("Exactly one supported firewall must be active: UFW or firewalld.")
    return "ufw" if ufw else "firewalld"


def firewalld_configuration_blocks(value):
    """Ignore display-only activity and the order of independent zone/policy blocks.

    Runtime getZones() and permanent getZoneNames() need not have the same order.
    Keep every field and the order of rules inside a block: those affect policy.
    """
    blocks = []
    current = []
    for line in value.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            if current:
                blocks.append(tuple(current))
            header = re.fullmatch(r"([A-Za-z0-9_-]+)(?: \(([^)]+)\))?", line.strip())
            if header:
                attributes = [item.strip() for item in (header.group(2) or "").split(",") if item.strip() and item.strip() != "active"]
                line = header.group(1) + (" (" + ", ".join(attributes) + ")" if attributes else "")
            current = [line.rstrip()]
        else:
            current.append(line.rstrip())
    if current:
        blocks.append(tuple(current))
    return sorted(blocks)


def persistent_firewalld():
    runtime = run("firewall-cmd", "--list-all-zones").stdout
    permanent = run("firewall-cmd", "--permanent", "--list-all-zones").stdout
    if firewalld_configuration_blocks(runtime) != firewalld_configuration_blocks(permanent):
        raise FirewallError("firewalld runtime and permanent configuration differ. Reconcile them before remediation to preserve rollback.")
    # Policies have a separate API on versions that provide policy objects.
    # Their runtime-only changes would also be discarded by rollback's reload.
    if "--list-all-policies" in run("firewall-cmd", "--help").stdout:
        runtime_policies = run("firewall-cmd", "--list-all-policies").stdout
        permanent_policies = run("firewall-cmd", "--permanent", "--list-all-policies").stdout
        if firewalld_configuration_blocks(runtime_policies) != firewalld_configuration_blocks(permanent_policies):
            raise FirewallError("firewalld runtime and permanent policies differ; rollback cannot be guaranteed.")
    # Direct rules are a separate API and must also be preserved.
    # Preserve their order: rules with equal priority can depend on insertion order.
    for option in ("--get-all-rules", "--get-all-chains", "--get-all-passthroughs"):
        if run("firewall-cmd", "--direct", option).stdout != run("firewall-cmd", "--permanent", "--direct", option).stdout:
            raise FirewallError("firewalld runtime and permanent direct rules differ; rollback cannot be guaranteed.")
    persistent_firewalld_ipsets()


def firewalld_ipset_info(output):
    """Compare the membership that reload would replace, not just zone names.

    Timeout entries are not tracked by firewalld. Refuse them even when the
    printed lists happen to agree; a filesystem backup cannot preserve them.
    """
    fields = {}
    lines = output.splitlines()
    if not lines or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", lines[0].strip()):
        raise FirewallError("Cannot verify firewalld IP set definition.")
    for line in lines[1:]:
        if not line.strip():
            continue
        match = re.fullmatch(r"\s+(type|options|entries):\s*(.*)", line)
        if not match or match.group(1) in fields:
            raise FirewallError("Unsupported firewalld IP set output; rollback cannot be guaranteed.")
        fields[match.group(1)] = tuple(sorted(match.group(2).split()))
    if set(fields) != {"type", "options", "entries"} or len(fields["type"]) != 1:
        raise FirewallError("Incomplete firewalld IP set definition; rollback cannot be guaranteed.")
    if any(option.split("=", 1)[0] == "timeout" for option in fields["options"]):
        raise FirewallError("firewalld IP sets with timeout entries cannot be safely backed up for rollback.")
    return fields


def persistent_firewalld_ipsets():
    names = []
    for persistence in ([], ["--permanent"]):
        # Do not silently skip a missing/failed capability. In that case the
        # operator needs to reconcile or back up the firewall independently.
        values = run("firewall-cmd", *persistence, "--get-ipsets").stdout.split()
        if len(values) != len(set(values)) or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value) for value in values):
            raise FirewallError("Cannot verify firewalld IP set names.")
        names.append(set(values))
    if names[0] != names[1]:
        raise FirewallError("firewalld runtime and permanent IP sets differ; rollback cannot be guaranteed.")
    for name in sorted(names[0]):
        runtime = firewalld_ipset_info(run("firewall-cmd", "--info-ipset=" + name).stdout)
        permanent = firewalld_ipset_info(run("firewall-cmd", "--permanent", "--info-ipset=" + name).stdout)
        if runtime != permanent:
            raise FirewallError("firewalld runtime and permanent IP set definitions or entries differ; rollback cannot be guaranteed.")


def ufw_numbered_rules(status):
    rows = []
    for raw_line in status.splitlines():
        # UFW's compact/numbered display may omit IN for the default incoming
        # direction; columns also contain alignment spaces. Ignore comments
        # only after locating the numbered rule, not the rule's direction.
        line = raw_line.split("#", 1)[0].strip()
        number = re.match(r"^\[\s*(\d+)\]", line)
        if not number:
            continue
        version = 6 if "(v6)" in line else 4
        text = " ".join(line[number.end():].replace("(v6)", "").split())
        for token in text.split():
            try:
                if ipaddress.ip_network(token, strict=False).version == 6:
                    version = 6
            except ValueError:
                pass
        rows.append({"number": int(number.group(1)), "version": version, "text": text})
    return rows


def ufw_ipv6_enabled():
    # UFW reads this setting even when its ruleset has no IPv6 rules yet.
    configuration = (CONFIG_ROOT / "default/ufw").read_text()
    value = re.search(r'^\s*IPV6\s*=\s*["\']?(yes|no)["\']?\s*(?:#.*)?$', configuration, re.M | re.I)
    if not value:
        raise FirewallError("Cannot determine UFW IPv6 policy from /etc/default/ufw.")
    return value.group(1).lower() == "yes"


def close_or_block(args):
    selected = backend()
    mutation_outputs = []
    if args.operation == "closePort":
        if not args.port or not 1 <= args.port <= 65535 or args.protocol not in ("tcp", "udp"):
            raise FirewallError("Invalid port or protocol.")
        if args.protocol == "tcp" and args.port in (22, args.ssh_port):
            raise FirewallError("The management SSH port cannot be closed automatically.")
        ufw_rule = ["deny", '{}/{}'.format(args.port, args.protocol)]
        rich_rules = ['rule family="{}" priority="-32768" port port="{}" protocol="{}" drop'.format(family, args.port, args.protocol) for family in ("ipv4", "ipv6")]
    else:
        try:
            address = ipaddress.IPv4Address(args.ip)
        except ipaddress.AddressValueError as error:
            raise FirewallError("Invalid IPv4 address.") from error
        if address.is_loopback or address.is_multicast or address.is_unspecified or int(address) >= int(ipaddress.IPv4Address("224.0.0.0")):
            raise FirewallError("Only a unicast IPv4 address can be blocked.")
        # SSH_CONNECTION is captured before privilege escalation by the playbook.
        if not args.ssh_client:
            raise FirewallError("The SSH management source could not be verified.")
        if str(address) == args.ssh_client or str(address) in args.protected_ip:
            raise FirewallError("The host or management address cannot be blocked.")
        ufw_rule = ["deny", "from", str(address)]
        rich_rules = ['rule family="ipv4" priority="-32768" source address="{}" drop'.format(address)]

    if selected == "ufw":
        status = run("ufw", "status", "numbered").stdout
        rows = ufw_numbered_rules(status)
        families = [4, 6] if args.operation == "closePort" and ufw_ipv6_enabled() else [4]
        # Bare DENY is the documented default incoming direction. OUT and FWD
        # must never satisfy this check. Require the exact global incoming rule.
        expected = ('^{}/{} DENY(?: IN)? Anywhere$'.format(args.port, args.protocol) if args.operation == "closePort" else '^Anywhere DENY(?: IN)? {}$'.format(re.escape(args.ip)))
        collision_pattern = expected.replace("DENY", "(?:ALLOW|DENY|LIMIT|REJECT)")
        def first_rules(rules):
            return {family: next((row["text"] for row in rules if row["version"] == family), "") for family in families}
        changed = any(not re.fullmatch(expected, first) for first in first_rules(rows).values())
        if changed and not args.check:
            # UFW set_rule treats the same tuple with a different action as an
            # existing rule and "insert"/"prepend" silently skips it (rc=0).
            # Delete only exact incoming collisions, preserving wider rules,
            # unrelated ports and OUT/FWD rules. Descending numbers stay valid
            # while deleting both IPv4 and IPv6 entries.
            collisions = [row["number"] for row in rows if row["version"] in families and re.fullmatch(collision_pattern, row["text"])]
            commands = [["ufw", "--force", "delete", str(number)] for number in sorted(collisions, reverse=True)]
            # prepend explicitly handles the start of each IP family, including
            # an empty ruleset; insert 1 calculates an IPv6 counterpart position.
            commands.append(["ufw", "prepend", *ufw_rule])
            for command in commands:
                mark_apply_intent(args, selected)
                completed = run(*command)
                mutation_outputs.append({"argv": command, "stdout": completed.stdout[-4000:], "stderr": completed.stderr[-4000:]})
        if not args.check:
            observed = ufw_numbered_rules(run("ufw", "status", "numbered").stdout)
            if any(not re.fullmatch(expected, first) for first in first_rules(observed).values()):
                raise FirewallError('UFW did not install the deny rule first in every required IP family. Observed rules: {!r}. Command output: {!r}'.format(observed, mutation_outputs))
    else:
        zones = {line.split()[0] for line in run("firewall-cmd", "--get-active-zones").stdout.splitlines() if line and not line[0].isspace()}
        zones.add(run("firewall-cmd", "--get-default-zone").stdout.strip())
        changed = False
        for zone in sorted(zones):
            if not re.fullmatch(r"[A-Za-z0-9_-]+", zone):
                raise FirewallError("Invalid firewalld zone.")
            for rule in rich_rules:
                for persistence in ([], ["--permanent"]):
                    command = ["firewall-cmd", *persistence, '--zone={}'.format(zone)]
                    if run(*command, '--query-rich-rule={}'.format(rule), acceptable=(0, 1)).returncode == 1:
                        changed = True
                        if not args.check:
                            mark_apply_intent(args, selected)
                            run(*command, '--add-rich-rule={}'.format(rule))
                            run(*command, '--query-rich-rule={}'.format(rule))
    return {"ok": True, "backend": selected, "changed": changed, "checkMode": args.check, "commands": mutation_outputs}


def transaction_dir(args):
    if not re.fullmatch(r"txn-[A-Za-z0-9-]{8,140}", args.transaction or ""):
        raise FirewallError("Invalid transaction identifier.")
    root = BACKUP_ROOT
    directory = root / args.transaction
    if root.is_symlink() or directory.is_symlink():
        raise FirewallError("Backup paths must not be symlinks.")
    return directory


def machine_id():
    return (CONFIG_ROOT / "machine-id").read_text().strip()


def ensure_private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    value = path.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) & 0o077:
        raise FirewallError("HCP state directory must be private and owned by the executing user: {}".format(path))


def sync_directory(path):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_control_json(path, value):
    """Durable replacement: neither a truncated journal nor an unsynced intent."""
    descriptor, temporary = tempfile.mkstemp(prefix=".hcp-state-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_control_json(path):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        value = os.fstat(stream.fileno())
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) & 0o077:
            raise FirewallError("Unsafe HCP state file: {}".format(path))
        raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise FirewallError("HCP state file exceeds the supported size.")
    result = json.loads(raw.decode("utf-8"))
    if not isinstance(result, dict):
        raise FirewallError("Invalid HCP state document.")
    return result


def optional_control_json(path):
    try:
        return read_control_json(path)
    except FileNotFoundError:
        return None


@contextlib.contextmanager
def target_lock():
    # A target-wide lock is shared by all aliases and controller processes.
    # Its persistent companion is retained when a process dies mid-operation.
    ensure_private_directory(BACKUP_ROOT)
    descriptor = os.open(str(BACKUP_ROOT / ".operation.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) & 0o077:
            raise FirewallError("Unsafe target operation lock.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EACCES):
                raise FirewallError("Another HCP firewall operation is still running on this target.") from error
            raise
        yield
    finally:
        os.close(descriptor)


def active_operation():
    value = optional_control_json(BACKUP_ROOT / STATE_NAME)
    if value is not None and (value.get("schemaVersion") != 1 or value.get("machineId") != machine_id()
                              or not isinstance(value.get("transactionId"), str)
                              or not re.fullmatch(r"txn-[A-Za-z0-9-]{8,140}", value.get("transactionId", ""))
                              or not isinstance(value.get("phase"), str)
                              or value.get("phase") not in {"backed_up", "apply_intent", "apply_failed", "apply_unknown", "rollback"}):
        raise FirewallError("Unrecognized target operation state; independent recovery is required.", outcome_unknown=True)
    return value


def record_active(args, phase, selected=None, archive_sha=None):
    ensure_private_directory(BACKUP_ROOT)
    write_control_json(BACKUP_ROOT / STATE_NAME, {"schemaVersion": 1, "machineId": machine_id(),
        "transactionId": args.transaction, "phase": phase, "backend": selected, "archiveSha256": archive_sha})


def release_active(args):
    value = active_operation()
    if value and value["transactionId"] == args.transaction:
        (BACKUP_ROOT / STATE_NAME).unlink()
        sync_directory(BACKUP_ROOT)


def mark_apply_intent(args, selected):
    # Public production entry points call execute_operation. Keeping the core
    # operation separately callable permits filesystem-free command unit tests.
    if not getattr(args, "_target_managed", False) or getattr(args, "_mutation_started", False):
        return
    directory, metadata, archive_path = verified_backup(args)
    if metadata["backend"] != selected:
        raise FirewallError("The active firewall changed after backup.")
    if not metadata.get("configurationSha256") or tree_digest(CONFIG_ROOT / selected, metadata_version=manifest_version(metadata)) != metadata["configurationSha256"]:
        raise FirewallError("Firewall configuration no longer matches the prepared backup; create a new transaction.")
    record_active(args, "apply_intent", selected, metadata["sha256"])
    args._mutation_started = True


def check_supported_attributes(path):
    try:
        attributes = os.listxattr(str(path), follow_symlinks=False)
    except OSError as error:
        if error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return
        raise
    unsupported = [name for name in attributes if name not in LABEL_HEADERS]
    if unsupported:
        raise FirewallError("Unsupported ACL or extended attribute on {}: {}. No firewall change was started.".format(path, ", ".join(sorted(unsupported))))


def manifest_digest(entries):
    return hashlib.sha256(json.dumps(sorted(entries, key=lambda item: item["path"]), sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def manifest_version(metadata):
    value = metadata.get("filesystemMetadata")
    return LEGACY_FILESYSTEM_METADATA if value is None else value


def tree_digest(root, sync=False, metadata_version=FILESYSTEM_METADATA):
    """Content, numeric ownership, mode and supported labels; no links/devices."""
    entries = []
    if metadata_version not in (LEGACY_FILESYSTEM_METADATA, FILESYSTEM_METADATA):
        raise FirewallError("Unsupported filesystem manifest version.")
    root_device = root.lstat().st_dev
    def visit(path):
        details = path.lstat()
        regular = stat.S_ISREG(details.st_mode)
        directory = stat.S_ISDIR(details.st_mode)
        if not (regular or directory) or (regular and details.st_nlink != 1) or details.st_dev != root_device:
            raise FirewallError("Unsupported link, mounted tree or special object in firewall configuration: {}".format(path))
        check_supported_attributes(path)
        label = security_label(path)
        selinux = security_label(path, SELINUX_LABEL)
        if metadata_version == LEGACY_FILESYSTEM_METADATA and selinux is not None:
            raise FirewallError("Legacy firewall backup has no SELinux label manifest; independent recovery is required.")
        entry = {"path": str(path.relative_to(root)) if path != root else ".", "type": "file" if regular else "directory",
                 "uid": details.st_uid, "gid": details.st_gid, "mode": stat.S_IMODE(details.st_mode),
                 "label": label.hex() if label is not None else None}
        if metadata_version == FILESYSTEM_METADATA:
            entry["selinux"] = selinux.hex() if selinux is not None else None
        if regular:
            descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(descriptor, "rb") as stream:
                initial = os.fstat(stream.fileno())
                if not stat.S_ISREG(initial.st_mode) or (initial.st_ino, initial.st_dev, initial.st_ctime_ns) != (details.st_ino, details.st_dev, details.st_ctime_ns):
                    raise FirewallError("Firewall file changed while checking its identity.")
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                final = os.fstat(stream.fileno())
                if (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns):
                    raise FirewallError("Firewall file changed while reading it.")
                entry["sha256"] = digest.hexdigest()
                if sync:
                    os.fsync(stream.fileno())
        else:
            for child in sorted(path.iterdir(), key=lambda item: item.name):
                visit(child)
            final = path.lstat()
            if (details.st_dev, details.st_ino, details.st_ctime_ns) != (final.st_dev, final.st_ino, final.st_ctime_ns):
                raise FirewallError("Firewall directory changed while reading it.")
            if sync:
                sync_directory(path)
        entries.append(entry)
    visit(root)
    return manifest_digest(entries)


def archive_digest(archive, selected, metadata_version=FILESYSTEM_METADATA):
    if metadata_version not in (LEGACY_FILESYSTEM_METADATA, FILESYSTEM_METADATA):
        raise FirewallError("Unsupported filesystem manifest version.")
    entries = []
    for member in archive.getmembers():
        label = archived_security_label(member, SECURITY_LABEL, required=True)
        parts = Path(member.name).parts[2:]
        entry = {"path": str(Path(*parts)) if parts else ".", "type": "file" if member.isfile() else "directory",
                 "uid": member.uid, "gid": member.gid, "mode": member.mode, "label": label.hex() if label is not None else None}
        if metadata_version == FILESYSTEM_METADATA:
            selinux = archived_security_label(member, SELINUX_LABEL, required=True)
            entry["selinux"] = selinux.hex() if selinux is not None else None
        if member.isfile():
            digest = hashlib.sha256()
            with archive.extractfile(member) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            entry["sha256"] = digest.hexdigest()
        entries.append(entry)
    return manifest_digest(entries)


def validate_members(archive, selected):
    names = set()
    root_directory = False
    for member in archive.getmembers():
        parts = Path(member.name).parts
        if member.name.startswith("/") or ".." in parts or parts[:2] != ("etc", selected) or not (member.isfile() or member.isdir()):
            raise FirewallError("Unsupported or unsafe member in firewall backup archive.")
        if parts in names or any(not isinstance(value, int) or value < 0 for value in (member.uid, member.gid, member.mode)) or member.mode > 0o7777:
            raise FirewallError("Invalid or duplicate filesystem metadata in firewall backup archive.")
        for key in member.pax_headers:
            if key.startswith(("HCP.security.", "SCHILY.xattr.", "LIBARCHIVE.xattr.", "SCHILY.acl.", "RHT.security.")) and key not in LABEL_HEADERS.values():
                raise FirewallError("Unsupported ACL or extended attribute in firewall backup: {}".format(key))
        names.add(parts)
        if parts == ("etc", selected) and member.isdir():
            root_directory = True
    if not root_directory:
        raise FirewallError("Firewall backup is missing its configuration directory.")


def restore_archive_metadata(archive, staging):
    # Python's data filter intentionally drops numeric owners and directory
    # modes and removes group/other write bits. Preserve its path/link safety,
    # then restore the validated local snapshot's POSIX metadata explicitly.
    # Apply directory modes after their children, and chmod after chown (which
    # can clear special permission bits). No live path has been replaced yet.
    for member in sorted(archive.getmembers(), key=lambda item: len(Path(item.name).parts), reverse=True):
        target = staging / member.name
        # Linux Python 3.5 may expose follow_symlinks but reject it for chmod.
        # Open without following the final component and operate on that same
        # verified object. NONBLOCK also prevents a substituted FIFO hanging us.
        descriptor = os.open(str(target), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            current = os.fstat(descriptor)
            if not (stat.S_ISREG(current.st_mode) if member.isfile() else stat.S_ISDIR(current.st_mode)):
                raise FirewallError("Unexpected filesystem object in restored firewall backup.")
            if (current.st_uid, current.st_gid) != (member.uid, member.gid):
                os.fchown(descriptor, member.uid, member.gid)
            os.fchmod(descriptor, member.mode)
            observed = os.fstat(descriptor)
            if (observed.st_uid, observed.st_gid, stat.S_IMODE(observed.st_mode)) != (member.uid, member.gid, member.mode):
                raise FirewallError("Filesystem ownership or permissions were not restored: {}".format(member.name))
        finally:
            os.close(descriptor)


def validate_security_label(value, name):
    if value is None:
        return
    maximum = 4096 if name == SELINUX_LABEL else 2048
    if not isinstance(value, bytes) or not 0 < len(value) <= maximum:
        raise FirewallError("Invalid or oversized {} security label.".format(name))
    if name == SELINUX_LABEL:
        # libselinux's setfilecon_raw passes strlen(context) + 1 to setxattr.
        # Preserve those raw bytes, including an optional terminal NUL, without
        # translation or restorecon (which would substitute policy defaults).
        context = value[:-1] if value.endswith(b"\x00") else value
        if not re.fullmatch(rb"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.,:-]+)?", context):
            raise FirewallError("Invalid raw SELinux context in firewall backup or configuration.")


def security_label(path, name=SECURITY_LABEL):
    try:
        value = os.getxattr(str(path), name, follow_symlinks=False)
    except OSError as error:
        if error.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
            return None
        raise
    validate_security_label(value, name)
    return value


def restore_security_label(path, value, name=SECURITY_LABEL):
    validate_security_label(value, name)
    current = security_label(path, name)
    if current == value:
        return
    if value is None:
        os.removexattr(str(path), name, follow_symlinks=False)
    else:
        os.setxattr(str(path), name, value, follow_symlinks=False)
    if security_label(path, name) != value:
        raise FirewallError("Mandatory security label {} was not restored: {}".format(name, path))


def archived_security_label(member, name, required=False):
    header = LABEL_HEADERS[name]
    if header not in member.pax_headers:
        if required:
            raise FirewallError("Mandatory label metadata {} is missing from firewall backup.".format(name))
        return None
    encoded = member.pax_headers[header]
    maximum = 8192 if name == SELINUX_LABEL else 4096
    if not isinstance(encoded, str) or len(encoded) > maximum or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", encoded):
        raise FirewallError("Invalid mandatory label {} in firewall backup.".format(name))
    value = bytes.fromhex(encoded) if encoded else None
    validate_security_label(value, name)
    return value


def validate_archive_labels(archive, metadata):
    version = metadata.get("securityLabels")
    for member in archive.getmembers():
        archived_security_label(member, SECURITY_LABEL, required=version in ("pax-v1", "pax-v2"))
        if version == "pax-v2":
            archived_security_label(member, SELINUX_LABEL, required=True)
        elif SELINUX_HEADER in member.pax_headers:
            raise FirewallError("Unexpected SELinux metadata in legacy firewall backup.")


def archive_security_label(member):
    source = CONFIG_ROOT.joinpath(*Path(member.name).parts[1:])
    for name, header in LABEL_HEADERS.items():
        value = security_label(source, name)
        member.pax_headers[header] = value.hex() if value is not None else ""
    return member


def restore_archive_labels(archive, staging, metadata):
    # Retain the historical PDPL-only fallback for archives that predate label
    # preservation. SELinux file types cannot be inferred from parent labels:
    # without recorded originals those archives must stop before replacement.
    for member in sorted(archive.getmembers(), key=lambda item: len(Path(item.name).parts)):
        if LABEL_HEADER in member.pax_headers:
            value = archived_security_label(member, SECURITY_LABEL)
        else:
            if metadata.get("securityLabels") in ("pax-v1", "pax-v2"):
                raise FirewallError("Mandatory label metadata is missing from firewall backup.")
            source = CONFIG_ROOT.joinpath(*Path(member.name).parts[1:])
            while not source.exists() and not source.is_symlink() and source != CONFIG_ROOT:
                source = source.parent
            if source.is_symlink():
                raise FirewallError("Firewall configuration must not contain symlinks.")
            value = security_label(source)
        restore_security_label(staging / member.name, value)
        if metadata.get("securityLabels") != "pax-v2" and security_label(staging / member.name, SELINUX_LABEL) is not None:
            raise FirewallError("Legacy firewall backup has no original SELinux labels; independent recovery is required.")
    if metadata.get("securityLabels") == "pax-v2":
        # Preserve the existing parent-first Astra integrity-label order above.
        # Apply SELinux labels only after all content/metadata work, children
        # first, so a restrictive directory type cannot hide unfinished files.
        for member in sorted(archive.getmembers(), key=lambda item: len(Path(item.name).parts), reverse=True):
            restore_security_label(staging / member.name, archived_security_label(member, SELINUX_LABEL, required=True), SELINUX_LABEL)


def backup(args):
    selected = backend()
    if selected == "firewalld":
        persistent_firewalld()
    if (CONFIG_ROOT / selected).lstat().st_dev != CONFIG_ROOT.lstat().st_dev:
        raise FirewallError("A mounted firewall configuration cannot be safely replaced for rollback.")
    original_digest = tree_digest(CONFIG_ROOT / selected)
    directory = transaction_dir(args)
    ensure_private_directory(directory.parent)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    archive_path = directory / "firewall-state.tar.gz"
    with tarfile.open(str(archive_path), "w:gz", format=tarfile.PAX_FORMAT) as archive:
        archive.add(str(CONFIG_ROOT / selected), arcname='etc/{}'.format(selected), filter=archive_security_label)
    os.chmod(str(archive_path), 0o600)
    with tarfile.open(str(archive_path)) as archive:
        validate_members(archive, selected)
        if archive_digest(archive, selected) != original_digest or tree_digest(CONFIG_ROOT / selected) != original_digest:
            raise FirewallError("Firewall configuration changed during backup; no mutation is allowed.")
    metadata = {"backend": selected, "machineId": machine_id(), "transactionId": args.transaction, "securityLabels": "pax-v2",
                "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(), "configurationSha256": original_digest,
                "filesystemMetadata": FILESYSTEM_METADATA}
    descriptor = os.open(str(archive_path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    write_control_json(directory / "metadata.json", metadata)
    sync_directory(directory.parent)
    return {"ok": True, "changed": True, "backupRef": str(archive_path)}


def verified_backup(args):
    directory = transaction_dir(args)
    details = directory.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise FirewallError("Unsafe backup directory.")
    metadata = read_control_json(directory / "metadata.json")
    selected = metadata["backend"]
    archive_path = directory / "firewall-state.tar.gz"
    if selected not in ("ufw", "firewalld") or metadata["machineId"] != machine_id() or metadata["transactionId"] != args.transaction:
        raise FirewallError("Backup identity does not match this host and transaction.")
    if metadata.get("securityLabels") not in (None, "pax-v1", "pax-v2") or manifest_version(metadata) not in (LEGACY_FILESYSTEM_METADATA, FILESYSTEM_METADATA):
        raise FirewallError("Unsupported backup metadata version.")
    if (metadata.get("securityLabels") == "pax-v2") != (manifest_version(metadata) == FILESYSTEM_METADATA):
        raise FirewallError("Inconsistent backup security metadata versions.")
    if metadata.get("filesystemMetadata") is not None and (not isinstance(metadata.get("configurationSha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", metadata["configurationSha256"])):
        raise FirewallError("Missing or invalid backup filesystem manifest.")
    descriptor = os.open(str(archive_path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_uid != os.geteuid():
            raise FirewallError("Unsafe firewall backup archive.")
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != metadata["sha256"]:
        raise FirewallError("Firewall backup checksum mismatch.")
    return directory, metadata, archive_path


def rollback_checkpoint(directory, state, phase):
    state["phase"] = phase
    state["generation"] += 1
    write_control_json(directory / "rollback-state.json", state)


def require_tree(path, expected, metadata_version=FILESYSTEM_METADATA):
    if not path.exists() or path.is_symlink() or tree_digest(path, metadata_version=metadata_version) != expected:
        raise FirewallError("Rollback tree does not match its saved manifest: {}. Independent recovery is required.".format(path))


def rollback_state(directory, metadata):
    state = optional_control_json(directory / "rollback-state.json")
    if state is None:
        return None
    required = {"schemaVersion": 1, "machineId": metadata["machineId"], "transactionId": metadata["transactionId"],
                "backend": metadata["backend"], "archiveSha256": metadata["sha256"]}
    if any(state.get(key) != value for key, value in required.items()) or not isinstance(state.get("phase"), str) or state.get("phase") not in ROLLBACK_PHASES:
        raise FirewallError("Rollback journal identity or phase mismatch.", outcome_unknown=True)
    if manifest_version(state) != manifest_version(metadata):
        raise FirewallError("Rollback journal filesystem manifest version mismatch.", outcome_unknown=True)
    if not isinstance(state.get("attemptId"), str) or not re.fullmatch(r"[a-f0-9]{32}", state.get("attemptId", "")) or state.get("stagingName") != ".hcp-rollback-" + state["attemptId"]:
        raise FirewallError("Unsafe staging identity in rollback journal.", outcome_unknown=True)
    if type(state.get("generation")) is not int or state["generation"] < 1 or not isinstance(state.get("previousSha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", state.get("previousSha256", "")):
        raise FirewallError("Invalid rollback journal manifest.", outcome_unknown=True)
    if state["phase"] != "preparing" and (not isinstance(state.get("preparedSha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", state.get("preparedSha256", ""))):
        raise FirewallError("Missing prepared rollback manifest.", outcome_unknown=True)
    if state["phase"] != "preparing" and any(not isinstance(state.get(key), int) or state[key] < 0 for key in ("stagingDevice", "stagingInode")):
        raise FirewallError("Missing rollback staging filesystem identity.", outcome_unknown=True)
    if "cleanupStarted" in state and type(state["cleanupStarted"]) is not bool:
        raise FirewallError("Invalid rollback cleanup checkpoint.", outcome_unknown=True)
    return state


def prepare_rollback_tree(directory, state, metadata, archive_path):
    staging = CONFIG_ROOT / state["stagingName"]
    destination = CONFIG_ROOT / metadata["backend"]
    version = manifest_version(state)
    require_tree(destination, state["previousSha256"], version)
    if staging.exists() or staging.is_symlink():
        details = staging.lstat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
            raise FirewallError("Unsafe rollback staging directory.")
        # No live rename is permitted before a durable prepared checkpoint.
        # Only the private, identity-bound unfinished extraction may be rebuilt.
        if (staging / "previous").exists() or (staging / "previous").is_symlink():
            raise FirewallError("Unexpected previous tree during rollback preparation.")
        owner = optional_control_json(staging / "owner.json")
        if owner != {"attemptId": state["attemptId"], "transactionId": state["transactionId"]}:
            if owner is not None or list(staging.iterdir()):
                raise FirewallError("Unrecognized rollback staging contents.")
        else:
            if any(item.name not in ("owner.json", "etc") for item in staging.iterdir()):
                raise FirewallError("Unexpected rollback staging contents.")
            candidate = staging / "etc"
            if candidate.is_symlink():
                raise FirewallError("Unsafe extraction directory.")
            if candidate.exists():
                shutil.rmtree(str(candidate))
    else:
        staging.mkdir(mode=0o700)
        sync_directory(CONFIG_ROOT)
    for name in LABEL_HEADERS:
        restore_security_label(staging, security_label(CONFIG_ROOT, name), name)
    write_control_json(staging / "owner.json", {"attemptId": state["attemptId"], "transactionId": state["transactionId"]})
    (staging / "etc").mkdir()
    for name in LABEL_HEADERS:
        restore_security_label(staging / "etc", security_label(CONFIG_ROOT, name), name)
    with tarfile.open(str(archive_path)) as archive:
        validate_members(archive, metadata["backend"])
        validate_archive_labels(archive, metadata)
        if metadata.get("configurationSha256") and archive_digest(archive, metadata["backend"], version) != metadata["configurationSha256"]:
            raise FirewallError("Firewall backup archive does not match its filesystem manifest.")
        archive.extractall(str(staging), **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
        restore_archive_metadata(archive, staging)
        restore_archive_labels(archive, staging, metadata)
    prepared = tree_digest(staging / "etc" / metadata["backend"], sync=True, metadata_version=version)
    if metadata.get("configurationSha256") and prepared != metadata["configurationSha256"]:
        raise FirewallError("Restored tree does not match the backup filesystem manifest.")
    require_tree(destination, state["previousSha256"], version)
    sync_directory(staging / "etc")
    sync_directory(staging)
    state["preparedSha256"] = prepared
    state["stagingDevice"], state["stagingInode"] = staging.stat().st_dev, staging.stat().st_ino
    rollback_checkpoint(directory, state, "prepared")


def rollback(args):
    directory, metadata, archive_path = verified_backup(args)
    selected = metadata["backend"]
    version = manifest_version(metadata)
    state = rollback_state(directory, metadata)
    replayed = state is not None and state["phase"] == "completed"
    pending = active_operation()
    if pending and pending["transactionId"] != args.transaction:
        raise FirewallError("A different transaction owns the target; finish its recovery first.", outcome_unknown=True)
    if pending and pending["phase"] in ("apply_intent", "apply_unknown") and not getattr(args, "recovery_verified", False):
        raise FirewallError("The earlier apply may still be running; independently verify its completion before rollback.", outcome_unknown=True)
    if state is None:
        if backend() != selected:
            raise FirewallError("The active firewall backend changed since backup.")
        previous_hash = tree_digest(CONFIG_ROOT / selected, metadata_version=version)
        attempt_id = uuid.uuid4().hex
        state = {"schemaVersion": 1, "machineId": metadata["machineId"], "transactionId": args.transaction,
                 "backend": selected, "archiveSha256": metadata["sha256"], "attemptId": attempt_id,
                 "stagingName": ".hcp-rollback-" + attempt_id, "previousSha256": previous_hash, "generation": 0,
                 "filesystemMetadata": version}
        rollback_checkpoint(directory, state, "preparing")
    record_active(args, "rollback", selected, metadata["sha256"])
    destination = CONFIG_ROOT / selected
    staging = CONFIG_ROOT / state["stagingName"]
    prepared = staging / "etc" / selected
    previous = staging / "previous"
    if state["phase"] == "preparing":
        prepare_rollback_tree(directory, state, metadata, archive_path)
    if state["phase"] not in ("completed",):
        details = staging.lstat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
            raise FirewallError("Unsafe rollback staging directory.", outcome_unknown=True)
        if (details.st_dev, details.st_ino) != (state["stagingDevice"], state["stagingInode"]):
            raise FirewallError("Rollback staging filesystem identity changed.", outcome_unknown=True)
        if read_control_json(staging / "owner.json") != {"attemptId": state["attemptId"], "transactionId": args.transaction}:
            raise FirewallError("Rollback staging owner does not match this attempt.", outcome_unknown=True)
    if state["phase"] == "prepared":
        require_tree(destination, state["previousSha256"], version)
        require_tree(prepared, state["preparedSha256"], version)
        if previous.exists() or previous.is_symlink():
            raise FirewallError("Unexpected previous tree before replacement.")
        rollback_checkpoint(directory, state, "move_old_intent")
    if state["phase"] == "move_old_intent":
        require_tree(prepared, state["preparedSha256"], version)
        if destination.exists() or destination.is_symlink():
            require_tree(destination, state["previousSha256"], version)
            if previous.exists() or previous.is_symlink():
                raise FirewallError("Ambiguous old and current rollback trees.")
            destination.rename(str(previous))
            sync_directory(CONFIG_ROOT)
            sync_directory(staging)
        require_tree(previous, state["previousSha256"], version)
        rollback_checkpoint(directory, state, "old_saved")
    if state["phase"] == "old_saved":
        require_tree(previous, state["previousSha256"], version)
        require_tree(prepared, state["preparedSha256"], version)
        if destination.exists() or destination.is_symlink():
            raise FirewallError("Unexpected live tree before installation.")
        rollback_checkpoint(directory, state, "install_intent")
    if state["phase"] == "install_intent":
        require_tree(previous, state["previousSha256"], version)
        if prepared.exists() or prepared.is_symlink():
            require_tree(prepared, state["preparedSha256"], version)
            if destination.exists() or destination.is_symlink():
                raise FirewallError("Ambiguous prepared and live rollback trees.")
            try:
                prepared.rename(str(destination))
            except OSError as error:
                raise FirewallError("Configuration installation failed; previous configuration retained at {}: {}".format(previous, error)) from error
            sync_directory(staging / "etc")
            sync_directory(CONFIG_ROOT)
        require_tree(destination, state["preparedSha256"], version)
        rollback_checkpoint(directory, state, "installed")
    if state["phase"] in ("reload_intent", "reload_unknown"):
        if not getattr(args, "recovery_verified", False):
            raise FirewallError("Previous reload outcome is unknown; independent process and firewall verification is required.", outcome_unknown=True)
        # The explicit recovery attestation belongs to this invocation. Every
        # later interrupted attempt requires a new controller attestation.
        rollback_checkpoint(directory, state, "installed")
    if state["phase"] in ("installed", "reload_failed"):
        require_tree(destination, state["preparedSha256"], version)
        require_tree(previous, state["previousSha256"], version)
        if backend() != selected:
            raise FirewallError("The active firewall backend changed before reload.")
        rollback_checkpoint(directory, state, "reload_intent")
        try:
            run("ufw", "reload") if selected == "ufw" else run("firewall-cmd", "--reload")
            if backend() != selected:
                raise FirewallError("Firewall is not active after rollback.")
            require_tree(destination, state["preparedSha256"], version)
        except FirewallError as error:
            rollback_checkpoint(directory, state, "reload_unknown" if error.outcome_unknown else "reload_failed")
            raise
        rollback_checkpoint(directory, state, "reload_completed")
    if state["phase"] == "reload_completed":
        require_tree(destination, state["preparedSha256"], version)
        state["result"] = {"ok": True, "changed": True, "backend": selected, "rollbackAttemptId": state["attemptId"]}
        rollback_checkpoint(directory, state, "completed")
    if state["phase"] != "completed" or state.get("result") != {"ok": True, "changed": True, "backend": selected, "rollbackAttemptId": state["attemptId"]}:
        raise FirewallError("Rollback has no verified completion record.", outcome_unknown=True)
    require_tree(destination, state["preparedSha256"], version)
    if backend() != selected:
        raise FirewallError("Firewall state changed after completed rollback.")
    # Cleanup follows durable completion. A lost response is replayed without
    # another reload, and a cleanup interruption cannot erase previous first.
    if staging.exists() or staging.is_symlink():
        details = staging.lstat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700 or (details.st_dev, details.st_ino) != (state["stagingDevice"], state["stagingInode"]):
            raise FirewallError("Unsafe completed rollback staging.")
        if not state.get("cleanupStarted"):
            if read_control_json(staging / "owner.json") != {"attemptId": state["attemptId"], "transactionId": args.transaction}:
                raise FirewallError("Unsafe completed rollback staging owner.")
            state["cleanupStarted"] = True
            rollback_checkpoint(directory, state, "completed")
        shutil.rmtree(str(staging))
        sync_directory(CONFIG_ROOT)
    release_active(args)
    result = dict(state["result"])
    result.update({"changed": not replayed, "replayed": replayed})
    return result


def outcome_is_unknown(args, error):
    if getattr(error, "outcome_unknown", False):
        return True
    # A journal/fsync error after submitting reload is not a known command
    # failure. Preserve uncertainty even when the local exception is OSError.
    try:
        active = active_operation()
        if not active or active.get("transactionId") != getattr(args, "transaction", None):
            return False
        if active["phase"] == "backed_up" and getattr(args, "operation", None) == "backup":
            # The durable marker can already exist when its directory fsync or
            # the final response fails. The controller has no backupRef yet;
            # do not let it cancel this as a known not-started operation and
            # orphan the target lease. Reconciliation can verify that backup.
            return True
        if active["phase"] in ("apply_intent", "apply_unknown"):
            return True
        if active["phase"] == "rollback":
            state = optional_control_json(transaction_dir(args) / "rollback-state.json")
            return state is None or state.get("phase") in ("reload_intent", "reload_unknown")
    except (FirewallError, OSError, ValueError, KeyError):
        return True
    return False


def execute_operation(args):
    with target_lock():
        if getattr(args, "check", False):
            if args.operation not in ("closePort", "blockIp"):
                raise FirewallError("Only firewall previews support check mode.")
            return close_or_block(args)
        transaction_dir(args)
        pending = active_operation()
        if pending and pending["transactionId"] != args.transaction:
            raise FirewallError("A different HCP transaction owns this target; finish its rollback or recovery first.")
        if args.operation == "rollback":
            return rollback(args)
        if pending and pending["phase"] != "backed_up":
            raise FirewallError("An earlier target operation requires rollback or independent recovery.", outcome_unknown=pending["phase"] in ("apply_intent", "apply_unknown", "rollback"))
        if args.operation == "backup":
            if pending:
                directory, metadata, archive_path = verified_backup(args)
                require_tree(CONFIG_ROOT / metadata["backend"], metadata.get("configurationSha256"), manifest_version(metadata))
                return {"ok": True, "changed": False, "backupRef": str(archive_path)}
            result = backup(args)
            directory, metadata, archive_path = verified_backup(args)
            record_active(args, "backed_up", metadata["backend"], metadata["sha256"])
            return result
        # A real mutation must be associated with its verified backup; previews
        # remain usable before the controller creates a transaction.
        verified_backup(args)
        args._target_managed = True
        args._mutation_started = False
        try:
            result = close_or_block(args)
        except (FirewallError, OSError, KeyError, ValueError) as error:
            if args._mutation_started:
                record_active(args, "apply_unknown" if getattr(error, "outcome_unknown", False) else "apply_failed")
            raise
        release_active(args)
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("closePort", "blockIp", "backup", "rollback"))
    parser.add_argument("--transaction")
    parser.add_argument("--port", type=int)
    parser.add_argument("--protocol", default="tcp")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ip")
    parser.add_argument("--ssh-client")
    parser.add_argument("--protected-ip", action="append", default=[])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--recovery-verified", action="store_true",
                        help="Independent operator verification that earlier remote processes stopped; permits retry of an unknown reload")
    args = parser.parse_args()
    try:
        result = execute_operation(args)
        print(json.dumps(result))
    except (FirewallError, OSError, KeyError, ValueError, tarfile.TarError) as error:
        print(json.dumps({"ok": False, "error": str(error), "outcomeUnknown": outcome_is_unknown(args, error)}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
