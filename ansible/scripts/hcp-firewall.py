#!/usr/bin/env python3
"""Validated firewall operations used by HCP. Never enables a firewall implicitly."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

CONFIG_ROOT = Path("/etc")
BACKUP_ROOT = Path("/var/lib/hcp-backups")

class FirewallError(RuntimeError):
    pass


def run(*args, acceptable=(0,)):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=45,
                                env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FirewallError(str(error)) from error
    if result.returncode not in acceptable:
        raise FirewallError(f"{' '.join(args)}: {result.stderr.strip() or result.stdout.strip()}")
    return result


def backend():
    ufw = shutil.which("ufw") is not None and "Status: active" in run("ufw", "status").stdout
    firewalld = shutil.which("firewall-cmd") is not None and run("firewall-cmd", "--state", acceptable=(0, 252)).stdout.strip() == "running"
    if ufw == firewalld:
        raise FirewallError("Exactly one supported firewall must be active: UFW or firewalld.")
    return "ufw" if ufw else "firewalld"


def persistent_firewalld():
    runtime = run("firewall-cmd", "--list-all-zones").stdout
    permanent = run("firewall-cmd", "--permanent", "--list-all-zones").stdout
    normalize = lambda value: re.sub(r"\s+\(active\)", "", value).strip()
    if normalize(runtime) != normalize(permanent):
        raise FirewallError("firewalld runtime and permanent configuration differ. Reconcile them before remediation to preserve rollback.")
    # Direct rules are a separate API and must also be preserved.
    for option in ("--get-all-rules", "--get-all-chains", "--get-all-passthroughs"):
        if run("firewall-cmd", "--direct", option).stdout != run("firewall-cmd", "--permanent", "--direct", option).stdout:
            raise FirewallError("firewalld runtime and permanent direct rules differ; rollback cannot be guaranteed.")


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
        rows.append({"number": int(number[1]), "version": version, "text": text})
    return rows


def ufw_ipv6_enabled():
    # UFW reads this setting even when its ruleset has no IPv6 rules yet.
    configuration = (CONFIG_ROOT / "default/ufw").read_text()
    value = re.search(r'^\s*IPV6\s*=\s*["\']?(yes|no)["\']?\s*(?:#.*)?$', configuration, re.M | re.I)
    if not value:
        raise FirewallError("Cannot determine UFW IPv6 policy from /etc/default/ufw.")
    return value[1].lower() == "yes"


def close_or_block(args):
    selected = backend()
    mutation_outputs = []
    if args.operation == "closePort":
        if not args.port or not 1 <= args.port <= 65535 or args.protocol not in ("tcp", "udp"):
            raise FirewallError("Invalid port or protocol.")
        if args.protocol == "tcp" and args.port in (22, args.ssh_port):
            raise FirewallError("The management SSH port cannot be closed automatically.")
        ufw_rule = ["deny", f"{args.port}/{args.protocol}"]
        rich_rules = [f'rule family="{family}" priority="-32768" port port="{args.port}" protocol="{args.protocol}" drop' for family in ("ipv4", "ipv6")]
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
        rich_rules = [f'rule family="ipv4" priority="-32768" source address="{address}" drop']

    if selected == "ufw":
        status = run("ufw", "status", "numbered").stdout
        rows = ufw_numbered_rules(status)
        families = [4, 6] if args.operation == "closePort" and ufw_ipv6_enabled() else [4]
        # Bare DENY is the documented default incoming direction. OUT and FWD
        # must never satisfy this check. Require the exact global incoming rule.
        expected = (rf"^{args.port}/{args.protocol} DENY(?: IN)? Anywhere$" if args.operation == "closePort" else rf"^Anywhere DENY(?: IN)? {re.escape(args.ip)}$")
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
                completed = run(*command)
                mutation_outputs.append({"argv": command, "stdout": completed.stdout[-4000:], "stderr": completed.stderr[-4000:]})
        if not args.check:
            observed = ufw_numbered_rules(run("ufw", "status", "numbered").stdout)
            if any(not re.fullmatch(expected, first) for first in first_rules(observed).values()):
                raise FirewallError(f"UFW did not install the deny rule first in every required IP family. Observed rules: {observed!r}. Command output: {mutation_outputs!r}")
    else:
        zones = {line.split()[0] for line in run("firewall-cmd", "--get-active-zones").stdout.splitlines() if line and not line[0].isspace()}
        zones.add(run("firewall-cmd", "--get-default-zone").stdout.strip())
        changed = False
        for zone in sorted(zones):
            if not re.fullmatch(r"[A-Za-z0-9_-]+", zone):
                raise FirewallError("Invalid firewalld zone.")
            for rule in rich_rules:
                for persistence in ([], ["--permanent"]):
                    command = ["firewall-cmd", *persistence, f"--zone={zone}"]
                    if run(*command, f"--query-rich-rule={rule}", acceptable=(0, 1)).returncode == 1:
                        changed = True
                        if not args.check:
                            run(*command, f"--add-rich-rule={rule}")
                            run(*command, f"--query-rich-rule={rule}")
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


def validate_members(archive, selected):
    for member in archive.getmembers():
        parts = Path(member.name).parts
        if member.name.startswith("/") or ".." in parts or parts[:2] != ("etc", selected) or not (member.isfile() or member.isdir()):
            raise FirewallError("Unsupported or unsafe member in firewall backup archive.")


def backup(args):
    selected = backend()
    if selected == "firewalld":
        persistent_firewalld()
    directory = transaction_dir(args)
    directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    archive_path = directory / "firewall-state.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(CONFIG_ROOT / selected, arcname=f"etc/{selected}")
    os.chmod(archive_path, 0o600)
    with tarfile.open(archive_path) as archive:
        validate_members(archive, selected)
    metadata = {"backend": selected, "machineId": machine_id(), "transactionId": args.transaction,
                "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()}
    (directory / "metadata.json").write_text(json.dumps(metadata))
    os.chmod(directory / "metadata.json", 0o600)
    return {"ok": True, "changed": True, "backupRef": str(archive_path)}


def rollback(args):
    directory = transaction_dir(args)
    metadata = json.loads((directory / "metadata.json").read_text())
    selected = metadata["backend"]
    archive_path = directory / "firewall-state.tar.gz"
    if selected not in ("ufw", "firewalld") or metadata["machineId"] != machine_id() or metadata["transactionId"] != args.transaction:
        raise FirewallError("Backup identity does not match this host and transaction.")
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != metadata["sha256"]:
        raise FirewallError("Firewall backup checksum mismatch.")
    if backend() != selected:
        raise FirewallError("The active firewall backend changed since backup.")
    # Extract into staging first. Replacement also removes files created since
    # backup (plain tar extraction over / would leave those new rules behind).
    with tempfile.TemporaryDirectory(prefix=".hcp-rollback-", dir=CONFIG_ROOT) as staging:
        with tarfile.open(archive_path) as archive:
            validate_members(archive, selected)
            archive.extractall(staging, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
        destination = CONFIG_ROOT / selected
        if destination.is_symlink():
            raise FirewallError("Firewall configuration must not be a symlink.")
        previous = Path(staging) / "previous"
        destination.rename(previous)
        try:
            (Path(staging) / "etc" / selected).rename(destination)
        except OSError:
            previous.rename(destination)
            raise
    run("ufw", "reload") if selected == "ufw" else run("firewall-cmd", "--reload")
    if backend() != selected:
        raise FirewallError("Firewall is not active after rollback.")
    return {"ok": True, "changed": True, "backend": selected}


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
    args = parser.parse_args()
    try:
        result = backup(args) if args.operation == "backup" else rollback(args) if args.operation == "rollback" else close_or_block(args)
        print(json.dumps(result))
    except (FirewallError, OSError, KeyError, ValueError, tarfile.TarError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
