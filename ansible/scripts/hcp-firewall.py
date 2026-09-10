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


def close_or_block(args):
    selected = backend()
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
        rows = [re.sub(r"^\[\s*\d+\]\s*", "", line.strip()) for line in status.splitlines() if re.match(r"^\[\s*\d+\]", line.strip()) and "(v6)" not in line]
        expected = (rf"^{args.port}/{args.protocol}\s+DENY IN\s+Anywhere\s*$" if args.operation == "closePort" else rf"^Anywhere\s+DENY IN\s+{re.escape(args.ip)}\s*$")
        matching = [index for index, row in enumerate(rows) if re.match(expected, row)]
        changed = not matching or matching[0] != 0
        if changed and not args.check:
            if matching:
                run("ufw", "--force", "delete", *ufw_rule)
            run("ufw", "insert", "1", *ufw_rule)
        if not args.check:
            first = next((re.sub(r"^\[\s*\d+\]\s*", "", line.strip()) for line in run("ufw", "status", "numbered").stdout.splitlines() if re.match(r"^\[\s*\d+\]", line.strip()) and "(v6)" not in line), "")
            if not re.match(expected, first):
                raise FirewallError("UFW did not install the deny rule before existing allow rules.")
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
    return {"ok": True, "backend": selected, "changed": changed, "checkMode": args.check}


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
