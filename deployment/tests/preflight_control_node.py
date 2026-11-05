#!/usr/bin/env python3
"""One read-only HCP controller installation preflight.

No service starts, network scans, auth attempts, secret values, sudo, writes to
the controller, or production readiness claims. Operator may request a read-only
Docker Compose running-service check after deployment.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from validate_production_env import assess, read_env_file

MAX_RUNTIME_BYTES = 65536


def safe_entry(path, expected_type, max_bytes=None):
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if expected_type == "directory":
        return stat.S_ISDIR(info.st_mode) and info.st_mode & 0o077 == 0
    if expected_type == "file":
        return (stat.S_ISREG(info.st_mode) and info.st_mode & 0o077 == 0
                and (max_bytes is None or 0 <= info.st_size <= max_bytes))
    return False


def run_docker(root, args, runner):
    # All docker subcommands are read-only and statically selected. In
    # particular: no up/down/build/exec/login/secret dump.
    try:
        process = runner(
            ["docker", *args], cwd=str(root), capture_output=True,
            text=True, timeout=30, check=False)
        return process if type(process.returncode) is int else None
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None


def parse_hcp_runtime(stdout):
    if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > MAX_RUNTIME_BYTES:
        return "runtime_response_invalid"
    try:
        objects = json.loads(stdout)
        if isinstance(objects, dict):
            objects = [objects]
    except ValueError:
        try:
            objects = [json.loads(s) for s in stdout.splitlines() if s.strip()]
        except ValueError:
            return "runtime_response_invalid"
    if not isinstance(objects, list) or len(objects) > 64:
        return "runtime_response_invalid"
    found = []
    for item in objects:
        if not isinstance(item, dict):
            return "runtime_response_invalid"
        if item.get("Service") == "hcp":
            found.append((item.get("State"), item.get("Health")))
    if len(found) != 1:
        return "hcp_service_not_unique_or_missing"
    if found[0][0] != "running":
        return "hcp_not_running"
    if found[0][1] != "healthy":
        return "hcp_not_healthy"
    return "healthy"


def probe(project_root, env_path, *, with_docker=True, check_running=False,
          runner=subprocess.run):
    """Return only safe status codes and booleans, never command output."""
    root = Path(project_root)
    env = Path(env_path)
    if not env.is_absolute():
        env = root / env
    checks = {
        "projectFiles": False, "secretsDirectoryPrivate": False,
        "knownHostsPrivate": False, "inventoryPresent": False,
        "envStatic": "blocked", "dockerVersion": "not_checked",
        "composeConfig": "not_checked", "hcpRuntime": "not_checked",
    }
    blockers, warnings = [], []

    def block(area, code):
        blockers.append({"area": area, "code": code})

    def warn(area, code):
        warnings.append({"area": area, "code": code})

    if not safe_entry(root, "directory"):
        # Root checkout may be group-readable in typical Git checkouts.
        # Validate directory type separately; only secrets demand mode 0700.
        try:
            parent = os.lstat(root)
            valid_root = stat.S_ISDIR(parent.st_mode)
        except OSError:
            valid_root = False
        if not valid_root:
            block("checkout", "project_directory_missing_or_symlink")
    required = ("Dockerfile", "docker-compose.yml")
    checks["projectFiles"] = all(
        os.path.isfile(root / name) and not os.path.islink(root / name)
        for name in required)
    if not checks["projectFiles"]:
        block("checkout", "required_project_file_missing_or_symlink")

    secrets = root / "secrets"
    checks["secretsDirectoryPrivate"] = safe_entry(secrets, "directory")
    if not checks["secretsDirectoryPrivate"]:
        block("secrets", "private_directory_missing_or_unsafe")
    known = secrets / "known_hosts"
    checks["knownHostsPrivate"] = safe_entry(known, "file", 1024 * 1024)
    if not checks["knownHostsPrivate"]:
        block("ssh", "known_hosts_missing_or_unsafe")
    inventory = root / "ansible" / "inventory.ini"
    try:
        item = os.lstat(inventory)
        checks["inventoryPresent"] = stat.S_ISREG(item.st_mode)
    except OSError:
        pass
    if not checks["inventoryPresent"]:
        block("inventory", "inventory_missing_or_symlink")

    try:
        values = read_env_file(str(env))
        assessment = assess(values, with_dependency_track=False)
        checks["envStatic"] = assessment["status"]
        for entry in assessment["blockers"]:
            block("env:" + entry["field"], entry["code"])
        for entry in assessment["warnings"]:
            warn("env:" + entry["field"], entry["code"])
    except (ValueError, OSError, UnicodeError) as exc:
        err = str(exc)
        code = err if err.startswith("env_") and len(err) <= 80 else "env_unreadable"
        block("env", code)

    if check_running and not with_docker:
        block("docker", "runtime_requires_docker_checks")
    if with_docker:
        version = run_docker(root, ["compose", "version", "--short"], runner)
        checks["dockerVersion"] = (
            "present" if version is not None and version.returncode == 0
            else "unavailable")
        if checks["dockerVersion"] != "present":
            block("docker", "compose_cli_unavailable")
        config = run_docker(root, ["compose", "config", "--quiet"], runner)
        checks["composeConfig"] = (
            "valid" if config is not None and config.returncode == 0
            else "invalid_or_unavailable")
        if checks["composeConfig"] != "valid":
            block("docker", "compose_config_not_verified")
        if check_running:
            runtime = run_docker(root, ["compose", "ps", "--format", "json"], runner)
            actual = (parse_hcp_runtime(runtime.stdout)
                      if runtime is not None and runtime.returncode == 0
                      else "runtime_unavailable")
            checks["hcpRuntime"] = actual
            if actual != "healthy":
                block("runtime", actual)

    return {
        "schemaVersion": 1,
        "status": "blocked" if blockers else "static-preflight-passed-live-acceptance-not-proven",
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "checkRunningRequested": bool(check_running),
        "operatorAcceptanceCompleted": False,
        "nativeAstra17AcceptanceCompleted": False,
        "firewallRollbackAcceptanceCompleted": False,
        "backupRestoreAcceptanceCompleted": False,
        "limitations": [
            "No secrets, SSH keys or raw Docker command output are disclosed.",
            "Healthy is not proof of HTTP authorization, login or source coverage.",
            "No production actions were made; operator must independently test backup, SSH and rollback.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", default=".")
    parser.add_argument("--env", default=".env")
    parser.add_argument("--without-docker", action="store_true")
    parser.add_argument("--check-running", action="store_true")
    parser.add_argument("--output", help="New private JSON file; never overwritten")
    args = parser.parse_args(argv)
    result = probe(args.project_dir, args.env,
                   with_docker=not args.without_docker,
                   check_running=args.check_running)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        target = Path(args.output)
        # Never write inside the project checkout or to an existing file.
        root = Path(args.project_dir).resolve()
        parent = target.parent.resolve()
        if parent == root or root in parent.parents:
            print('{"status":"blocked","reason":"output_inside_project"}')
            return 1
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(rendered + "\n")
                output.flush()
                os.fsync(output.fileno())
        except OSError:
            print('{"status":"blocked","reason":"output_unavailable"}')
            return 1
    print(rendered)
    return 0 if not result["blockers"] else 1


if __name__ == "__main__":
    sys.exit(main())
