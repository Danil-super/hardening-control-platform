#!/usr/bin/env python3
"""Real UFW acceptance on a disposable GitHub-hosted Ubuntu VM only.

Runs the repository's actual Ansible playbooks. A separate Docker network
namespace probes an HTTP server bound to the VM bridge gateway, so loopback's
UFW exemption cannot make the deny test pass incorrectly. No external targets.
"""
import argparse
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
import urllib.request
import uuid

REPO = Path(__file__).resolve().parents[2]
PORT = 8088


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o644)


def snapshot(directory):
    return {str(path.relative_to(directory)): {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "mode": oct(path.stat().st_mode & 0o7777),
    } for path in sorted(directory.rglob("*")) if path.is_file()}


def assert_disposable_runner(args):
    if not args.execute_on_disposable_runner or os.geteuid() != 0:
        raise RuntimeError("Requires root and --execute-on-disposable-runner on a disposable GitHub-hosted VM.")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Refusing firewall changes outside a GitHub-hosted runner.")
    release = Path("/etc/os-release").read_text()
    if not re.search(r'^ID=ubuntu$', release, re.M) or not re.search(r'^VERSION_ID="24\.04"$', release, re.M):
        raise RuntimeError("This acceptance procedure requires Ubuntu 24.04.")


def cleanup(work):
    recovery = work / "recovery.json"
    if not recovery.exists():
        return
    state = json.loads(recovery.read_text())
    if state.get("cleaned"):
        return
    errors = []
    def execute(argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=25,
                                env={**os.environ, "LC_ALL": "C.UTF-8"})
        if result.returncode:
            raise RuntimeError(f"Cleanup {' '.join(argv)}: {result.stderr or result.stdout}")
        return result.stdout
    try:
        if state.get("firewallTouched"):
            execute(["ufw", "--force", "disable"])
            original = work / "original-ufw"
            if not original.is_dir() or not (work / "original-default-ufw").is_file():
                raise RuntimeError("Original UFW configuration is missing; cannot restore it.")
            replacement = Path("/etc") / f".hcp-ufw-restore-{uuid.uuid4().hex}"
            shutil.copytree(original, replacement, symlinks=True)
            previous = Path("/etc") / f".hcp-ufw-previous-{uuid.uuid4().hex}"
            Path("/etc/ufw").rename(previous)
            try:
                replacement.rename("/etc/ufw")
            except OSError:
                previous.rename("/etc/ufw")
                raise
            shutil.rmtree(previous)
            shutil.copy2(work / "original-default-ufw", "/etc/default/ufw")
            if snapshot(Path("/etc/ufw")) != state["originalSnapshot"]:
                raise RuntimeError("Original /etc/ufw files were not restored exactly.")
            if "Status: inactive" not in execute(["ufw", "status"]):
                raise RuntimeError("UFW did not return to its original inactive state.")
    except Exception as error:
        errors.append(str(error))
    for resource, operation in ((state.get("container"), ["docker", "rm", "--force"]),
                                (state.get("network"), ["docker", "network", "rm"])):
        if resource:
            if not re.fullmatch(r"hcp-firewall-[a-f0-9]+", resource):
                errors.append("Invalid disposable Docker resource name.")
                continue
            # An interrupted setup may not have created either resource yet.
            result = subprocess.run([*operation, resource], capture_output=True, text=True, timeout=20)
            if result.returncode and "No such" not in result.stderr and "not found" not in result.stderr:
                errors.append(result.stderr)
    transaction = state.get("transaction", "")
    if re.fullmatch(r"txn-ci-firewall-[a-f0-9]+", transaction):
        shutil.rmtree(Path("/var/lib/hcp-backups") / transaction, ignore_errors=True)
    if errors:
        write_json(work / "artifacts/cleanup.json", {"ok": False, "errors": errors})
        raise RuntimeError("; ".join(errors))
    state["cleaned"] = True
    write_json(recovery, state)
    write_json(work / "artifacts/cleanup.json", {"ok": True, "originalUfwState": "inactive", "originalConfigurationRestored": True})


def verify(work):
    work.mkdir(parents=True, exist_ok=False, mode=0o755)
    artifacts = work / "artifacts"
    artifacts.mkdir(mode=0o755)
    deadline = time.monotonic() + 270
    sequence = 0
    result = {"ok": False, "scope": "real UFW kernel and Ansible playbooks; isolated Docker-to-VM HTTP probe", "port": PORT, "checks": []}
    server = None

    def command(argv, label, timeout=60, allowed=(0,)):
        nonlocal sequence
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Firewall acceptance exceeded its 270-second execution budget.")
        sequence += 1
        process = subprocess.run(argv, cwd=REPO, capture_output=True, text=True,
                                 timeout=min(timeout, remaining), env={**os.environ, "LC_ALL": "C.UTF-8", "ANSIBLE_FORCE_COLOR": "false"})
        (artifacts / f"{sequence:02}-{label}.log").write_text(process.stdout + "\n" + process.stderr)
        if process.returncode not in allowed:
            raise RuntimeError(f"{label} exited with {process.returncode}: {process.stderr[-1500:]} {process.stdout[-1500:]}")
        return process

    try:
        status = command(["ufw", "status"], "initial-ufw-status").stdout
        if "Status: inactive" not in status:
            raise RuntimeError("UFW must initially be inactive; refusing to modify an existing active firewall.")
        if Path("/etc/ufw").is_symlink():
            raise RuntimeError("Refusing a symlinked /etc/ufw configuration.")
        shutil.copytree("/etc/ufw", work / "original-ufw", symlinks=True)
        (work / "original-ufw").chmod(0o700)
        shutil.copy2("/etc/default/ufw", work / "original-default-ufw")
        name = "hcp-firewall-" + uuid.uuid4().hex[:12]
        state = {"network": name, "container": name, "transaction": "txn-ci-firewall-" + uuid.uuid4().hex,
                 "originalSnapshot": snapshot(Path("/etc/ufw")), "firewallTouched": False, "cleaned": False}
        write_json(work / "recovery.json", state)
        command(["docker", "network", "create", "--driver", "bridge", name], "create-probe-network")
        network = json.loads(command(["docker", "network", "inspect", name], "inspect-probe-network").stdout)[0]
        gateway = network["IPAM"]["Config"][0]["Gateway"]
        if ipaddress.ip_address(gateway).is_loopback:
            raise RuntimeError("Probe gateway must not be a loopback address.")
        result["target"] = gateway
        command(["docker", "run", "--detach", "--name", name, "--network", name, "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges", "--read-only", "--pids-limit", "64", "python:3.12-alpine",
                 "python3", "-c", "import time; time.sleep(360)"], "start-probe-client")
        token = "hcp-firewall-acceptance-" + uuid.uuid4().hex

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                payload = token.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *arguments):
                pass

        server = http.server.ThreadingHTTPServer((gateway, PORT), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://{gateway}:{PORT}/health"
        probe_code = """import json,sys,urllib.request
client=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with client.open(sys.argv[1],timeout=3) as response:
        body=response.read(4096).decode()
        print(json.dumps({'reachable':True,'status':response.status,'body':body}))
except (OSError, urllib.error.URLError, TimeoutError) as error:
    print(json.dumps({'reachable':False,'error':str(error)}))
"""

        def probe(label, expected):
            observed = json.loads(command(["docker", "exec", name, "python3", "-c", probe_code, url], label, timeout=10).stdout)
            if observed["reachable"] != expected or (expected and (observed.get("status") != 200 or observed.get("body") != token)):
                raise RuntimeError(f"{label}: unexpected HTTP reachability: {observed}")
            result["checks"].append({"name": label, "ok": True, "reachable": expected})

        probe("initial-bridge-http", True)
        state["firewallTouched"] = True
        write_json(work / "recovery.json", state)
        # Keep CI management traffic available; only the explicit test port is denied later.
        for suffix, arguments in (("allow-input", ["default", "allow", "incoming"]),
                                  ("allow-output", ["default", "allow", "outgoing"]),
                                  ("allow-ssh", ["allow", "22/tcp"]),
                                  ("allow-test-port", ["allow", f"{PORT}/tcp"]),
                                  ("enable", ["--force", "enable"])):
            command(["ufw", *arguments], "baseline-" + suffix)
        probe("active-firewall-baseline-http", True)
        baseline = snapshot(Path("/etc/ufw"))
        write_json(artifacts / "baseline-config-digests.json", baseline)
        inventory = work / "inventory.ini"
        inventory.write_text("[linux_hosts]\nhcp-firewall-ci ansible_connection=local ansible_port=22 ansible_python_interpreter=/usr/bin/python3\n")
        variables = work / "vars.json"
        write_json(variables, {"transaction_id": state["transaction"], "remediation_action": "closePort", "target_port": PORT, "target_protocol": "tcp"})

        def playbook(name, label, check=False):
            arguments = ["ansible-playbook", "-i", str(inventory), str(REPO / "ansible/playbooks" / f"{name}.yml"),
                         "--limit", "hcp-firewall-ci", "-e", "@" + str(variables)]
            if check:
                arguments.append("--check")
            command(arguments, label, timeout=70)

        playbook("backup-remediation", "actual-backup-playbook")
        playbook("close-port", "actual-preview-playbook", check=True)
        if snapshot(Path("/etc/ufw")) != baseline:
            raise RuntimeError("Preview changed persistent UFW configuration.")
        probe("preview-leaves-http-open", True)
        result["checks"].append({"name": "preview-config-unchanged", "ok": True})
        playbook("close-port", "actual-apply-playbook")
        probe("deny-blocks-container-to-vm-http", False)
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=3) as response:
            if response.read().decode() != token:
                raise RuntimeError("The target HTTP service stopped; a deny cannot be inferred.")
        result["checks"].append({"name": "http-service-still-running-locally", "ok": True})
        command(["ufw", "status", "numbered"], "applied-ufw-rules")
        applied = snapshot(Path("/etc/ufw"))
        playbook("close-port", "actual-idempotent-apply-playbook")
        if snapshot(Path("/etc/ufw")) != applied:
            raise RuntimeError("A repeated apply changed the firewall configuration.")
        result["checks"].append({"name": "repeated-apply-idempotent", "ok": True})
        playbook("rollback-remediation", "actual-rollback-playbook")
        probe("rollback-restores-container-to-vm-http", True)
        if snapshot(Path("/etc/ufw")) != baseline:
            raise RuntimeError("Rollback did not restore the baseline UFW configuration exactly.")
        result["checks"].append({"name": "rollback-config-restored", "ok": True})
        command(["ufw", "status", "numbered"], "restored-ufw-rules")
        result["ok"] = True
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        if server:
            server.shutdown()
            server.server_close()
        try:
            cleanup(work)
        except Exception as error:
            result["ok"] = False
            result["cleanupError"] = str(error)
            raise
        finally:
            write_json(artifacts / "acceptance.json", result)
            print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-on-disposable-runner", action="store_true")
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    assert_disposable_runner(args)
    work = args.work_dir.resolve()
    if args.cleanup_only:
        cleanup(work)
    else:
        verify(work)


if __name__ == "__main__":
    main()
