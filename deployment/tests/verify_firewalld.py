#!/usr/bin/env python3
"""Live firewalld acceptance; only a disposable GitHub-hosted Ubuntu 24.04 VM.

A network namespace connects to a dedicated HTTP and SSH listener on its veth
gateway. All Ansible playbooks travel over SSH, without a reused control socket.
No external target, user SSH key, system sshd configuration or Astra VM is used.
"""
import argparse
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.request
import uuid

from verify_firewall import assert_disposable_runner, snapshot, write_json

REPO = Path(__file__).resolve().parents[2]
PORT = 8088
SSH_PORT = 2228


def cleanup(work):
    recovery = work / "recovery.json"
    if not recovery.exists():
        return
    state = json.loads(recovery.read_text())
    if state.get("cleaned"):
        return
    errors = []

    def execute(argv, allowed=(0,)):
        process = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                                 env={**os.environ, "LC_ALL": "C.UTF-8"})
        if process.returncode not in allowed:
            raise RuntimeError(f"Cleanup {' '.join(argv)}: {process.stderr or process.stdout}")
        return process

    try:
        pid = state.get("sshdPid")
        if pid and Path(f"/proc/{pid}/cmdline").exists():
            # A stale PID must never terminate an unrelated process.
            arguments = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
            if str(work / "sshd_config") not in arguments or "sshd" not in arguments:
                raise RuntimeError("Disposable SSH listener PID no longer belongs to this test.")
            os.kill(pid, signal.SIGTERM)
        if state.get("firewallTouched"):
            execute(["systemctl", "stop", "firewalld.service"])
            original = work / "original-firewalld"
            if not original.is_dir():
                raise RuntimeError("Original firewalld configuration is unavailable.")
            previous = Path("/etc") / (".hcp-firewalld-previous-" + uuid.uuid4().hex)
            replacement = Path("/etc") / (".hcp-firewalld-restore-" + uuid.uuid4().hex)
            shutil.copytree(original, replacement, symlinks=True)
            Path("/etc/firewalld").rename(previous)
            try:
                replacement.rename("/etc/firewalld")
            except OSError:
                previous.rename("/etc/firewalld")
                raise
            shutil.rmtree(previous)
            if snapshot(Path("/etc/firewalld")) != state["originalSnapshot"]:
                raise RuntimeError("Original firewalld files were not restored exactly.")
            if execute(["systemctl", "is-active", "firewalld.service"], allowed=(0, 3, 4)).returncode == 0:
                raise RuntimeError("firewalld did not return to its original inactive state.")
    except Exception as error:
        errors.append(str(error))

    namespace = state.get("namespace", "")
    interface = state.get("interface", "")
    try:
        if re.fullmatch(r"hcp-firewalld-[a-f0-9]{12}", namespace):
            existing = execute(["ip", "netns", "list"]).stdout
            if namespace in {line.split()[0] for line in existing.splitlines() if line.strip()}:
                execute(["ip", "netns", "delete", namespace])
        if re.fullmatch(r"hfw[a-f0-9]{10}", interface):
            if execute(["ip", "link", "show", "dev", interface], allowed=(0, 1)).returncode == 0:
                execute(["ip", "link", "delete", interface])
    except Exception as error:
        errors.append(str(error))
    # Docker is stopped so it cannot add runtime-only zones during the test.
    # Return initially running services after the original firewall is restored.
    for service in ("docker.socket", "docker.service"):
        if service in state.get("stoppedServices", []):
            try:
                execute(["systemctl", "start", service])
            except Exception as error:
                errors.append(str(error))
    transaction = state.get("transaction", "")
    if re.fullmatch(r"txn-ci-firewalld-[a-f0-9]{32}", transaction):
        shutil.rmtree(Path("/var/lib/hcp-backups") / transaction, ignore_errors=True)
    for filename in ("client-key", "client-key.pub", "host-key", "host-key.pub"):
        (work / filename).unlink(missing_ok=True)
    ssh_runtime = state.get("sshRuntimeDirectory", "")
    if re.fullmatch(r"/run/hcp-firewalld-[a-f0-9]{12}", ssh_runtime):
        shutil.rmtree(ssh_runtime, ignore_errors=True)
    if errors:
        write_json(work / "artifacts/cleanup.json", {"ok": False, "errors": errors})
        raise RuntimeError("; ".join(errors))
    state["cleaned"] = True
    write_json(recovery, state)
    write_json(work / "artifacts/cleanup.json", {
        "ok": True, "originalFirewalldState": "inactive",
        "originalConfigurationRestored": True, "temporarySshKeysRemoved": True,
    })


def verify(work):
    work.mkdir(parents=True, exist_ok=False, mode=0o700)
    artifacts = work / "artifacts"
    artifacts.mkdir(mode=0o755)
    deadline = time.monotonic() + 540
    sequence = 0
    servers = []
    sshd = None
    sshd_log = None
    result = {
        "ok": False, "scope": "real firewalld kernel, fresh SSH connections and actual Ansible playbooks on Ubuntu 24.04",
        "port": PORT, "sshPort": SSH_PORT, "ipFamily": "IPv4", "checks": [],
    }

    def command(argv, label, timeout=45, allowed=(0,)):
        nonlocal sequence
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("firewalld acceptance exceeded its 540-second budget.")
        sequence += 1
        process = subprocess.run(argv, cwd=REPO, capture_output=True, text=True,
                                 timeout=min(timeout, remaining), env={
                                     **os.environ, "LC_ALL": "C.UTF-8", "ANSIBLE_FORCE_COLOR": "false",
                                     "ANSIBLE_SSH_ARGS": "-o ControlMaster=no -o ControlPath=none -o ControlPersist=no",
                                 })
        (artifacts / f"{sequence:02}-{label}.log").write_text(process.stdout + "\n" + process.stderr)
        if process.returncode not in allowed:
            raise RuntimeError(f"{label} exited with {process.returncode}: {process.stderr[-2000:]} {process.stdout[-3000:]}")
        return process

    def runtime_state(label):
        return {"zones": command(["firewall-cmd", "--list-all-zones"], label + "-zones").stdout,
                "policies": command(["firewall-cmd", "--list-all-policies"], label + "-policies").stdout,
                "direct": command(["firewall-cmd", "--direct", "--get-all-rules"], label + "-direct").stdout}

    def check(label, **details):
        result["checks"].append({"name": label, "ok": True, **details})

    try:
        if command(["systemctl", "is-active", "firewalld.service"], "initial-firewalld-state", allowed=(0, 3, 4)).returncode == 0:
            raise RuntimeError("Refusing to replace an already active firewalld configuration.")
        if shutil.which("ufw") and "Status: active" in command(["ufw", "status"], "initial-ufw-state").stdout:
            raise RuntimeError("UFW must be inactive for this firewalld test.")
        configuration = Path("/etc/firewalld")
        if not configuration.is_dir() or configuration.is_symlink():
            raise RuntimeError("Requires an ordinary /etc/firewalld directory.")
        shutil.copytree(configuration, work / "original-firewalld", symlinks=True)
        identifier = uuid.uuid4().hex[:12]
        state = {
            "namespace": "hcp-firewalld-" + identifier, "interface": "hfw" + identifier[:10],
            "sshRuntimeDirectory": "/run/hcp-firewalld-" + identifier,
            "transaction": "txn-ci-firewalld-" + uuid.uuid4().hex,
            "originalSnapshot": snapshot(configuration), "firewallTouched": False,
            "stoppedServices": [], "cleaned": False,
        }
        write_json(work / "recovery.json", state)
        for service in ("docker.service", "docker.socket"):
            if command(["systemctl", "is-active", service], "initial-" + service, allowed=(0, 3, 4)).returncode == 0:
                state["stoppedServices"].append(service)
        write_json(work / "recovery.json", state)
        if state["stoppedServices"]:
            command(["systemctl", "stop", "docker.socket", "docker.service"], "stop-docker-zone-writer")

        # Select an unused small benchmark subnet; there is no namespace default
        # route, so the client can reach only this disposable VM-side link.
        routes = json.loads(command(["ip", "-json", "route", "show", "table", "all"], "original-routes").stdout)
        occupied = [ipaddress.ip_network(route["dst"], strict=False) for route in routes
                    if route.get("dst") not in (None, "default") and ":" not in route["dst"]]
        subnet = next((network for network in ipaddress.ip_network("198.19.0.0/16").subnets(new_prefix=30)
                       if not any(network.overlaps(route) for route in occupied)), None)
        if subnet is None:
            raise RuntimeError("No isolated benchmark subnet is available.")
        target, client = map(str, subnet.hosts())
        namespace, interface = state["namespace"], state["interface"]
        peer = "hfp" + identifier[:10]
        command(["ip", "netns", "add", namespace], "create-network-namespace")
        command(["ip", "link", "add", interface, "type", "veth", "peer", "name", peer], "create-veth-pair")
        command(["ip", "link", "set", peer, "netns", namespace], "move-client-link")
        command(["ip", "addr", "add", target + "/30", "dev", interface], "target-address")
        command(["ip", "link", "set", interface, "up"], "target-link-up")
        command(["ip", "netns", "exec", namespace, "ip", "addr", "add", client + "/30", "dev", peer], "client-address")
        command(["ip", "netns", "exec", namespace, "ip", "link", "set", peer, "up"], "client-link-up")
        command(["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"], "client-loopback-up")
        result.update({"target": target, "controller": client})

        token = "hcp-firewalld-acceptance-" + uuid.uuid4().hex

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                payload = token.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *arguments):
                pass

        server = http.server.ThreadingHTTPServer((target, PORT), Handler)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://{target}:{PORT}/health"
        probe_code = """import json,sys,urllib.request
client=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with client.open(sys.argv[1],timeout=3) as response:
        print(json.dumps({'reachable':True,'status':response.status,'body':response.read(4096).decode()}))
except (OSError, urllib.error.URLError, TimeoutError) as error:
    print(json.dumps({'reachable':False,'error':str(error)}))
"""

        def probe(label, expected):
            observed = json.loads(command(["ip", "netns", "exec", namespace, "python3", "-c", probe_code, url], label, timeout=10).stdout)
            if observed["reachable"] != expected or (expected and (observed.get("status") != 200 or observed.get("body") != token)):
                raise RuntimeError(f"{label}: unexpected HTTP response: {observed}")
            check(label, reachable=expected)

        for filename in ("client-key", "host-key"):
            command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / filename)], "generate-" + filename)
        # GitHub RUNNER_TEMP has runner-owned ancestors. OpenSSH StrictModes
        # correctly refuses a root AuthorizedKeysFile under that path. Keep
        # authentication material in a separate root-owned /run directory;
        # never weaken StrictModes or alter permissions of the runner's files.
        ssh_runtime = Path(state["sshRuntimeDirectory"])
        ssh_runtime.mkdir(mode=0o700)
        authorized_keys = ssh_runtime / "authorized_keys"
        shutil.copyfile(work / "client-key.pub", authorized_keys)
        authorized_keys.chmod(0o600)
        host_public = (work / "host-key.pub").read_text().split()
        known_hosts = work / "known_hosts"
        known_hosts.write_text(f"[{target}]:{SSH_PORT} {host_public[0]} {host_public[1]}\n")
        sshd_config = work / "sshd_config"
        sshd_config.write_text("\n".join([
            f"Port {SSH_PORT}", f"ListenAddress {target}", f"HostKey {work / 'host-key'}",
            f"AuthorizedKeysFile {authorized_keys}", f"PidFile {work / 'sshd.pid'}", "StrictModes yes",
            "PermitRootLogin prohibit-password", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
            "PubkeyAuthentication yes", "UsePAM yes", "AllowUsers root", "PrintMotd no", "LogLevel VERBOSE",
            "Subsystem sftp internal-sftp", "",
        ]))
        Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
        command(["/usr/sbin/sshd", "-t", "-f", str(sshd_config)], "validate-isolated-sshd")
        sshd_log = (artifacts / "isolated-sshd.log").open("w")
        sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(sshd_config)], stdout=sshd_log, stderr=subprocess.STDOUT)
        state["sshdPid"] = sshd.pid
        write_json(work / "recovery.json", state)
        for attempt in range(30):
            if sshd.poll() is not None:
                raise RuntimeError("The dedicated SSH listener exited unexpectedly.")
            try:
                with socket.create_connection((target, SSH_PORT), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("The dedicated SSH listener did not become ready.")
        ssh_options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
                       "-o", "ConnectTimeout=5", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no"]

        def ssh_probe(label):
            observed = command(["ip", "netns", "exec", namespace, "ssh", *ssh_options, "-i", str(work / "client-key"),
                                "-p", str(SSH_PORT), "root@" + target, "printenv SSH_CONNECTION"], label, timeout=10).stdout.split()
            if len(observed) != 4 or observed[0] != client or observed[2:] != [target, str(SSH_PORT)]:
                raise RuntimeError(f"Unexpected SSH transport endpoints: {observed}")
            check(label, freshConnection=True)

        probe("initial-namespace-http", True)
        ssh_probe("initial-namespace-ssh")
        state["firewallTouched"] = True
        write_json(work / "recovery.json", state)
        # Default trusted preserves the runner's unrelated management traffic;
        # only the isolated veth enters the restrictive hcpci zone.
        for label, arguments in (
            ("default-zone", ["--set-default-zone=trusted"]),
            ("isolated-zone", ["--new-zone=hcpci"]),
            ("isolated-default-deny", ["--zone=hcpci", "--set-target=DROP"]),
            ("isolated-interface", ["--zone=hcpci", "--add-interface=" + interface]),
            ("allow-http", ["--zone=hcpci", f"--add-port={PORT}/tcp"]),
            ("allow-ssh", ["--zone=hcpci", f"--add-port={SSH_PORT}/tcp"]),
        ):
            command(["firewall-offline-cmd", *arguments], "baseline-" + label)
        command(["systemctl", "start", "firewalld.service"], "start-firewalld")
        command(["firewall-cmd", "--state"], "ready-firewalld")
        result["firewalldVersion"] = command(["firewall-cmd", "--version"], "firewalld-version").stdout.strip()
        if command(["firewall-cmd", "--get-zone-of-interface=" + interface], "check-probe-zone").stdout.strip() != "hcpci":
            raise RuntimeError("The probe interface did not enter the restrictive zone.")
        probe("active-firewall-baseline-http", True)
        ssh_probe("active-firewall-baseline-ssh")
        baseline = snapshot(configuration)
        baseline_runtime = runtime_state("baseline-runtime")
        write_json(artifacts / "baseline-config-digests.json", baseline)
        inventory = work / "inventory.ini"
        inventory.write_text("[linux_hosts]\n" + f"hcp-firewalld-ci ansible_host={target} ansible_port={SSH_PORT} ansible_user=root ansible_python_interpreter=/usr/bin/python3\n")
        variables = work / "vars.json"
        base_variables = {"transaction_id": state["transaction"], "remediation_action": "closePort", "target_port": PORT,
                          "target_protocol": "tcp", "ansible_ssh_private_key_file": str(work / "client-key"),
                          "ansible_ssh_common_args": f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts} -o ConnectTimeout=5"}

        def playbook(name, label, check_mode=False, overrides=None, expected_error=None):
            write_json(variables, {**base_variables, **(overrides or {})})
            argv = ["ip", "netns", "exec", namespace, "ansible-playbook", "-i", str(inventory),
                    str(REPO / "ansible/playbooks" / (name + ".yml")), "--limit", "hcp-firewalld-ci", "-e", "@" + str(variables)]
            if check_mode:
                argv.append("--check")
            observed = command(argv, label, timeout=75, allowed=(2,) if expected_error else (0,))
            if expected_error and expected_error not in observed.stdout + observed.stderr:
                raise RuntimeError(f"{label}: the request failed for a different reason than the management protection.")
            return observed.stdout

        playbook("backup-remediation", "actual-backup-over-ssh")
        playbook("close-port", "reject-actual-ssh-port", overrides={"target_port": SSH_PORT}, expected_error="management SSH port cannot be closed")
        playbook("close-port", "reject-standard-ssh-port", overrides={"target_port": 22}, expected_error="management SSH port cannot be closed")
        for label, address in (("controller", client), ("target", target)):
            playbook("block-ip", "reject-management-" + label, overrides={"block_ip": address, "remediation_action": "blockIp"},
                     expected_error="host or management address cannot be blocked")
        if snapshot(configuration) != baseline or runtime_state("after-rejected-management") != baseline_runtime:
            raise RuntimeError("A refused management request modified the firewall.")
        check("ssh-port-controller-and-target-protection", rejectedRequests=4)
        ssh_probe("management-still-reachable-after-rejected-requests")
        playbook("close-port", "actual-preview-over-ssh", check_mode=True)
        if snapshot(configuration) != baseline or runtime_state("preview-runtime") != baseline_runtime:
            raise RuntimeError("Preview modified runtime or permanent firewall configuration.")
        probe("preview-leaves-http-open", True)
        check("preview-config-and-runtime-unchanged")
        playbook("close-port", "actual-apply-over-ssh")
        probe("deny-blocks-namespace-to-vm-http", False)
        ssh_probe("fresh-ssh-survives-apply")
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=3) as response:
            if response.read().decode() != token:
                raise RuntimeError("The HTTP service stopped; firewall enforcement cannot be inferred.")
        check("http-service-still-running-locally")
        applied = snapshot(configuration)
        applied_runtime = runtime_state("applied-runtime")
        repeated = playbook("close-port", "actual-repeat-apply-over-ssh")
        if snapshot(configuration) != applied or runtime_state("repeated-runtime") != applied_runtime:
            raise RuntimeError("Repeated apply changed the firewall configuration or runtime.")
        if not re.search(r"hcp-firewalld-ci\s+:.*changed=0\b", repeated):
            raise RuntimeError("Repeated apply did not report an unchanged Ansible result.")
        check("repeated-apply-idempotent")
        command(["firewall-cmd", "--reload"], "verify-permanent-deny-reload")
        probe("deny-survives-firewalld-reload", False)
        ssh_probe("fresh-ssh-survives-firewalld-reload")
        playbook("rollback-remediation", "actual-rollback-over-ssh")
        probe("rollback-restores-namespace-http", True)
        ssh_probe("fresh-ssh-survives-rollback")
        if snapshot(configuration) != baseline or runtime_state("restored-runtime") != baseline_runtime:
            raise RuntimeError("Rollback did not restore the exact permanent and runtime baseline.")
        check("rollback-config-and-runtime-restored")
        result["ok"] = True
    except Exception as error:
        result["error"] = str(error)
        for label, argv in (("failure-firewalld-zones", ["firewall-cmd", "--list-all-zones"]),
                            ("failure-firewalld-permanent-zones", ["firewall-cmd", "--permanent", "--list-all-zones"]),
                            ("failure-kernel-nftables", ["nft", "list", "ruleset"]),
                            ("failure-firewalld-journal", ["journalctl", "-u", "firewalld", "--no-pager", "-n", "80"])):
            try:
                diagnostic = subprocess.run(argv, capture_output=True, text=True, timeout=10)
                (artifacts / (label + ".log")).write_text(diagnostic.stdout + "\n" + diagnostic.stderr)
                if "zones" in label or "journal" in label:
                    print(label + ":\n" + diagnostic.stdout[-9000:] + diagnostic.stderr[-2000:], flush=True)
            except Exception:
                pass
        if sshd_log:
            sshd_log.flush()
            print("Dedicated SSH listener diagnostics:\n" + (artifacts / "isolated-sshd.log").read_text()[-5000:], flush=True)
        raise
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        try:
            cleanup(work)
        except Exception as error:
            result["ok"] = False
            result["cleanupError"] = str(error)
            raise
        finally:
            if sshd:
                try:
                    sshd.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            if sshd_log:
                sshd_log.close()
            write_json(artifacts / "acceptance.json", result)
            # Artifacts contain only evidence, never the disposable SSH keys.
            work.chmod(0o755)
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
