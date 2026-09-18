#!/usr/bin/env python3
"""CI-only acceptance against two disposable OpenSSH containers, never Astra.

The fixture passwords are intentionally public and only valid inside this lab.
They must never appear in HCP state, responses, process arguments or logs.
"""
import argparse
import http.cookiejar
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

COMPOSE = ["docker", "compose", "-f", "deployment/lab/docker-compose.yml"]
SECOND = "hcp-enrollment-target"
BASE = "http://127.0.0.1:3001"
PASSWORD = "hcp-enrollment-fixture-password"
WRONG_SUDO_PASSWORD = "wrong-sudo-fixture-password"
PROTOCOL = Path(".lab/ssh-enrollment.json")


def run(args, text=None, check=True):
    result = subprocess.run(args, input=text, text=True, capture_output=True, timeout=60)
    if check and result.returncode:
        # Never attach a command's stdin to its error.
        raise AssertionError("Lab command failed: " + " ".join(args[:5]) + ": " + result.stderr[:500])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-persistence", action="store_true")
    args = parser.parse_args()
    jar = http.cookiejar.CookieJar()
    api_client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def request(endpoint, body=None, method=None, status=200):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + endpoint, data=data, method=method or ("POST" if body is not None else "GET"),
                                     headers={"Origin": BASE, "Content-Type": "application/json"})
        try:
            response = api_client.open(req, timeout=220)
        except urllib.error.HTTPError as error:
            response = error
        payload = response.read().decode()
        if any(secret in payload for secret in (PASSWORD, WRONG_SUDO_PASSWORD)):
            raise AssertionError("SSH or sudo password leaked in API response")
        value = json.loads(payload)
        if response.status != status:
            raise AssertionError("Unexpected HTTP status for " + endpoint + ": " + str(response.status) + ": " + value.get("message", ""))
        return value
    request("/api/ansible/auth/login", {"password": "lab-only-password"})
    hcp = run(COMPOSE + ["ps", "-q", "hcp"]).stdout.strip()
    target = run(COMPOSE + ["ps", "-q", "lab-target"]).stdout.strip()
    if not hcp or not target:
        raise AssertionError("Start the isolated lab first")
    # ``False`` is Ansible's default, so config-dump may omit it or format its
    # source differently between supported Ansible releases.  Check the
    # immutable config copied into the image; the real requiretty enrollment
    # below then proves the option works for an actual Ansible become run.
    config_file = run(["docker", "exec", "--user", "node", hcp, "cat", "/app/ansible.cfg"]).stdout
    if not re.search(r"(?m)^pipelining\s*=\s*False\s*$", config_file):
        raise AssertionError("HCP must disable Ansible pipelining for non-interactive sudo")
    def check_connection(host):
        body = dict(host)
        if body.get("sudoMode") == "on_demand":
            body["sudoPassword"] = PASSWORD
        result = request("/api/ansible/hosts/preflight", body)
        if not result.get("ok") or result["checks"]["sudo"]["state"] != "passed":
            sudo = result.get("checks", {}).get("sudo", {})
            # Do not include request data: it can contain this fixture's
            # password.  The server already redacts the bounded diagnostic.
            details = str(sudo.get("details", ""))[-2000:]
            raise AssertionError("Per-host Ansible preflight failed: " + result.get("message", "") + "\n" + details)
    if args.check_persistence:
        protocol = json.loads(PROTOCOL.read_text())
        hosts = request("/api/ansible/hosts")["hosts"]
        for host in protocol["hosts"]:
            saved = next(item for item in hosts if item["alias"] == host["alias"])
            assert saved["credentialId"] == host["credentialId"]
            assert saved["credentialFingerprint"] == host["fingerprint"]
            assert saved["credentialReady"]
            check_connection({key: host[key] for key in ["alias", "address", "user", "port", "credentialId", "become", "sudoMode"]})
        closing = next(host for host in protocol["hosts"] if host["alias"] == "enrolled-second")
        closed = request("/api/ansible/hosts/decommission", {"alias": closing["alias"], "confirmation": closing["alias"]})
        assert closed["ok"], closed
        keys = run(["docker", "exec", SECOND, "cat", "/home/lab/.ssh/authorized_keys"]).stdout.splitlines()
        assert closing["publicKey"] not in keys, "Closeout left the individual HCP key on the target"
        rule_path = "/etc/sudoers.d/zz-hcp-" + closing["credentialId"]
        assert run(["docker", "exec", SECOND, "/bin/sh", "-c", "test ! -e " + rule_path], check=False).returncode == 0, "On-demand enrollment unexpectedly created an HCP sudoers rule"
        assert all(host["alias"] != closing["alias"] for host in request("/api/ansible/hosts")["hosts"]), "Closeout left the host in inventory"
        print("PASS Individual keys survive restart and closeout removes the HCP key without changing sudoers")
        return

    networks = json.loads(run(["docker", "inspect", target, "--format", "{{json .NetworkSettings.Networks}}"]).stdout)
    network = next(iter(networks))
    image = run(["docker", "inspect", target, "--format", "{{.Image}}"]).stdout.strip()
    run(["docker", "rm", "-f", SECOND], check=False)
    run(["docker", "run", "-d", "--network", network, "--name", SECOND, "--entrypoint", "/bin/sh", image, "-c",
         "mkdir -p /run/sshd /etc/ssh/host_keys; ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/host_keys/ssh_host_ed25519_key; chown -R lab:lab /home/lab/.ssh; chmod 700 /home/lab/.ssh; exec /usr/sbin/sshd -D -e"])
    for attempt in range(50):
        ready = run(["docker", "exec", SECOND, "cat", "/proc/1/comm"], check=False)
        if ready.returncode == 0 and ready.stdout.strip() == "sshd":
            break
        time.sleep(0.2)
    else:
        raise AssertionError("Second disposable SSH server did not start")
    for container in [target, SECOND]:
        run(["docker", "exec", "-i", container, "chpasswd"], text="lab:" + PASSWORD + "\n")
        run(["docker", "exec", container, "/bin/sh", "-c", "printf '\nMatch User lab\n  PasswordAuthentication yes\n' >> /etc/ssh/sshd_config; /usr/sbin/sshd -t"])
        run(["docker", "kill", "--signal", "HUP", container])
    # Model a hardened target where sudo requires a terminal. HCP must use a
    # PTY for the password-bearing one-time operations without modifying the
    # target's sudoers policy.
    run(["docker", "exec", SECOND, "/bin/sh", "-c", "printf 'Defaults:lab requiretty\nlab ALL=(root) ALL\n' > /etc/sudoers.d/lab; chmod 440 /etc/sudoers.d/lab; visudo -c"])
    a = {"alias": "lab-insecure", "address": "lab-target", "user": "lab", "port": 22, "become": True}
    b = {"alias": "enrolled-second", "address": SECOND, "user": "lab", "port": 22, "become": True}
    assert request("/api/ansible/access", {"operation": "status", "address": b["address"], "port": 22})["trusted"] is False
    unknown = request("/api/ansible/hosts/bootstrap", {**b, "password": PASSWORD}, status=400)
    assert unknown["error"] == "host_not_trusted", "Unexpected initial rejection: " + json.dumps(unknown)
    for host, container in [(a, target), (b, SECOND)]:
        public_key = run(["docker", "exec", container, "cat", "/etc/ssh/host_keys/ssh_host_ed25519_key.pub"]).stdout
        fingerprint = run(["ssh-keygen", "-lf", "-", "-E", "sha256"], text=public_key).stdout.split()[1]
        request("/api/ansible/access", {"operation": "trust", "address": host["address"], "port": 22, "expectedFingerprint": fingerprint})
        assert request("/api/ansible/access", {"operation": "status", "address": host["address"], "port": 22})["trusted"] is True
    wrong = request("/api/ansible/hosts/bootstrap", {**a, "password": "wrong-fixture-password"}, status=400)
    assert wrong["error"] == "password_rejected", "Unexpected password rejection: " + json.dumps(wrong)
    result_a = request("/api/ansible/hosts/bootstrap", {**a, "password": PASSWORD, "sudoPassword": PASSWORD,
                                                          "configureSudo": True, "confirmRootAccess": True})
    rejected_sudo = request("/api/ansible/hosts/bootstrap", {**b, "password": PASSWORD, "sudoPassword": WRONG_SUDO_PASSWORD,
                                                                "configureSudo": True, "confirmRootAccess": True}, status=400)
    assert rejected_sudo["error"] in {"sudo_password_rejected", "sudo_auth_timeout"}, "Unexpected sudo-password rejection: " + json.dumps(rejected_sudo)
    assert rejected_sudo.get("credentialId") and rejected_sudo.get("publicKey"), "Failed sudo setup must retain the individual SSH key"
    # The key is already proven at this point, so retry with only the separate
    # sudo password. This covers Astra-style rootpw policies without making the
    # operator re-send the SSH password.
    result_b = request("/api/ansible/hosts/bootstrap", {**b, "credentialId": rejected_sudo["credentialId"], "password": "", "sudoPassword": PASSWORD,
                                                          "configureSudo": True, "confirmRootAccess": True})
    assert result_a["ok"] and result_b["ok"]
    assert result_b["credentialId"] == rejected_sudo["credentialId"]
    assert result_b["publicKey"] == rejected_sudo["publicKey"]
    assert result_a["fingerprint"] != result_b["fingerprint"]
    assert result_a["publicKey"] != result_b["publicKey"]
    assert result_a["sudoMode"] == "on_demand" and result_a["sudo"]["ready"]
    assert result_b["sudoMode"] == "on_demand" and result_b["sudo"]["ready"]
    assert result_b["sudo"]["configured"] is False
    a["credentialId"] = result_a["credentialId"]
    b["credentialId"] = result_b["credentialId"]
    a["sudoMode"] = result_a["sudoMode"]
    b["sudoMode"] = result_b["sudoMode"]
    request("/api/ansible/hosts", {**a, "group": "linux_hosts"}, method="PUT")
    request("/api/ansible/hosts", {**b, "group": "linux_hosts"})
    # The saved identity and the supplied key conflict.  A 409 makes the
    # conflict explicit while still proving that a key from host A cannot be
    # used for host B.
    swapped = request("/api/ansible/hosts/preflight", {**b, "credentialId": a["credentialId"]}, status=409)
    assert not swapped["ok"]
    repeat = request("/api/ansible/hosts/bootstrap", {**a, "password": "", "sudoPassword": PASSWORD,
                                                        "configureSudo": True, "confirmRootAccess": True})
    assert repeat["credentialId"] == a["credentialId"] and repeat["fingerprint"] == result_a["fingerprint"]
    # The remote authorized_keys file contains only one copy of the managed key.
    keys = run(["docker", "exec", target, "cat", "/home/lab/.ssh/authorized_keys"]).stdout.splitlines()
    assert keys.count(result_a["publicKey"]) == 1
    # Disable the legacy key locally during real preflights. Both operations
    # must use their individual keys, irrespective of the fallback environment.
    run(["docker", "exec", hcp, "mv", "/home/node/.ssh/hcp-control", "/home/node/.ssh/hcp-control.test-saved"])
    try:
        check_connection(a)
        check_connection(b)
        # Also verify inventory lookup when API clients omit credentialId.
        check_connection({key: value for key, value in a.items() if key != "credentialId"})
        for source, destination in [(a, b), (b, a)]:
            path = "/var/lib/hcp/ssh-host-keys/" + source["credentialId"] + "/id_ed25519"
            crossed = run(["docker", "exec", "--user", "node", hcp, "ssh", "-i", path,
                           "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                           "-o", "UserKnownHostsFile=/var/lib/hcp/known_hosts", "lab@" + destination["address"], "true"], check=False)
            assert crossed.returncode != 0, "One host's key unexpectedly opened another host"
    finally:
        run(["docker", "exec", hcp, "mv", "/home/node/.ssh/hcp-control.test-saved", "/home/node/.ssh/hcp-control"])
    # Inspect only HCP persistent state, never print it.
    script = "from pathlib import Path; import sys; needle=sys.stdin.buffer.read(); assert not any(needle in p.read_bytes() for p in Path('/var/lib/hcp').rglob('*') if p.is_file()), 'password in persistent state'"
    for secret in (PASSWORD, WRONG_SUDO_PASSWORD):
        run(["docker", "exec", "-i", hcp, "python3", "-c", script], text=secret)
    logs = run(["docker", "logs", hcp])
    assert all(secret not in logs.stdout + logs.stderr for secret in (PASSWORD, WRONG_SUDO_PASSWORD))
    protocol = {"passed": True, "scope": "Two disposable Debian OpenSSH containers; not Astra",
                "checks": ["unknown server rejected before password authentication", "wrong SSH password rejected", "wrong sudo password returns a safe classified error", "retry reuses the pair with a separate sudo password", "unique per-host keys", "password-based sudo with requiretty without a sudoers change", "real Ansible without legacy key", "cross-host keys rejected", "no password in state or responses", "closeout removes the managed key without a sudoers rule"],
                "hosts": [{**a, "fingerprint": result_a["fingerprint"], "publicKey": result_a["publicKey"]}, {**b, "fingerprint": result_b["fingerprint"], "publicKey": result_b["publicKey"]}]}
    PROTOCOL.write_text(json.dumps(protocol, indent=2) + "\n")
    print("PASS Password enrollment, unique keys, sudo, cross-host isolation and secret handling on two real SSH servers")


if __name__ == "__main__":
    main()
