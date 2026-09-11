#!/usr/bin/env python3
"""Controller-only SSH enrollment. Secrets arrive on stdin, never in argv/files.

Runs with controller Python/Paramiko; no Python is required on the target for
key installation. Server keys MUST already be in the platform's known_hosts.
"""
import base64
import hashlib
import json
import logging
import os
import re
import shlex
import socket
import subprocess
import sys
from pathlib import Path

logging.disable(logging.CRITICAL)

class EnrollmentError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def key_install_script(public_key):
    # Preserve existing entries and reject symlinks/nonstandard authorized_keys.
    return """set -eu
umask 077
[ ! -L "$HOME/.ssh" ] && [ ! -L "$HOME/.ssh/authorized_keys" ] || exit 71
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
mkdir "$HOME/.ssh/.hcp-key-lock" || exit 72
trap 'rmdir "$HOME/.ssh/.hcp-key-lock"' EXIT HUP INT TERM
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
grep -qxF -- %s "$HOME/.ssh/authorized_keys" || printf '\\n%%s\\n' %s >> "$HOME/.ssh/authorized_keys"
""" % (shlex.quote(public_key), shlex.quote(public_key))


def sudo_setup_script(user, credential_id):
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}", user) or not re.fullmatch(r"[a-f0-9]{64}", credential_id):
        raise EnrollmentError("bad_identity")
    # Refuse collisions; validate the entire sudoers configuration. An existing
    # matching rule is reused. No unrelated sudoers file is overwritten.
    rule = shlex.quote(user + " ALL=(root) NOPASSWD: ALL\n")
    destination = shlex.quote("/etc/sudoers.d/zz-hcp-" + credential_id)
    return """set -eu
[ "$(id -u)" = 0 ] || exit 73
command -v visudo >/dev/null || exit 74
[ -d /etc/sudoers.d ] || exit 74
umask 077
hcp_rule_tmp=$(mktemp /etc/sudoers.d/.hcp-rule.XXXXXX)
trap 'rm -f "$hcp_rule_tmp"' EXIT HUP INT TERM
printf '%%s' %s > "$hcp_rule_tmp"
visudo -cf "$hcp_rule_tmp" >/dev/null 2>&1 || exit 75
hcp_rule_dest=%s
if [ -e "$hcp_rule_dest" ] || [ -L "$hcp_rule_dest" ]; then
  [ ! -L "$hcp_rule_dest" ] && cmp -s "$hcp_rule_tmp" "$hcp_rule_dest" || exit 76
else
  chown root:root "$hcp_rule_tmp"
  chmod 440 "$hcp_rule_tmp"
  mv "$hcp_rule_tmp" "$hcp_rule_dest"
  if ! visudo -c >/dev/null 2>&1; then rm -f "$hcp_rule_dest"; exit 75; fi
fi
visudo -c >/dev/null 2>&1 || exit 75
""" % (rule, destination)


def run_remote(client, script, input_text=None, elevated=False):
    command = "/bin/sh -c " + shlex.quote(script)
    if elevated:
        command = "sudo -S -k -p '' -- " + command
    stdin, stdout, stderr = client.exec_command(command, timeout=25, get_pty=False)
    if input_text is not None:
        stdin.write(input_text + "\n")
        stdin.flush()
    stdin.channel.shutdown_write()
    # No remote output is returned to the API: even error strings may contain
    # secrets or attacker-controlled content. Small commands have bounded output.
    output = stdout.read(65536).decode("utf-8", "replace")
    stderr.read(65536)
    status = stdout.channel.recv_exit_status()
    return status, output


def connect(config, password=None, key_path=None):
    import paramiko
    client = paramiko.SSHClient()
    try:
        client.load_host_keys(config["knownHostsPath"])
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        pattern = config["address"] if config["port"] == 22 else "[%s]:%s" % (config["address"], config["port"])
        if not client.get_host_keys().lookup(pattern):
            raise EnrollmentError("host_not_trusted")
        client.connect(config["address"], port=config["port"], username=config["user"],
                       password=password, key_filename=key_path, allow_agent=False, look_for_keys=False,
                       timeout=10, banner_timeout=10, auth_timeout=15)
        return client
    except Exception:
        client.close()
        raise


def ensure_key(config):
    key = Path(config["keyPath"])
    if not key.exists():
        result = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "hcp:" + config["credentialId"], "-f", str(key)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if result.returncode:
            raise EnrollmentError("key_generation_failed")
    os.chmod(key, 0o600)
    result = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(key)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if result.returncode:
        raise EnrollmentError("key_invalid")
    public_key = result.stdout.decode().strip()
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?", public_key):
        raise EnrollmentError("key_invalid")
    Path(str(key) + ".pub").write_text(public_key + "\n")
    os.chmod(str(key) + ".pub", 0o600)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(public_key.split()[1])).digest()).decode().rstrip("=")
    return public_key, fingerprint


def enroll(config):
    import paramiko
    password_client = None
    key_client = None
    sudo_result = {"requested": bool(config.get("configureSudo")), "ready": False, "configured": False}
    try:
        # A retry can recover an installed key after a lost HTTP response.
        if Path(config["keyPath"]).exists():
            try:
                key_client = connect(config, key_path=config["keyPath"])
            except paramiko.AuthenticationException:
                pass
        if key_client is None:
            if not config.get("password"):
                raise EnrollmentError("password_required")
            password_client = connect(config, password=config["password"])
            public_key, fingerprint = ensure_key(config)
            status, _ = run_remote(password_client, key_install_script(public_key))
            if status:
                raise EnrollmentError("key_install_failed")
            # A fresh connection must succeed without a password or ssh-agent.
            try:
                key_client = connect(config, key_path=config["keyPath"])
            except paramiko.AuthenticationException:
                raise EnrollmentError("key_login_failed")
        else:
            public_key, fingerprint = ensure_key(config)
        status, uid = run_remote(key_client, "id -u")
        if status or not uid.strip().isdigit():
            raise EnrollmentError("key_login_failed")
        if config.get("configureSudo"):
            try:
                status, _ = run_remote(key_client, sudo_setup_script(config["user"], config["credentialId"]),
                                       input_text=(config.get("sudoPassword") or config.get("password") or "") if uid.strip() != "0" else None,
                                       elevated=uid.strip() != "0")
                sudo_result["configured"] = status == 0
                if status:
                    sudo_result["error"] = "sudo_setup_failed"
            except Exception:
                sudo_result["error"] = "sudo_setup_failed"
        try:
            status, root_uid = run_remote(key_client, "sudo -k -n id -u" if uid.strip() != "0" else "id -u")
            sudo_result["ready"] = status == 0 and root_uid.strip() == "0"
        except Exception:
            sudo_result["error"] = "sudo_check_failed"
        return {"ok": True, "publicKey": public_key, "fingerprint": fingerprint, "sudo": sudo_result}
    finally:
        if key_client:
            key_client.close()
        if password_client:
            password_client.close()
        config.pop("password", None)
        config.pop("sudoPassword", None)


def main():
    try:
        import paramiko
    except ImportError:
        print(json.dumps({"ok": False, "error": "ssh_dependency_missing"}))
        return 1
    try:
        config = json.loads(sys.stdin.buffer.read(16385))
        result = enroll(config)
    except EnrollmentError as error:
        result = {"ok": False, "error": error.code}
    except paramiko.BadHostKeyException:
        result = {"ok": False, "error": "host_key_changed"}
    except paramiko.AuthenticationException:
        result = {"ok": False, "error": "password_rejected"}
    except (socket.timeout, TimeoutError):
        result = {"ok": False, "error": "ssh_timeout"}
    except FileNotFoundError:
        result = {"ok": False, "error": "host_not_trusted"}
    except Exception:
        result = {"ok": False, "error": "ssh_setup_failed"}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
