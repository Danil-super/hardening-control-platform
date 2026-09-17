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

SUDO_READY_MARKER = "__HCP_SUDO_READY__"
SUDO_ELEVATED_MARKER = "__HCP_SUDO_ELEVATED__"

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
    # A hardened target may require a TTY for sudo.  HCP jobs are intentionally
    # non-interactive, so its narrowly named per-user rule also disables that
    # one constraint for this account.  The legacy one-line rule is accepted
    # only to upgrade an earlier HCP enrolment; no unrelated sudoers file is
    # overwritten.
    rule = shlex.quote("Defaults:" + user + " !requiretty\n" + user + " ALL=(root) NOPASSWD: ALL\n")
    legacy_rule = shlex.quote(user + " ALL=(root) NOPASSWD: ALL\n")
    destination = shlex.quote("/etc/sudoers.d/zz-hcp-" + credential_id)
    return """set -eu
[ "$(id -u)" = 0 ] || exit 73
printf '%%s\\n' %s
command -v visudo >/dev/null || exit 74
[ -d /etc/sudoers.d ] || exit 74
umask 077
hcp_rule_tmp=$(mktemp /etc/sudoers.d/.hcp-rule.XXXXXX)
hcp_legacy_tmp=''
trap 'rm -f "$hcp_rule_tmp" "$hcp_legacy_tmp"' EXIT HUP INT TERM
printf '%%s' %s > "$hcp_rule_tmp"
visudo -cf "$hcp_rule_tmp" >/dev/null 2>&1 || exit 75
hcp_rule_dest=%s
if [ -e "$hcp_rule_dest" ] || [ -L "$hcp_rule_dest" ]; then
  [ ! -L "$hcp_rule_dest" ] && [ -f "$hcp_rule_dest" ] || exit 76
  [ "$(stat -c '%%u:%%a' "$hcp_rule_dest")" = '0:440' ] || exit 76
  if cmp -s "$hcp_rule_tmp" "$hcp_rule_dest"; then
    :
  else
    hcp_legacy_tmp=$(mktemp /etc/sudoers.d/.hcp-legacy.XXXXXX)
    printf '%%s' %s > "$hcp_legacy_tmp"
    cmp -s "$hcp_legacy_tmp" "$hcp_rule_dest" || exit 76
    chown root:root "$hcp_rule_tmp"
    chmod 440 "$hcp_rule_tmp"
    mv "$hcp_rule_tmp" "$hcp_rule_dest"
    if ! visudo -c >/dev/null 2>&1; then
      chown root:root "$hcp_legacy_tmp"
      chmod 440 "$hcp_legacy_tmp"
      mv "$hcp_legacy_tmp" "$hcp_rule_dest"
      exit 75
    fi
  fi
else
  chown root:root "$hcp_rule_tmp"
  chmod 440 "$hcp_rule_tmp"
  mv "$hcp_rule_tmp" "$hcp_rule_dest"
  if ! visudo -c >/dev/null 2>&1; then rm -f "$hcp_rule_dest"; exit 75; fi
fi
visudo -c >/dev/null 2>&1 || exit 75
""" % (shlex.quote(SUDO_ELEVATED_MARKER), rule, destination, legacy_rule)


def sudo_attempt_script(root_script):
    """Run one password-fed sudo attempt without returning remote diagnostics.

    A pty is needed for Astra installations with ``requiretty``.  Its output
    must never be inspected by the controller because a misconfigured pty can
    echo the password.  This wrapper disables echo *before* the controller is
    told to send the password, captures all remote command output in mode-0600
    temporary files, maps known sudo failures to exit codes, then deletes the
    files.  The only output that crosses the SSH channel is a fixed marker.
    """
    return """set -u
umask 077
hcp_err=''
hcp_out=''
hcp_tty_state=''
cleanup() {
  if [ -n "$hcp_tty_state" ]; then stty "$hcp_tty_state" >/dev/null 2>&1 || :; fi
  if [ -n "$hcp_err" ]; then rm -f -- "$hcp_err" >/dev/null 2>&1 || :; fi
  if [ -n "$hcp_out" ]; then rm -f -- "$hcp_out" >/dev/null 2>&1 || :; fi
}
trap 'cleanup' EXIT
trap 'exit 82' HUP INT TERM
command -v sudo >/dev/null 2>&1 || exit 77
hcp_err=$(mktemp /tmp/.hcp-sudo-error.XXXXXX 2>/dev/null) || exit 82
hcp_out=$(mktemp /tmp/.hcp-sudo-output.XXXXXX 2>/dev/null) || exit 82
hcp_tty_state=$(stty -g 2>/dev/null) || exit 78
stty -echo 2>/dev/null || exit 78
printf '%%s\\n' %s
if command -v timeout >/dev/null 2>&1; then
  LC_ALL=C LANG=C timeout 12 sudo -S -k -p '' -- /bin/sh -c %s >"$hcp_out" 2>"$hcp_err"
else
  LC_ALL=C LANG=C sudo -S -k -p '' -- /bin/sh -c %s >"$hcp_out" 2>"$hcp_err"
fi
status=$?
case "$status" in
  0|74|75|76) exit "$status" ;;
esac
if [ "$status" -eq 124 ]; then exit 85; fi
if grep -qx %s "$hcp_out" >/dev/null 2>&1; then exit 83; fi
if grep -Eqi 'not in the sudoers|not allowed to (execute|run sudo)|may not run sudo|not permitted to run sudo' "$hcp_err" >/dev/null 2>&1; then exit 80; fi
if grep -Eqi 'must have a tty|no tty present|a terminal is required|no terminal is available' "$hcp_err" >/dev/null 2>&1; then exit 79; fi
if grep -Eqi 'sorry, try again|incorrect password|authentication failure|authentication failed|a password is required|no password was provided' "$hcp_err" >/dev/null 2>&1; then exit 81; fi
exit 82
""" % (shlex.quote(SUDO_READY_MARKER), shlex.quote(root_script), shlex.quote(root_script), shlex.quote(SUDO_ELEVATED_MARKER))


def sudo_setup_failure(status):
    """Return only stable local codes; never expose remote stderr or input."""
    return {
        74: "sudoers_unavailable",
        75: "sudoers_validation_failed",
        76: "sudoers_rule_conflict",
        77: "sudo_unavailable",
        78: "sudo_tty_unavailable",
        79: "sudo_tty_required",
        80: "sudo_not_permitted",
        81: "sudo_password_rejected",
        82: "sudo_pam_or_policy_rejected",
        83: "sudoers_write_rejected",
        84: "sudo_safe_channel_failed",
        85: "sudo_auth_timeout",
    }.get(status, "sudo_elevation_rejected_or_policy")


def sudo_readiness_script():
    """Match the non-interactive sudo shape used for Ansible modules.

    This receives neither a password nor a PTY.  A successful short `sudo id`
    is not enough on a policy that distinguishes the shell/Python wrapper used
    by Ansible from an individual command.
    """
    python_probe = "exec /usr/bin/python3 -c " + shlex.quote("import os; print(os.geteuid())")
    return "exec sudo -H -S -k -n -u root -- /bin/sh -c " + shlex.quote(python_probe)


def run_remote(client, script):
    command = "/bin/sh -c " + shlex.quote(script)
    stdin, stdout, stderr = client.exec_command(command, timeout=25, get_pty=False)
    stdin.channel.shutdown_write()
    # No remote output is returned to the API: even error strings may contain
    # secrets or attacker-controlled content. Small commands have bounded output.
    output = stdout.read(65536).decode("utf-8", "replace")
    stderr.read(65536)
    status = stdout.channel.recv_exit_status()
    return status, output


def run_password_sudo(client, root_script, password):
    """Run the wrapper above and send its password only after echo is off."""
    command = "/bin/sh -c " + shlex.quote(sudo_attempt_script(root_script))
    stdin, stdout, stderr = client.exec_command(command, timeout=25, get_pty=True)
    # Paramiko's ``read`` is bytes, while some supported releases return a
    # text string specifically from ``readline``.  Normalise both forms before
    # comparing the fixed marker; otherwise a valid sudo rejection is hidden
    # behind an AttributeError and appears as a generic setup failure.
    marker_line = stdout.readline(256)
    marker = marker_line.decode("utf-8", "replace").strip() if isinstance(marker_line, bytes) else str(marker_line).strip()
    if marker == SUDO_READY_MARKER:
        # Do not half-close a PTY immediately after writing.  On Paramiko/
        # OpenSSH combinations this can race sudo's first read and discard a
        # valid password.  The remote ``timeout`` bounds an invalid attempt.
        stdin.write(password + "\n")
        stdin.flush()
    else:
        stdin.channel.shutdown_write()
    # Deliberately discard all pty output.  The remote wrapper returns only a
    # status code; no password or remote diagnostic becomes API/log data.
    stdout.read(65536)
    stderr.read(65536)
    status = stdout.channel.recv_exit_status()
    if marker != SUDO_READY_MARKER:
        # These three codes can be emitted before the marker.  Anything else
        # means a broken or unexpected remote channel and must fail closed.
        return status if status in (77, 78, 82, 85) else 84
    return status


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
                if uid.strip() == "0":
                    status, _ = run_remote(key_client, sudo_setup_script(config["user"], config["credentialId"]))
                else:
                    status = run_password_sudo(key_client, sudo_setup_script(config["user"], config["credentialId"]),
                                               config.get("sudoPassword") or config.get("password") or "")
                sudo_result["configured"] = status == 0
                if status:
                    sudo_result["error"] = sudo_setup_failure(status)
            except (socket.timeout, TimeoutError):
                sudo_result["error"] = "sudo_auth_timeout"
            except Exception:
                sudo_result["error"] = "sudo_setup_failed"
        try:
            status, root_uid = run_remote(key_client, sudo_readiness_script() if uid.strip() != "0"
                                          else "/usr/bin/python3 -c " + shlex.quote("import os; print(os.geteuid())"))
            sudo_result["ready"] = status == 0 and root_uid.strip() == "0"
            if not sudo_result["ready"] and "error" not in sudo_result:
                sudo_result["error"] = "sudo_ansible_probe_failed"
        except Exception:
            sudo_result["error"] = "sudo_ansible_probe_failed"
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
