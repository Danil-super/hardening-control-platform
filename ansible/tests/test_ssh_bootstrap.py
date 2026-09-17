import importlib.util
from pathlib import Path
import unittest


HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "hcp-ssh-bootstrap.py"
SPEC = importlib.util.spec_from_file_location("hcp_ssh_bootstrap_test", HELPER_PATH)
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class _Channel:
    def __init__(self, status=0):
        self.closed_input = False
        self.status = status

    def shutdown_write(self):
        self.closed_input = True

    def recv_exit_status(self):
        return self.status


class _Input:
    def __init__(self, channel):
        self.channel = channel
        self.value = ""
        self.flushed = False

    def write(self, value):
        self.value += value

    def flush(self):
        self.flushed = True


class _Output:
    def __init__(self, channel, value=b""):
        self.channel = channel
        self.value = value

    def read(self, limit):
        value = self.value[:limit]
        self.value = self.value[limit:]
        return value

    def readline(self, limit):
        newline = b"\n" if isinstance(self.value, bytes) else "\n"
        index = self.value.find(newline)
        if index >= 0:
            size = min(index + 1, limit)
        else:
            size = min(len(self.value), limit)
        value = self.value[:size]
        self.value = self.value[size:]
        return value


class _Client:
    def __init__(self, stdout=b"0\n", stderr=b"", status=0):
        self.calls = []
        self.channel = _Channel(status)
        self.stdin = _Input(self.channel)
        self.stdout = stdout
        self.stderr = stderr

    def exec_command(self, command, timeout, get_pty):
        self.calls.append({"command": command, "timeout": timeout, "get_pty": get_pty})
        return self.stdin, _Output(self.channel, self.stdout), _Output(self.channel, self.stderr)


class SshBootstrapTests(unittest.TestCase):
    def test_regular_key_commands_do_not_request_a_tty(self):
        regular = _Client()
        status, output = BOOTSTRAP.run_remote(regular, "id -u")
        self.assertEqual((status, output), (0, "0\n"))
        self.assertFalse(regular.calls[0]["get_pty"])

    def test_password_sudo_disables_pty_echo_before_receiving_the_secret(self):
        client = _Client(stdout=(BOOTSTRAP.SUDO_READY_MARKER + "\n").encode())
        status = BOOTSTRAP.run_password_sudo(client, "id -u", "fixture-password")
        self.assertEqual(status, 0)
        self.assertTrue(client.calls[0]["get_pty"])
        wrapper = BOOTSTRAP.sudo_attempt_script("id -u")
        self.assertIn("stty -echo", wrapper)
        self.assertIn("IFS= read -r hcp_sudo_password", wrapper)
        self.assertIn('"$hcp_sudo_password" |', wrapper)
        self.assertIn("unset hcp_sudo_password", wrapper)
        self.assertIn("timeout 12 sudo", wrapper)
        self.assertIn("sudo -S -k -p ''", wrapper)
        self.assertIn('>"$hcp_out" 2>"$hcp_err"', wrapper)
        self.assertNotIn("fixture-password", client.calls[0]["command"])
        self.assertEqual(client.stdin.value, "fixture-password\n")
        self.assertTrue(client.stdin.flushed)
        self.assertFalse(client.channel.closed_input)

    def test_password_sudo_accepts_paramiko_text_readline(self):
        # Paramiko 2.x can return a text line from ChannelFile.readline even
        # though its bulk read remains bytes.
        client = _Client(stdout=BOOTSTRAP.SUDO_READY_MARKER + "\n", status=81)
        status = BOOTSTRAP.run_password_sudo(client, "id -u", "fixture-password")
        self.assertEqual(status, 81)
        self.assertEqual(client.stdin.value, "fixture-password\n")
        self.assertTrue(client.stdin.flushed)

    def test_password_sudo_never_writes_the_secret_without_the_safe_marker(self):
        unavailable = _Client(stdout=b"", status=77)
        self.assertEqual(BOOTSTRAP.run_password_sudo(unavailable, "id -u", "fixture-password"), 77)
        self.assertEqual(unavailable.stdin.value, "")
        self.assertFalse(unavailable.stdin.flushed)
        self.assertTrue(unavailable.channel.closed_input)

        broken_channel = _Client(stdout=b"", status=0)
        self.assertEqual(BOOTSTRAP.run_password_sudo(broken_channel, "id -u", "fixture-password"), 84)
        self.assertEqual(broken_channel.stdin.value, "")

    def test_hcp_rule_overrides_requiretty_only_for_the_enrolled_user(self):
        rendered = BOOTSTRAP.sudo_setup_script("lab", "a" * 64)
        self.assertIn("Defaults:lab !requiretty", rendered)
        self.assertIn("lab ALL=(root) NOPASSWD: ALL", rendered)
        self.assertIn("hcp_legacy_tmp", rendered)
        self.assertIn(BOOTSTRAP.SUDO_ELEVATED_MARKER, rendered)

        wrapper = BOOTSTRAP.sudo_attempt_script(rendered)
        self.assertIn(BOOTSTRAP.SUDO_READY_MARKER, wrapper)
        self.assertIn("stty -echo", wrapper)
        self.assertIn('>"$hcp_out" 2>"$hcp_err"', wrapper)
        self.assertIn("exit 80", wrapper)
        self.assertIn("exit 81", wrapper)
        self.assertIn("exit 83", wrapper)

    def test_readiness_probe_matches_noninteractive_ansible_sudo_shape(self):
        rendered = BOOTSTRAP.sudo_readiness_script()
        self.assertIn("sudo -H -S -k -n -u root", rendered)
        self.assertIn("/bin/sh -c", rendered)
        self.assertIn("/usr/bin/python3", rendered)
        self.assertIn("geteuid", rendered)

    def test_sudo_setup_failures_use_safe_stable_codes(self):
        for status, code in {
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
        }.items():
            self.assertEqual(BOOTSTRAP.sudo_setup_failure(status), code)
        self.assertEqual(BOOTSTRAP.sudo_setup_failure(1), "sudo_elevation_rejected_or_policy")


if __name__ == "__main__":
    unittest.main()
