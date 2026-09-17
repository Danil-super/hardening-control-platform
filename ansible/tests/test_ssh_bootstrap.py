import importlib.util
from pathlib import Path
import unittest


HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "hcp-ssh-bootstrap.py"
SPEC = importlib.util.spec_from_file_location("hcp_ssh_bootstrap_test", HELPER_PATH)
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class _Channel:
    def __init__(self):
        self.closed_input = False

    def shutdown_write(self):
        self.closed_input = True

    def recv_exit_status(self):
        return 0


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

    def read(self, _limit):
        return self.value


class _Client:
    def __init__(self):
        self.calls = []
        self.channel = _Channel()
        self.stdin = _Input(self.channel)

    def exec_command(self, command, timeout, get_pty):
        self.calls.append({"command": command, "timeout": timeout, "get_pty": get_pty})
        return self.stdin, _Output(self.channel, b"0\n"), _Output(self.channel)


class SshBootstrapTests(unittest.TestCase):
    def test_password_fed_sudo_requests_a_tty_but_regular_key_commands_do_not(self):
        elevated = _Client()
        status, output = BOOTSTRAP.run_remote(elevated, "id -u", input_text="fixture-password", elevated=True)
        self.assertEqual((status, output), (0, "0\n"))
        self.assertTrue(elevated.calls[0]["get_pty"])
        self.assertIn("sudo -S -k", elevated.calls[0]["command"])
        self.assertEqual(elevated.stdin.value, "fixture-password\n")
        self.assertTrue(elevated.stdin.flushed)
        self.assertTrue(elevated.channel.closed_input)

        regular = _Client()
        BOOTSTRAP.run_remote(regular, "id -u")
        self.assertFalse(regular.calls[0]["get_pty"])

    def test_hcp_rule_overrides_requiretty_only_for_the_enrolled_user(self):
        rendered = BOOTSTRAP.sudo_setup_script("lab", "a" * 64)
        self.assertIn("Defaults:lab !requiretty", rendered)
        self.assertIn("lab ALL=(root) NOPASSWD: ALL", rendered)
        self.assertIn("hcp_legacy_tmp", rendered)

    def test_sudo_setup_failures_use_safe_stable_codes(self):
        self.assertEqual(BOOTSTRAP.sudo_setup_failure(74), "sudoers_unavailable")
        self.assertEqual(BOOTSTRAP.sudo_setup_failure(75), "sudoers_validation_failed")
        self.assertEqual(BOOTSTRAP.sudo_setup_failure(76), "sudoers_rule_conflict")
        self.assertEqual(BOOTSTRAP.sudo_setup_failure(1), "sudo_elevation_rejected_or_policy")


if __name__ == "__main__":
    unittest.main()
