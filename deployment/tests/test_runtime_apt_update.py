"""Exercise the Dockerfile's APT update flags without touching system indexes."""
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import unittest


class RuntimeAptUpdateTests(unittest.TestCase):
    def test_unavailable_index_prevents_package_installation(self):
        dockerfile = (Path(__file__).resolve().parents[2] / "Dockerfile").read_text()
        commands = re.findall(r"^RUN (apt-get [^\n]*?) update\s*\\$", dockerfile, re.M)
        self.assertEqual(len(commands), 1, "Expected one runtime APT update")
        command = shlex.split(commands[0])
        command[0] = shutil.which("apt-get")
        self.assertIsNotNone(command[0], "APT is required for this build regression")
        with socket.socket() as unavailable:
            # A bound, non-listening socket reserves a deterministically refused port.
            unavailable.bind(("127.0.0.1", 0))
            port = unavailable.getsockname()[1]
            with tempfile.TemporaryDirectory(prefix="hcp-apt-index-test-") as directory:
                root = Path(directory)
                (root / "lists" / "partial").mkdir(parents=True)
                (root / "cache").mkdir()
                source = root / "sources.list"
                source.write_text(f"deb http://127.0.0.1:{port}/ unavailable main\n")
                marker = root / "package-install-started"
                options = ["-o", f"Dir::Etc::sourcelist={source}",
                           "-o", "Dir::Etc::sourceparts=-", "-o", "Dir::Etc::main=/dev/null",
                           "-o", "Dir::Etc::parts=-", "-o", f"Dir::State::lists={root / 'lists'}",
                           "-o", f"Dir::Cache={root / 'cache'}", "-o", "Acquire::http::Timeout=1",
                           "-o", f"APT::Sandbox::User={pwd.getpwuid(os.geteuid()).pw_name}"]
                env = {k: v for k, v in os.environ.items() if not k.lower().endswith("proxy")}
                env["LC_ALL"] = "C"

                def update(flags):
                    return subprocess.run(
                        ["/bin/sh", "-c", shlex.join(flags + options + ["update"])
                         + " && touch " + shlex.quote(str(marker))],
                        capture_output=True, text=True, env=env, timeout=20)

                result = update(command)
                self.assertIn("Failed to fetch", result.stdout + result.stderr)
                self.assertNotEqual(result.returncode, 0, "APT accepted a missing index")
                self.assertFalse(marker.exists(), "Package installation would have started")
                control = command.copy()
                option = control.index("APT::Update::Error-Mode=any")
                del control[option - 1:option + 1]
                result = update(control)
                self.assertIn("Failed to fetch", result.stdout + result.stderr)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(marker.exists(), "Negative control did not reproduce the bug")


if __name__ == "__main__":
    unittest.main()
