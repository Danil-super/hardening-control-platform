"""Run the real entrypoint in an isolated filesystem, without a Docker daemon.

Requires Linux, root/chroot, ssh-keygen and coreutils. This validates file
initialization and privilege dropping, not image builds or container networking.
"""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]


def supports_chroot():
    if os.geteuid() != 0 or not shutil.which("chroot"):
        return False
    return subprocess.run(["chroot", "/", "/bin/true"], capture_output=True).returncode == 0


@unittest.skipUnless(supports_chroot(), "requires root with permitted chroot (CAP_SYS_CHROOT)")
class EntrypointTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hcp-entrypoint-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)
        for directory in ("etc", "dev", "run/secrets", "app/ansible", "home/node/.ssh", "var/lib/hcp"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\nnode:x:1000:1000:node:/home/node:/bin/sh\n")
        (self.root / "etc/group").write_text("root:x:0:\nnode:x:1000:\n")
        (self.root / "dev/null").touch()
        (self.root / "dev/null").chmod(0o666)
        for name in ("sh", "id", "mkdir", "chown", "chmod", "cp", "ssh-keygen", "ln", "rm", "dirname", "setpriv", "cat"):
            binary = shutil.which(name)
            if not binary:
                self.skipTest(f"missing {name}")
            self.copy_binary(binary, f"/bin/{name}")
        shutil.copyfile(REPO / "deployment/docker-entrypoint.sh", self.root / "entrypoint.sh")
        (self.root / "run/secrets/inventory.ini").write_text("[linux_hosts]\ninitial-host\n")
        (self.root / "run/secrets/known_hosts").write_text("initial-trusted-host\n")
        self.key = self.root / "run/secrets/hcp-control"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True)

    def tearDown(self):
        self.temporary.cleanup()

    def copy_binary(self, source, target):
        output = self.root / target.lstrip("/")
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output)
        output.chmod(0o755)
        linked = subprocess.run(["ldd", source], text=True, capture_output=True, check=True).stdout
        for library in re.findall(r"(?:=>\s*)?(/[^\s]+)", linked):
            destination = self.root / library.lstrip("/")
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(library, destination)

    def start(self, command="id -u"):
        return subprocess.run(
            ["chroot", str(self.root), "/bin/sh", "/entrypoint.sh", "/bin/sh", "-c", command],
            env={"PATH": "/bin:/usr/bin:/usr/sbin", "HCP_KNOWN_HOSTS_PATH": "/var/lib/hcp/known_hosts"},
            text=True, capture_output=True,
        )

    def test_initializes_writable_inventory_and_drops_root(self):
        result = self.start("test -w /app/ansible/inventory.ini && test -r /home/node/.ssh/hcp-control && id -u")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "1000")
        self.assertEqual(os.readlink(self.root / "app/ansible/inventory.ini"), "/var/lib/hcp/inventory.ini")
        inventory = self.root / "var/lib/hcp/inventory.ini"
        self.assertEqual(inventory.stat().st_uid, 1000)
        self.assertEqual(inventory.stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.root / "home/node/.ssh/hcp-control.pub").read_text().startswith("ssh-ed25519 "))

    def test_restart_preserves_operator_inventory_and_trust(self):
        first = self.start()
        self.assertEqual(first.returncode, 0, first.stderr)
        (self.root / "var/lib/hcp/inventory.ini").write_text("[linux_hosts]\noperator-added-host\n")
        (self.root / "var/lib/hcp/known_hosts").write_text("operator-confirmed-key\n")
        second = self.start()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("operator-added-host", (self.root / "var/lib/hcp/inventory.ini").read_text())
        self.assertEqual((self.root / "var/lib/hcp/known_hosts").read_text(), "operator-confirmed-key\n")

    def test_missing_key_is_an_actionable_startup_error(self):
        self.key.unlink()
        result = self.start()
        self.assertEqual(result.returncode, 64)
        self.assertIn("Missing SSH key", result.stderr)

    def test_passphrase_key_is_rejected_without_interactive_prompt(self):
        self.key.unlink()
        self.key.with_suffix(".pub").unlink()
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "test-passphrase", "-f", str(self.key)], check=True)
        result = self.start()
        self.assertEqual(result.returncode, 64)
        self.assertIn("without a passphrase", result.stderr)


if __name__ == "__main__":
    unittest.main()
