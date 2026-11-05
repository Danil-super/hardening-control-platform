"""No network or VM execution: strict native QEMU source and SSH gating fixtures."""
import json
import unittest
import verify_astra17_qemu_kvm as mod


class QemuAstra17SmokeTests(unittest.TestCase):
    def test_exact_official_image_sha_and_size(self):
        self.assertEqual(mod.SOURCE["bytes"], 402259968)
        self.assertEqual(mod.SOURCE["sha256"],
                         "75d247c79beecd468ab9da777c1c90ca273f20ece748dc2575e7d091eb3e87b4")
        self.assertIn("1.7.6.uu2-base-qemu-mg15.3.1", mod.SOURCE["url"])
        self.assertNotIn("latest", mod.SOURCE["url"])
        self.assertIn("artifactory/api/storage", mod.SOURCE["metadataUrl"])

    def test_native_identity_requires_point_and_full_build(self):
        raw = ("NAME=Astra Linux\nID=astra\n"
               "HCP_RELEASE=1.7.6\nHCP_BUILD=1.7.6.15\n"
               "HCP_ARCH=x86_64\nHCP_KERNEL=6.1.90-1-generic\n"
               "HCP_MACHINE_ID=0123456789abcdef0123456789abcdef\n")
        expected = mod.identity_proof(raw)
        self.assertEqual(expected["fullBuild"], "1.7.6.15")
        self.assertEqual(expected["pointRelease"], "1.7.6")
        self.assertNotIn("0123456789abcdef", json.dumps(expected))
        for corrupted in [
            raw.replace("HCP_RELEASE=1.7.6", "HCP_RELEASE=1.7.7"),
            raw.replace("HCP_BUILD=1.7.6.15", "HCP_BUILD=1.7.6.14"),
            raw.replace("ID=astra", "ID=debian"),
            raw.replace("HCP_ARCH=x86_64", "HCP_ARCH=aarch64"),
            raw.replace("HCP_MACHINE_ID=0123456789abcdef0123456789abcdef",
                        "HCP_MACHINE_ID=" + "0" * 32),
            raw + "HCP_BUILD=1.7.6.15\n",
        ]:
            with self.subTest(case=hash(corrupted)):
                with self.assertRaises(RuntimeError):
                    mod.identity_proof(corrupted)

    def test_ssh_pin_strictly_matches_loopback_port_and_ed25519(self):
        port = 44440
        public = "[127.0.0.1]:%d ssh-ed25519 %s\n" % (port, "A" * 70)
        self.assertEqual(mod.key_line(public, port), public)
        for bad in (public + public,
                    public.replace("127.0.0.1", "192.0.2.3"),
                    public.replace("ssh-ed25519", "ssh-rsa"),
                    public.replace(str(port), "54321")):
            with self.assertRaises(RuntimeError):
                mod.key_line(bad, port)

    def test_required_security_limitations_are_explicit(self):
        data = open(mod.__file__, encoding="utf-8").read()
        self.assertIn('"nativeOpenScap18RulesVerified": False', data)
        self.assertIn('"nativeOval17Evaluated": False', data)
        self.assertIn('"nativeRollbackVerified": False', data)
        self.assertIn('"operatorProductionAccepted": False', data)
        self.assertNotIn("StrictHostKeyChecking=no", data)
        self.assertNotIn("shell=True", data)


if __name__ == "__main__":
    unittest.main()
