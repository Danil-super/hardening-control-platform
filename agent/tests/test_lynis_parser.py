import importlib.util
import sys
import unittest
from pathlib import Path


AGENT_PATH = Path(__file__).resolve().parents[1] / "agent.py"
SPEC = importlib.util.spec_from_file_location("hcp_agent", AGENT_PATH)
assert SPEC and SPEC.loader
hcp_agent = importlib.util.module_from_spec(SPEC)
sys.modules["hcp_agent"] = hcp_agent
SPEC.loader.exec_module(hcp_agent)


class LynisParserTest(unittest.TestCase):
    def test_parse_console_warning_and_suggestion(self) -> None:
        output = "\n".join(
            [
                "[WARNING]: Found one or more cronjob files with incorrect file permissions [SCHD-7704]",
                "[SUGGESTION]: Harden compilers by restricting access to root [HRDN-7222]",
            ],
        )

        findings = hcp_agent.parse_lynis_findings("basic_linux", output)

        self.assertEqual(2, len(findings))
        self.assertEqual("lynis_schd-7704", findings[0].id)
        self.assertEqual("high", findings[0].risk)
        self.assertEqual("lynis_hrdn-7222", findings[1].id)
        self.assertEqual("medium", findings[1].risk)

    def test_parse_report_dat_warning_and_suggestion(self) -> None:
        content = "\n".join(
            [
                "# Lynis Report",
                "warning[]=Found one or more cronjob files with incorrect file permissions|SCHD-7704|",
                "suggestion[]=Harden compilers by restricting access to root|HRDN-7222|",
                "hardening_index=68",
            ],
        )

        findings = hcp_agent.parse_lynis_report_dat("basic_linux", content, "/tmp/lynis-report.dat")

        self.assertEqual(2, len(findings))
        self.assertEqual("lynis_schd-7704", findings[0].id)
        self.assertEqual("high", findings[0].risk)
        self.assertIn("/tmp/lynis-report.dat", findings[0].evidence)
        self.assertEqual("lynis_hrdn-7222", findings[1].id)
        self.assertEqual("medium", findings[1].risk)


if __name__ == "__main__":
    unittest.main()
