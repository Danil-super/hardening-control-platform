import importlib.util
import sys
import unittest
from pathlib import Path


AGENT_PATH = Path(__file__).resolve().parents[1] / "agent.py"
SPEC = importlib.util.spec_from_file_location("hcp_agent_openscap", AGENT_PATH)
assert SPEC and SPEC.loader
hcp_agent = importlib.util.module_from_spec(SPEC)
sys.modules["hcp_agent_openscap"] = hcp_agent
SPEC.loader.exec_module(hcp_agent)


class OpenScapParserTest(unittest.TestCase):
    def test_parse_failed_rule_result_with_title_and_mapping(self) -> None:
        content = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
    <title>Disable SSH Root Login</title>
  </Rule>
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login" severity="high">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_package_aide_installed" severity="medium">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>"""

        findings = hcp_agent.parse_openscap_results("basic_linux", content, "/tmp/results.xml")

        self.assertEqual(1, len(findings))
        self.assertEqual("openscap_sshd_disable_root_login", findings[0].id)
        self.assertEqual("high", findings[0].risk)
        self.assertEqual("SSH", findings[0].category)
        self.assertEqual("disable_ssh_root_login", findings[0].remediationId)
        self.assertTrue(findings[0].remediationAvailable)
        self.assertEqual("openscap", findings[0].source)

    def test_parse_unknown_failed_rule_uses_category_heuristic(self) -> None:
        content = """<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen" severity="medium">
      <result>error</result>
    </rule-result>
  </TestResult>
</Benchmark>"""

        findings = hcp_agent.parse_openscap_results("basic_linux", content, "/tmp/results.xml")

        self.assertEqual(1, len(findings))
        self.assertEqual("openscap_accounts_password_pam_minlen", findings[0].id)
        self.assertEqual("medium", findings[0].risk)
        self.assertEqual("Учетные записи", findings[0].category)
        self.assertFalse(findings[0].remediationAvailable)


if __name__ == "__main__":
    unittest.main()
