"""OVAL semantics and boundary regressions; fixtures are synthetic, not vendor feeds."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'hcp-oval-audit.py'
spec = importlib.util.spec_from_file_location('oval_audit', SCRIPT)
oval = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oval)


def source(classes=('vulnerability',), timestamp='2026-09-11T00:00:00Z', cve='CVE-2021-44228'):
    definitions = ''.join('''<definition id="oval:test:def:{index}" version="1" class="{kind}">
      <metadata><title>Fixture {index}</title><reference source="CVE" ref_id="{cve}"/>
      <description>Synthetic evidence</description></metadata>
      <criteria><criterion test_ref="oval:test:tst:1" comment="Package predicate"/></criteria>
      </definition>'''.format(index=index, kind=kind, cve=cve) for index, kind in enumerate(classes, 1))
    return ('''<oval_definitions xmlns="{ns}" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">
      <generator><oval:product_name>HCP test</oval:product_name><oval:schema_version>5.11.1</oval:schema_version>
      <oval:timestamp>{timestamp}</oval:timestamp></generator><definitions>{definitions}</definitions>
      </oval_definitions>'''.format(ns=oval.DEFINITIONS_NS, timestamp=timestamp, definitions=definitions)).encode()


def results(statuses=('true',), extra='', duplicate=False):
    entries = ''.join('<definition definition_id="oval:test:def:{index}" version="1" result="{status}"><criteria result="{status}"><criterion test_ref="oval:test:tst:1" result="{status}"/></criteria></definition>'.format(index=index, status=status) for index, status in enumerate(statuses, 1))
    if duplicate:
        entries += '<definition definition_id="oval:test:def:1" result="true"/>'
    return ('<oval_results xmlns="' + oval.RESULTS_NS + '"><results><system><definitions>' + entries + '</definitions>' + extra + '</system></results></oval_results>').encode()


def config(raw=None, **values):
    current = {'mode': 'local', 'path': '/usr/share/oval/db.xml', 'releasePattern': '*',
               'sha256': hashlib.sha256(raw).hexdigest() if raw else '', 'maxAgeDays': 30}
    current.update(values)
    return oval.parse_config(current)


def arguments(**values):
    return argparse.Namespace(**dict({'inventory_host': 'astra-test', 'run_id': 'test', 'input': '',
                                     'config': json.dumps(config())}, **values))


class OvalAuditTests(unittest.TestCase):
    def parse(self, classes, statuses, extra=''):
        root = oval.safe_xml(source(classes))
        report = oval.empty_report(arguments())
        oval.parse_results(oval.safe_xml(results(statuses, extra)), oval.source_definitions(root), report)
        return oval.finish(report)

    def test_definition_class_controls_cve_status_and_deduplication(self):
        report = self.parse(('vulnerability', 'vulnerability', 'patch', 'compliance', 'inventory'), ('true',) * 5)
        self.assertEqual(report['scanner']['uniqueCveCount'], 1)
        self.assertEqual(report['scanner']['cveIds'], ['CVE-2021-44228'])
        failed = [item for item in report['findings'] if item['status'] == 'failed']
        self.assertEqual(len(failed), 2)
        self.assertTrue(all(item['risk'] == 'info' and item['vulnerability']['cvss'] is None for item in failed))
        self.assertFalse(report['scanner']['fullCveCoverage'])
        self.assertEqual(len(report['scanner']['definitionResults']), 5)
        self.assertFalse(report['scanner']['partial'])

    def test_non_vulnerability_reference_never_becomes_cve(self):
        report = self.parse(('patch', 'compliance', 'inventory'), ('true',) * 3)
        self.assertIsNone(report['scanner']['uniqueCveCount'])
        self.assertTrue(report['scanner']['partial'])
        self.assertFalse(any(item['status'] == 'failed' for item in report['findings']))

    def test_false_results_have_no_global_secure_verdict(self):
        report = self.parse(('vulnerability',), ('false',))
        self.assertFalse(any(item['status'] == 'passed' for item in report['findings']))
        self.assertEqual(report['scanner']['definitionResults'][0]['result'], 'false')
        self.assertIsNone(report['summary']['score'])
        self.assertFalse(report['scanner']['fullCveCoverage'])

    def test_missing_unknown_error_not_evaluated_are_partial_and_preserved(self):
        for status in ('unknown', 'error', 'not evaluated'):
            with self.subTest(status=status):
                report = self.parse(('vulnerability', 'vulnerability'), ('true', status))
                self.assertTrue(report['scanner']['partial'])
                self.assertEqual(report['scanner']['uniqueCveCount'], 1)
                self.assertEqual(report['scanner']['definitionResults'][1]['result'], status)
        report = self.parse(('vulnerability', 'vulnerability'), ('false',))
        self.assertTrue(report['scanner']['partial'])
        self.assertEqual(report['scanner']['definitionResults'][1]['result'], 'missing')

    def test_all_not_applicable_vulnerability_results_are_not_a_cve_assessment(self):
        report = self.parse(('vulnerability',), ('not applicable',))
        self.assertTrue(report['scanner']['partial'])
        self.assertIsNone(report['scanner']['uniqueCveCount'])
        self.assertEqual(report['scanner']['evaluatedVulnerabilityDefinitionCount'], 0)

    def test_duplicate_or_foreign_results_are_rejected(self):
        defs = oval.source_definitions(oval.safe_xml(source()))
        for value in (results(('true', 'false')), results(duplicate=True)):
            with self.assertRaises(ValueError):
                oval.parse_results(oval.safe_xml(value), defs, oval.empty_report(arguments()))

    def test_test_references_and_packages_preserved_without_shadow_contents(self):
        extra = '''<tests><test test_id="oval:test:tst:1" result="true"><tested_item item_id="7" result="true"/></test></tests>
        <oval_system_characteristics><system_data>
        <dpkginfo_item id="7"><name>example</name><version>1.2-astra1</version><arch>amd64</arch></dpkginfo_item>
        <shadow_item id="9"><password>secret-shadow</password></shadow_item>
        </system_data></oval_system_characteristics>'''
        report = self.parse(('vulnerability',), ('true',), extra)
        self.assertEqual(report['scanner']['testResults'][0]['testedItems'][0]['item_id'], '7')
        self.assertEqual(report['scanner']['packageItems'][0]['values']['version'], '1.2-astra1')
        self.assertNotIn('secret-shadow', json.dumps(report))
        self.assertEqual(report['scanner']['definitionResults'][0]['resultCriteria']['children'][0]['attributes']['test_ref'], 'oval:test:tst:1')

    def test_xml_entities_alternate_encoding_xinclude_and_depth_rejected(self):
        invalid = [b'<!DOCTYPE x [<!ENTITY a "x">]><x>&a;</x>',
                   '<x/>'.encode('utf-16'), b'<x xmlns:i="http://www.w3.org/2001/XInclude"><i:include href="/etc/passwd"/></x>',
                   (('<x>' * 102) + ('</x>' * 102)).encode()]
        for value in invalid:
            with self.assertRaises(ValueError):
                oval.safe_xml(value)

    def test_nonlocal_sql_and_missing_external_variables_prevent_evaluation(self):
        for node in ('<sql57_object/>', '<external_variable/>'):
            raw = source().replace(b'</oval_definitions>', node.encode() + b'</oval_definitions>')
            with self.assertRaises(ValueError):
                oval.source_definitions(oval.safe_xml(raw))

    def test_hash_age_future_and_unknown_date(self):
        current_time = datetime.datetime(2026, 9, 11, 1, tzinfo=oval.UTC)
        raw = source()
        metadata, reasons = oval.source_metadata(oval.safe_xml(raw), raw, config(raw), current_time)
        self.assertTrue(metadata['checksumVerified'])
        self.assertEqual(metadata['freshness'], 'current')
        self.assertEqual(reasons, [])
        with self.assertRaises(ValueError):
            oval.source_metadata(oval.safe_xml(raw), raw, config(raw, sha256='0' * 64), current_time)
        for timestamp, expected in (('2026-01-01T00:00:00Z', 'stale'), ('2027-01-01T00:00:00Z', 'future'), ('invalid', 'unknown')):
            value = source(timestamp=timestamp)
            metadata, reasons = oval.source_metadata(oval.safe_xml(value), value, config(value), current_time)
            self.assertEqual(metadata['freshness'], expected)
            self.assertTrue(reasons)
        metadata, reasons = oval.source_metadata(oval.safe_xml(raw), raw, config(), current_time)
        self.assertFalse(metadata['checksumVerified'])
        self.assertTrue(reasons)

    def test_scope_supports_family_releases_and_architecture_aliases(self):
        for release in ('1.6.7.15', '1.7.6', '1.8', '12.4-custom'):
            oval.check_scope({'id': 'astra', 'astraVersion': release, 'architecture': 'x86_64'}, config(architectures=['amd64']))
        oval.check_scope({'id': 'astra', 'astraVersion': '1.7.6', 'architecture': 'aarch64'}, config(releasePattern='1.7.*', architectures=['arm64']))
        for identity in ({'id': 'debian', 'astraVersion': '1.7.6', 'architecture': 'x86_64'},
                         {'id': 'astra', 'astraVersion': '1.8', 'architecture': 'x86_64'},
                         {'id': 'astra', 'astraVersion': '1.7.6', 'architecture': 'aarch64'}):
            with self.assertRaises(ValueError):
                oval.check_scope(identity, config(releasePattern='1.7.*', architectures=['amd64']))

    def test_source_url_hash_and_path_boundaries(self):
        for url in ('http://mirror.example/db.xml', 'https://user:password@example/db.xml',
                    'https://mirror.example/db.xml#x', 'https://mirror.example/db.xml?token=secret'):
            with self.assertRaises(ValueError):
                config(mode='online', url=url, sha256='a' * 64)
        with self.assertRaises(ValueError):
            config(mode='online', url='https://mirror.example/db.xml')
        for path in ('relative.xml', '/etc/../db.xml', '/tmp/a\n.xml'):
            with self.assertRaises(ValueError):
                config(path=path)
        request = urllib.request.Request('https://mirror.example/db.xml')
        handler = oval.SameOriginRedirect(('mirror.example', 443))
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, '', {}, 'https://other.example/db.xml')
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, '', {}, 'http://mirror.example/db.xml')

    def test_local_reader_rejects_fifo_symlink_and_size_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'db.xml'
            target.write_bytes(source())
            self.assertEqual(oval.read_regular(str(target), 10000), source())
            with self.assertRaises(ValueError):
                oval.read_regular(str(target), 10)
            link = Path(directory) / 'link.xml'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                oval.read_regular(str(link), 10000)
            fifo = Path(directory) / 'fifo'
            os.mkfifo(str(fifo))
            with self.assertRaises(ValueError):
                oval.read_regular(str(fifo), 10000)

    def test_evaluate_snapshots_exact_source_and_preserves_scanner_error(self):
        raw = source()
        calls = []
        def execute(command, directory, timeout=900, capture_stdout=False):
            if command[1] == '--version':
                return 0, 'OpenSCAP command line tool (oscap) fixture\n'
            calls.append(command)
            self.assertEqual(Path(command[-1]).read_bytes(), raw)
            if command[2] == 'eval':
                Path(command[4]).write_bytes(results())
                return 1, 'Probe error after partial result'
            return 0, ''
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'db.xml'
            target.write_bytes(raw)
            with patch.object(oval, 'host_identity', return_value={'id': 'astra', 'astraVersion': '1.8', 'architecture': 'x86_64'}), \
                    patch.object(oval.shutil, 'which', return_value='/usr/bin/oscap'), patch.object(oval, 'run_oscap', side_effect=execute):
                report = oval.evaluate(arguments(config=json.dumps(config(raw, path=str(target)))))
        self.assertTrue(report['scanner']['evaluationPerformed'])
        self.assertTrue(report['scanner']['partial'])
        self.assertEqual(report['scanner']['uniqueCveCount'], 1)
        self.assertEqual([command[2] for command in calls], ['validate', 'eval'])
        self.assertTrue(all('--fetch-remote-resources' not in command for command in calls))

    def test_missing_source_does_not_report_zero_vulnerabilities(self):
        with patch.object(oval, 'host_identity', return_value={'id': 'astra', 'astraVersion': '1.7', 'architecture': 'x86_64'}):
            report = oval.evaluate(arguments(config=json.dumps(config(path='/nonexistent/hcp/db.xml'))))
        self.assertFalse(report['scanner']['evaluationPerformed'])
        self.assertIsNone(report['scanner']['uniqueCveCount'])
        self.assertTrue(report['scanner']['partial'])


if __name__ == '__main__':
    unittest.main()
