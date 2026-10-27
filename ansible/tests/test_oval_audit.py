"""OVAL semantics and boundary regressions; fixtures are synthetic, not vendor feeds."""
import argparse
import datetime
import hashlib
import io
import importlib.util
import json
import os
import shutil
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
               'sha256': hashlib.sha256(raw).hexdigest() if raw else '', 'maxAgeDays': 30,
               'sourceName': 'Тестовый доверенный реестр', 'sourceReference': 'TEST-OVAL-1'}
    current.update(values)
    return oval.parse_config(current)


def arguments(**values):
    return argparse.Namespace(**dict({'inventory_host': 'astra-test', 'run_id': 'test', 'input': '',
                                     'config': json.dumps(config())}, **values))


class OvalAuditTests(unittest.TestCase):
    def test_indexed_stylesheet_preserves_all_template_priorities_and_rules(self):
        stylesheet = b'''<axsl:stylesheet xmlns:axsl="http://www.w3.org/1999/XSL/Transform"
          xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" version="1.0">
          <axsl:param name="example"/><axsl:template match="/">
          <axsl:apply-templates select="/" mode="M1"/></axsl:template>
          <axsl:template match="oval-def:tests/*/oval-def:object" priority="1001" mode="M1">
          <axsl:if test="@object_ref=ancestor::oval-def:oval_definitions/oval-def:objects/oval-def:example_object/@id">OBJECT RULE</axsl:if>
          <axsl:apply-templates select="@*|*" mode="M1"/></axsl:template>
          <axsl:template match="oval-def:tests/*/oval-def:state" priority="1000" mode="M1">STATE RULE
          <axsl:apply-templates select="@*|*" mode="M1"/></axsl:template>
          <axsl:template match="text()" priority="-1" mode="M1"/>
          <axsl:template match="@*|node()" priority="-2" mode="M1"><axsl:apply-templates select="@*|*" mode="M1"/></axsl:template>
          </axsl:stylesheet>'''
        optimized, proof = oval.indexed_schematron(stylesheet)
        self.assertEqual(proof['rules'], 2)
        self.assertEqual(proof['indexedLookups'], 1)
        self.assertIn(b'OBJECT RULE', optimized)
        self.assertIn(b'STATE RULE', optimized)
        self.assertIn(b'//oval-def:tests/*/oval-def:object | //oval-def:tests/*/oval-def:state', optimized)
        self.assertIn(b'priority="1001"', optimized)
        self.assertNotIn(b'@object_ref=ancestor::', optimized)
        # An unknown traversal with side effects must use the original validator.
        unexpected = stylesheet.replace(b'<axsl:template match="text()" priority="-1" mode="M1"/>',
            b'<axsl:template match="text()" priority="-1" mode="M1"><axsl:value-of select="."/></axsl:template>')
        self.assertIsNone(oval.indexed_schematron(unexpected))

    @unittest.skipUnless(shutil.which('oscap') and Path('/usr/share/openscap/schemas/oval/5.11.1').is_dir(), 'Requires actual controller OpenSCAP')
    def test_indexed_and_stock_openscap_agree_on_valid_sources_and_invalid_reference_types(self):
        spec = importlib.util.spec_from_file_location('oval_acceptance_fixture',
            SCRIPT.parents[2] / 'deployment/tests/verify_oval.py')
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        raw = fixture.content(oval.now().isoformat())
        variants = [raw,
            raw.replace(b'object_ref="oval:hcp.acceptance:obj:1"', b'object_ref="missing"'),
            raw.replace(b'state_ref="oval:hcp.acceptance:ste:1"', b'state_ref="missing"'),
            raw.replace(b'<linux:dpkginfo_object', b'<linux:rpminfo_object').replace(b'</linux:dpkginfo_object>', b'</linux:rpminfo_object>'),
            raw.replace(b'<linux:dpkginfo_state', b'<linux:rpminfo_state').replace(b'</linux:dpkginfo_state>', b'</linux:rpminfo_state>'),
            raw.replace(b'check="all"', b'check="none exist"')]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'source.xml'
            target.write_bytes(raw)
            environment, proof = oval.schematron_environment(str(target), directory)
            self.assertIsNotNone(environment)
            self.assertGreater(proof['rules'], proof['ruleGroups'])
            for index, value in enumerate(variants):
                target.write_bytes(value)
                command = [shutil.which('oscap'), 'oval', 'validate', str(target)]
                stock = oval.run_oscap(command, directory, 30, capture_stdout=True)
                indexed = oval.run_oscap(command, directory, 30, capture_stdout=True, environment=environment)
                with self.subTest(index=index):
                    self.assertEqual(stock, indexed)
                    if index == 0: self.assertEqual(stock[0], 0)
                    elif index < 5: self.assertNotEqual(stock[0], 0)

    def test_slow_download_is_allowed_past_five_minutes_and_keeps_its_deadline(self):
        raw = source(timestamp=oval.now().isoformat())
        class Response(io.BytesIO):
            headers = {'Content-Length': str(len(raw))}
            def geturl(self): return 'https://mirror.example/db.xml'
            def getcode(self): return 200
        class Opener:
            def open(self, request, timeout): return Response(raw)
        for times, success in (([0, 301, 302], True), ([0, 0, oval.DOWNLOAD_TIMEOUT + 1], False)):
            with tempfile.TemporaryDirectory() as directory, patch.object(urllib.request, 'build_opener', return_value=Opener()), patch.object(oval.time, 'monotonic', side_effect=times):
                target = Path(directory) / 'source.xml'
                settings = config(raw, mode='online', url='https://mirror.example/db.xml')
                if success:
                    oval.prepare(settings, str(target))
                    self.assertEqual(target.read_bytes(), raw)
                else:
                    with self.assertRaisesRegex(ValueError, 'Превышено время загрузки'):
                        oval.prepare(settings, str(target))
                    self.assertFalse(target.exists())

    def test_controller_validation_never_accepts_schema_or_semantic_errors(self):
        for outcomes in ([1], [None], [0, 1]):
            with self.subTest(outcomes=outcomes), patch.object(oval, 'run_oscap', side_effect=[(code, 'invalid source') for code in outcomes]) as run:
                with self.assertRaises(ValueError):
                    oval.validate_for_transfer('/usr/bin/oscap', '/tmp/source.xml', 'a' * 64, 100, '/tmp')
                self.assertEqual(run.call_count, len(outcomes))

    def test_large_feed_schematron_timeout_is_recorded_as_partial_after_successful_xsd(self):
        with patch.object(oval, 'run_oscap', side_effect=[(0, ''), (None, 'timeout'), (0, 'OpenSCAP fixture')]):
            proof = oval.validate_for_transfer('/usr/bin/oscap', '/tmp/source.xml', 'a' * 64, 100 * 1024 * 1024, '/tmp')
        self.assertEqual(proof['schemaExitCode'], 0)
        self.assertIsNone(proof['schematronExitCode'])
        scanner = {'partialReasons': []}
        args = arguments(input='/tmp/source.xml', source_validation=json.dumps(proof))
        settings = config(mode='online', url='https://mirror.example/db.xml', sha256='a' * 64)
        self.assertTrue(oval.use_controller_validation(args, settings, 'a' * 64, scanner))
        self.assertIn('Schematron', scanner['partialReasons'][0])

    def test_controller_proof_is_bound_to_exact_online_bytes_and_never_accepted_for_local_sources(self):
        proof = {'sha256': 'a' * 64, 'schemaExitCode': 0, 'schematronExitCode': 0, 'validator': 'OpenSCAP fixture', 'location': 'control_node'}
        args = arguments(input='/tmp/source.xml', source_validation=json.dumps(proof))
        settings = config(mode='online', url='https://mirror.example/db.xml', sha256='a' * 64)
        for digest, current, changes in [('b' * 64, settings, {}), ('a' * 64, config(), {}), ('a' * 64, settings, {'schemaExitCode': True}), ('a' * 64, settings, {'schematronExitCode': 1}), ('a' * 64, settings, {'schematronExitCode': False}), ('a' * 64, settings, {'location': 'target'})]:
            args.source_validation = json.dumps(dict(proof, **changes))
            with self.subTest(changes=changes, digest=digest, mode=current['mode']), self.assertRaises(ValueError):
                oval.use_controller_validation(args, current, digest, {'partialReasons': []})

    def test_target_evaluates_controller_validated_bytes_without_repeating_old_validator(self):
        raw = source(timestamp=datetime.datetime.now(oval.UTC).isoformat())
        digest = hashlib.sha256(raw).hexdigest()
        proof = {'sha256': digest, 'schemaExitCode': 0, 'schematronExitCode': None, 'validator': 'OpenSCAP fixture', 'location': 'control_node'}
        calls = []
        def execute(command, directory, timeout=900, capture_stdout=False):
            if command[1] == '--version': return 0, 'OpenSCAP target'
            calls.append(command)
            self.assertEqual(command[2], 'eval')
            self.assertIn('--skip-validation', command)
            self.assertEqual(Path(command[-1]).read_bytes(), raw)
            Path(command[4]).write_bytes(results())
            return 0, ''
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'source.xml'
            target.write_bytes(raw)
            with patch.object(oval, 'host_identity', return_value={'id': 'astra', 'astraVersion': '1.7', 'architecture': 'x86_64'}), patch.object(oval.shutil, 'which', return_value='/usr/bin/oscap'), patch.object(oval, 'run_oscap', side_effect=execute):
                report = oval.evaluate(arguments(input=str(target), source_validation=json.dumps(proof), config=json.dumps(config(raw, mode='online', url='https://mirror.example/db.xml'))))
        self.assertEqual(len(calls), 1)
        self.assertTrue(report['scanner']['evaluationPerformed'])
        self.assertEqual(report['scanner']['uniqueCveCount'], 1)
        self.assertTrue(report['scanner']['partial'])
        self.assertIn('Schematron', ' '.join(report['scanner']['partialReasons']))

    def test_streamed_report_preserves_unicode_and_never_overwrites_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'report.json'
            value = {'message': 'Проверка Astra', 'results': [{'id': str(i)} for i in range(1000)]}
            oval.write_json(str(target), value)
            self.assertEqual(json.loads(target.read_text(encoding='utf-8')), value)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): oval.write_json(str(target), {})
            self.assertEqual(json.loads(target.read_text(encoding='utf-8')), value)
    def test_interrupted_https_download_resumes_and_still_checks_pinned_digest(self):
        raw = source(timestamp=datetime.datetime.now(oval.UTC).isoformat())
        split = len(raw) // 2
        requests = []
        class Response(io.BytesIO):
            def __init__(self, data, headers, status):
                super().__init__(data)
                self.headers, self.status = headers, status
            def geturl(self): return 'https://mirror.example/db.xml'
            def getcode(self): return self.status
        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                if len(requests) == 1:
                    return Response(raw[:split], {'Content-Length': str(len(raw)), 'ETag': 'fixture'}, 200)
                return Response(raw[split:], {'Content-Range': 'bytes {}-{}/{}'.format(split, len(raw)-1, len(raw)), 'ETag': 'fixture'}, 206)
        with tempfile.TemporaryDirectory() as directory, patch.object(urllib.request, 'build_opener', return_value=Opener()):
            target = str(Path(directory) / 'db.xml')
            result = oval.prepare(config(raw, mode='online', url='https://mirror.example/db.xml'), target)
            self.assertTrue(result['ok'])
            self.assertEqual(Path(target).read_bytes(), raw)
            self.assertEqual(requests[1].get_header('Range'), 'bytes={}-'.format(split))
            self.assertEqual(requests[1].get_header('If-range'), 'fixture')
            requests.clear()
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                oval.prepare(config(raw, mode='online', url='https://mirror.example/db.xml', sha256='0'*64), str(Path(directory) / 'wrong.xml'))
            self.assertFalse((Path(directory) / 'wrong.xml').exists())

    def test_resource_bounds_accept_the_current_vendor_feed_and_reject_complexity_overflow(self):
        # Measured official XML: 131721258 bytes, 796021 nodes; no live fetch in tests.
        self.assertGreater(oval.MAX_SOURCE_BYTES, 131721258)
        self.assertGreater(oval.MAX_XML_NODES, 796021)
        with patch.object(oval, 'MAX_XML_NODES', 3), self.assertRaises(ValueError):
            oval.safe_xml(b'<root><a/><b/><c/></root>')

    def test_download_restarts_if_range_is_ignored_and_rejects_changed_ranges(self):
        raw = source(timestamp=datetime.datetime.now(oval.UTC).isoformat())
        class Response(io.BytesIO):
            def __init__(self, data, headers, status):
                super().__init__(data)
                self.headers, self.status = headers, status
            def geturl(self): return 'https://mirror.example/db.xml'
            def getcode(self): return self.status
        for mode in ('ignored', 'changed', 'wrong-offset', 'incomplete'):
            class Opener:
                calls = 0
                def open(self, request, timeout):
                    self.calls += 1
                    if self.calls == 1 or mode == 'incomplete':
                        return Response(raw[:20], {'Content-Length': str(len(raw)), 'ETag': 'original'}, 200)
                    if mode == 'ignored':
                        return Response(raw, {'Content-Length': str(len(raw)), 'ETag': 'original'}, 200)
                    return Response(raw[20:], {'Content-Range': 'bytes {}-{}/{}'.format(21 if mode == 'wrong-offset' else 20, len(raw)-1, len(raw)), 'ETag': 'changed' if mode == 'changed' else 'original'}, 206)
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, patch.object(urllib.request, 'build_opener', return_value=Opener()):
                target = Path(directory) / 'db.xml'
                settings = config(raw, mode='online', url='https://mirror.example/db.xml')
                if mode == 'ignored':
                    oval.prepare(settings, str(target))
                    self.assertEqual(target.read_bytes(), raw)
                else:
                    with self.assertRaises(ValueError): oval.prepare(settings, str(target))
                    self.assertFalse(target.exists())

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

    def test_foreign_platforms_never_confirm_astra_cve_even_with_true_package_result(self):
        for platform in ('Ubuntu 24.04', 'Debian GNU/Linux 12', 'Red Hat Enterprise Linux 9',
                         'cpe:/o:oracle:linux:8', 'CPE:2.3:O:MICROSOFT:WINDOWS_11:*:*:*:*:*:*:*',
                         'cpe:2.3:o:apple:mac_os_x:14:*:*:*:*:*:*:*'):
            with self.subTest(platform=platform):
                raw = source().replace(b'<metadata>', ('<metadata><affected family="unix"><platform>' + platform
                    + '</platform><product>fixture-package</product></affected>').encode())
                report = oval.empty_report(arguments())
                oval.parse_results(oval.safe_xml(results()), oval.source_definitions(oval.safe_xml(raw)), report)
                report = oval.finish(report)
                scanner = report['scanner']
                self.assertTrue(scanner['partial'])
                self.assertIsNone(scanner['uniqueCveCount'])
                self.assertEqual(scanner['evaluatedVulnerabilityDefinitionCount'], 0)
                self.assertEqual(scanner['excludedPlatformDefinitionCount'], 1)
                self.assertEqual(scanner['resultCounts'], {'true': 1})
                entry = scanner['definitionResults'][0]
                self.assertEqual(entry['result'], 'true')
                self.assertEqual(entry['affected'][0]['platforms'], [platform])
                self.assertEqual(entry['affected'][0]['products'], ['fixture-package'])
                self.assertEqual(entry['platformApplicability']['status'], 'foreign_platform')
                self.assertFalse(any(item['status'] == 'failed' for item in report['findings']))
                self.assertIn('CVE-2021-44228', report['findings'][0]['evidence'])

    def test_foreign_false_is_not_used_as_a_clean_cve_assessment(self):
        raw = source().replace(b'<metadata>', b'<metadata><affected family="unix"><platform>Debian</platform></affected>')
        report = oval.empty_report(arguments())
        oval.parse_results(oval.safe_xml(results(('false',))), oval.source_definitions(oval.safe_xml(raw)), report)
        report = oval.finish(report)
        self.assertTrue(report['scanner']['partial'])
        self.assertIsNone(report['scanner']['uniqueCveCount'])
        self.assertEqual(report['scanner']['resultCounts'], {'false': 1})

    def test_astra_metadata_can_coexist_with_foreign_platforms_without_release_whitelist(self):
        for astra in ('Astra Linux 1.6', 'Astra Linux 12.4-custom (Debian based)',
                      'cpe:2.3:o:rusbitech:astra_linux:99:*:*:*:*:*:*:*'):
            affected = [{'family': 'unix', 'platforms': ['Debian 12', astra], 'products': []}]
            result = oval.platform_applicability(affected)
            self.assertEqual(result['status'], 'astra_named')
            self.assertEqual(result['vendorReleaseApplicability'], 'not_verified')

    def test_unknown_platform_is_never_claimed_as_vendor_verified(self):
        for platforms in ([], ['Linux'], ['HCP synthetic fixture']):
            result = oval.platform_applicability([{'family': 'unix', 'platforms': platforms, 'products': []}])
            self.assertEqual(result['status'], 'not_verified')
            self.assertEqual(result['vendorReleaseApplicability'], 'not_verified')

    def test_missing_or_unrecognized_severity_is_explicitly_unrated(self):
        for severity, expected in (('', True), ('vendor-special', True), ('Important', False)):
            raw = source().replace(b'</metadata>', ('<severity>' + severity + '</severity></metadata>').encode())
            report = oval.empty_report(arguments())
            oval.parse_results(oval.safe_xml(results()), oval.source_definitions(oval.safe_xml(raw)), report)
            report = oval.finish(report)
            failed = [item for item in report['findings'] if item['status'] == 'failed']
            self.assertEqual(len(failed), 1)
            self.assertEqual(failed[0]['severityUnknown'], expected)
            self.assertEqual(report['scanner']['unratedVulnerabilityCount'], int(expected))
            self.assertIsNone(failed[0]['vulnerability']['cvss'])

    def test_explicit_chromium_label_is_attributed_and_conflicts_stay_unrated(self):
        for level in ('Critical', 'High', 'Medium', 'Low'):
            description = 'Synthetic evidence (Chromium security severity: ' + level + ')'
            raw = source().replace(b'Fixture 1', b'Astra chromium').replace(b'Synthetic evidence', description.encode())
            report = oval.empty_report(arguments())
            oval.parse_results(oval.safe_xml(results()), oval.source_definitions(oval.safe_xml(raw)), report)
            item = report['findings'][0]
            self.assertEqual(item['severityAssessment'], {'level': level.lower(), 'source': 'chromium_description'})
            self.assertFalse(item['severityUnknown'])
            self.assertIsNone(item['vulnerability']['cvss'])
        self.assertIsNone(oval.severity_assessment(None, 'openssl', '(Chromium security severity: Critical)'))
        self.assertIsNone(oval.severity_assessment(None, 'chromium', 'critical vulnerability'))
        self.assertIsNone(oval.severity_assessment(None, 'chromium', '(Chromium security severity: High) (Chromium security severity: Low)'))
        self.assertIsNone(oval.severity_assessment('custom', 'chromium', '(Chromium security severity: Critical)'))

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
            if command[2] == 'validate': self.assertGreaterEqual(timeout, 600)
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
