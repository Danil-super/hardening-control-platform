"""Exercise the real PDF renderer's historical asset scope and public projection."""

import base64
import importlib.util
import json
import re
import subprocess
import sys
import unittest
import zlib
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'hcp-final-report-pdf.py'
SPEC = importlib.util.spec_from_file_location('hcp_final_report_pdf', SCRIPT)
RENDERER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDERER)
ASSET_A = 'asset-' + 'a' * 64
ASSET_B = 'asset-' + 'b' * 64


def identity_fixture():
    timestamp = '2026-10-28T14:30:00Z'
    report_a = 'report-original-machine-' + 'a' * 125
    report_b = 'report-current-machine-' + 'b' * 125
    private_fields = {
        'machineIdSha256': 'c' * 64,
        'sshHostKeyFingerprint': 'SHA256:' + 'D' * 43,
        'connectionId': 'e' * 64,
        'machineId': 'PRIVATE_MACHINE_ID_MUST_NOT_RENDER',
        'privateKeyPath': '/private/SSH_KEY_PATH_MUST_NOT_RENDER',
    }
    manifest = [
        {'id': report_a, 'mode': 'agentless', 'assetBinding': dict(private_fields, version=1, status='verified', assetId=ASSET_A, generation=1)},
        {'id': report_b, 'mode': 'agentless', 'assetBinding': dict(private_fields, version=1, status='verified', assetId=ASSET_B, generation=2)},
        {'id': 'report-network-unknown', 'mode': 'nmap', 'assetBinding': dict(private_fields, version=1, status='unknown', reason='unauthenticated_network_scan', aliasGeneration=2)},
        {'id': 'report-legacy', 'mode': 'agentless', 'assetBinding': None},
    ]
    for item in manifest:
        item.update(createdAt=timestamp, sha256='1' * 64)
    issues = [['asset_identity_changed'], [], ['asset_identity_unverified'], ['legacy_identity_unknown']]
    coverage = [dict(reportId=item['id'], mode=item['mode'], createdAt=timestamp,
                     fresh=index in (1, 2), partial=index in (0, 3), available=True,
                     current=index in (1, 2), scanScope='top_100', coverageIssues=issues[index])
                for index, item in enumerate(manifest)]
    return {
        'id': 'project_report_11111111-2222-4333-8444-555555555555',
        'createdAt': timestamp, 'hostAlias': 'production-host',
        'subject': {'clientName': 'Демонстрационный заказчик', 'projectName': 'Смена машины под прежним псевдонимом',
                    'period': 'Октябрь 2026', 'specialist': 'Аудитор'},
        'scope': {'auditModes': ['agentless', 'nmap']},
        'coverage': coverage,
        'findings': [{
            'title': 'Ранее согласованное решение для машины A', 'risk': 'high', 'status': 'confirmed',
            'description': 'Исторический контроль был проверен на исходной машине.',
            'recommendation': 'Сопоставить исходный актив до повторного применения решения.',
            'evidence': [{'reportId': report_a, 'findingId': 'original-machine-firewall-control'}],
        }],
        'unplannedFindings': [{
            'title': 'Текущая находка машины B: открытый Telnet', 'risk': 'high', 'severityUnknown': False,
            'recommendation': 'Проверить необходимость службы и ограничить доступ.',
            'sources': [{'reportId': report_b, 'findingId': 'current-machine-telnet'}],
        }],
        'transactions': [], 'integrity': {'valid': True, 'entries': 12, 'payloadProtected': True},
        'sourceManifest': manifest, 'sourceManifestSha256': '2' * 64,
    }


def decoded_pdf_streams(pdf):
    """Read actual compressed PDF streams using only the standard library."""
    streams = []
    for raw in re.findall(rb'stream\r?\n(.*?)endstream', pdf, re.S):
        try:
            raw = raw.strip()
            if raw.endswith(b'~>'):
                raw = base64.a85decode(raw, adobe=True)
            streams.append(zlib.decompress(raw))
        except (ValueError, zlib.error):
            pass
    return b'\n'.join(streams)


class FinalReportIdentityPdfTest(unittest.TestCase):
    def test_identity_exclusions_are_distinct_from_historical_scan_scope(self):
        expected = {
            'asset_identity_changed': 'другая машина',
            'asset_connection_changed': 'параметры подключения изменены',
            'asset_binding_invalid': 'недостоверная привязка',
            'legacy_identity_unknown': 'идентичность машины неизвестна',
        }
        for reason, label in expected.items():
            with self.subTest(reason=reason):
                state = RENDERER.coverage_state({'current': False, 'coverageIssues': [reason]})
                self.assertIn(label, state)
                self.assertIn('исключён из текущей оценки', state)
                self.assertNotIn('историческая область', state)
        self.assertIn('историческая область', RENDERER.coverage_state({'current': False, 'coverageIssues': ['scope_superseded']}))
        unknown = RENDERER.coverage_state({'current': True, 'fresh': True, 'available': True,
                                           'mode': 'nmap', 'coverageIssues': ['asset_identity_unverified']})
        self.assertIn('завершён в выбранной области', unknown)
        self.assertIn('идентичность машины не подтверждена (unknown)', unknown)

    def test_missing_and_malformed_bindings_never_claim_verified_identity(self):
        self.assertIn('legacy', RENDERER.asset_binding_label(None))
        self.assertIn('unknown', RENDERER.asset_binding_label({'version': 1, 'status': 'unknown', 'reason': 'unauthenticated_network_scan'}))
        for binding in ({}, {'version': 1, 'status': 'verified', 'assetId': '/private/SECRET', 'generation': 1},
                        {'version': 1, 'status': 'verified', 'assetId': ASSET_A, 'generation': True}):
            with self.subTest(binding=binding):
                label = RENDERER.asset_binding_label(binding)
                self.assertIn('недостоверна', label)
                self.assertNotIn('SECRET', label)
                self.assertNotIn(ASSET_A, label)

    def test_actual_pdf_preserves_original_plan_asset_and_omits_private_identity_fields(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], input=json.dumps(identity_fixture()).encode('utf-8'),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertTrue(result.stdout.startswith(b'%PDF-'))
        contents = decoded_pdf_streams(result.stdout)
        # A occurs in both the plan's source scope and the source manifest;
        # B has its own manifest identity and must not replace A's plan scope.
        self.assertGreaterEqual(contents.count(ASSET_A.encode('ascii')), 2)
        self.assertIn(ASSET_B.encode('ascii'), contents)
        self.assertIn(b'unknown', contents)
        self.assertIn(b'legacy', contents)
        for secret in ('c' * 64, 'SHA256:' + 'D' * 43, 'e' * 64,
                       'PRIVATE_MACHINE_ID_MUST_NOT_RENDER', '/private/SSH_KEY_PATH_MUST_NOT_RENDER'):
            self.assertNotIn(secret.encode('ascii'), contents)
        page_count = len(re.findall(rb'/Type\s*/Page\b', result.stdout))
        self.assertGreaterEqual(page_count, 2)
        self.assertLessEqual(page_count, 3)


if __name__ == '__main__':
    unittest.main()
