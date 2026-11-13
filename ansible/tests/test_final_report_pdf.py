"""Exercise the real PDF renderer's historical asset scope and public projection."""

import base64
import importlib.util
import json
import re
import subprocess
import sys
import unittest
from unittest.mock import patch
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
    def test_report_image_markup_stays_text_in_both_pdf_formats(self):
        markup = '<img src="file:///hcp-img"/> &lt;img src="https://invalid.test/img"/&gt;'
        project = identity_fixture()
        project['hostAlias'] = markup
        project['subject'] = {key: markup for key in project['subject']}
        for item in project['findings'] + project['unplannedFindings']:
            item.update(title=markup, description=markup, recommendation=markup)
        audit = {'kind': 'audit', 'id': 'image-markup', 'available': True,
                 'hostAlias': markup, 'mode': 'lynis', 'coverageIssues': [markup],
                 'findings': [{'id': markup, 'title': markup, 'description': markup,
                               'recommendation': markup, 'source': markup}],
                 'events': [{'source': markup, 'message': markup}]}
        for snapshot in (project, audit):
            with self.subTest(kind=snapshot.get('kind', 'project')):
                with patch('reportlab.platypus.paraparser.ImageReader',
                           side_effect=AssertionError('report text reached image loading')) as reader, \
                     patch('PIL.Image.open',
                           side_effect=AssertionError('report text reached Pillow')) as opener:
                    pdf = RENDERER.render(snapshot)
                    reader.assert_not_called()
                    opener.assert_not_called()
                self.assertTrue(pdf.startswith(b'%PDF-'))
                self.assertTrue(b'file:///hcp-img' in decoded_pdf_streams(pdf),
                                'literal image filename disappeared from PDF text')

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


    def test_debian_package_index_pdf_rejects_forged_install_origin_or_corrupt_digest(self):
        fixture = identity_fixture()
        evidence = {
            "schemaVersion": 1, "sourceReportId": "debian-package-inventory",
            "sourceReportSha256": "a" * 64, "status": "locally_hash_matched",
            "provenanceScope": "cached-debian-packages-uncompressed-sha256-locally-signed-release-v1",
            "candidateIndexes": 1, "matchedIndexes": 1, "missingSignedHashes": 0,
            "mismatchedIndexes": 0, "verifiedAgainstLocallySignedRelease": True,
            "publisherAuthenticated": False, "keyringIndependentlyAuthenticated": False,
            "publisherFreshnessVerified": False, "installedPackageOriginVerified": False,
            "remediationAuthorized": False,
            "indexRecords": [{"suite": "bookworm", "component": "main", "architecture": "amd64",
                              "releaseSha256": "b" * 64, "packagesSha256": "c" * 64,
                              "packagesBytes": 4096}],
        }
        fixture["debianPackageIndexEvidence"] = [evidence]
        fixture["debianPackageIndexEvidenceSha256"] = "d" * 64
        self.assertTrue(RENDERER.render(fixture).startswith(b"%PDF-"))
        candidate = {
            "schemaVersion": 1, "status": "candidate_record_match",
            "eligibleInstalled": 150, "exactInstalledVersionCandidates": 72,
            "matchedIdentitySha256": "e" * 64,
            "scope": "installed-dpkg-version-in-locally-verified-Packages-record-v1",
            "publisherAuthenticated": False, "installedPackageOriginVerified": False,
            "remediationAuthorized": False,
        }
        fixture["debianPackageIndexEvidence"] = [{**evidence, "installedVersionCandidates": candidate}]
        self.assertTrue(RENDERER.render(fixture).startswith(b"%PDF-"))
        for invalid in [
            {"installedPackageOriginVerified": True}, {"publisherAuthenticated": True},
            {"remediationAuthorized": True}, {"exactInstalledVersionCandidates": 151},
            {"matchedIdentitySha256": "not-a-sha256"}, {"status": "installed-archive-proven"},
        ]:
            fixture["debianPackageIndexEvidence"] = [{
                **evidence, "installedVersionCandidates": {**candidate, **invalid}}]
            with self.subTest(invalid_candidate=invalid), self.assertRaises(ValueError):
                RENDERER.render(fixture)
        archive = {
            "schemaVersion": 1, "status": "locally_hash_matched", "eligibleInstalled": 150,
            "candidateArchives": 1, "matchedArchives": 1, "mismatchedArchives": 0,
            "missingIndexHashes": 0, "ambiguousIndexHashes": 0,
            "verifiedArchiveSha256": ["f" * 64],
            "scope": "cached-deb-sha256-locally-verified-Packages-record-only-v1",
            "publisherAuthenticated": False, "installedPackageOriginVerified": False,
            "remediationAuthorized": False,
        }
        fixture["debianPackageIndexEvidence"] = [{
            **evidence, "installedVersionCandidates": candidate, "cachedArchiveEvidence": archive}]
        self.assertTrue(RENDERER.render(fixture).startswith(b"%PDF-"))
        for tamper in [
            {"publisherAuthenticated": True}, {"installedPackageOriginVerified": True},
            {"remediationAuthorized": True}, {"candidateArchives": 0},
            {"matchedArchives": 2}, {"verifiedArchiveSha256": ["../secret"]},
            {"scope": "trusted-installed-archive"}, {"status": "installed-origin-verified"},
        ]:
            fixture["debianPackageIndexEvidence"] = [{
                **evidence, "installedVersionCandidates": candidate,
                "cachedArchiveEvidence": {**archive, **tamper}}]
            with self.subTest(archive=tamper), self.assertRaises(ValueError):
                RENDERER.render(fixture)
        for update in [
            {"publisherAuthenticated": True},
            {"keyringIndependentlyAuthenticated": True},
            {"publisherFreshnessVerified": True},
            {"installedPackageOriginVerified": True},
            {"remediationAuthorized": True},
            {"verifiedAgainstLocallySignedRelease": False},
            {"candidateIndexes": -1},
            {"indexRecords": [{**evidence["indexRecords"][0], "packagesSha256": "../secret"}]},
            {"indexRecords": [{**evidence["indexRecords"][0], "suite": "trixie/../../"}]},
        ]:
            with self.subTest(update=update):
                fixture["debianPackageIndexEvidence"] = [{**evidence, **update}]
                with self.assertRaises(ValueError):
                    RENDERER.render(fixture)
        fixture["debianPackageIndexEvidence"] = [evidence, evidence]
        with self.assertRaises(ValueError):
            RENDERER.render(fixture)
        fixture["debianPackageIndexEvidence"] = [evidence]
        fixture["debianPackageIndexEvidenceSha256"] = "not-a-digest"
        with self.assertRaises(ValueError):
            RENDERER.render(fixture)

    def test_signed_release_pdf_rejects_untrusted_keyring_upgrades(self):
        fixture = identity_fixture()
        observation = {
            "schemaVersion": 1,
            "sourceReportId": "debian-native-packages",
            "sourceReportSha256": "a" * 64,
            "status": "verified_with_local_keyring",
            "candidateFiles": 1, "validLocalSignatures": 1, "invalidOrUnverifiable": 0,
            "localSignatureVerified": True,
            "signerFingerprints": ["b" * 40],
            "inReleaseSha256": ["c" * 64],
            "localKeyringSha256": "d" * 64,
            "signedReleases": ["bookworm"],
            "publisherAuthenticated": False, "publisherFreshnessVerified": False,
            "packageIndexHashesVerified": False, "installedPackageOriginVerified": False,
            "remediationAuthorized": False,
            "provenanceScope": "cached-inrelease-gpgv-installed-archive-keyring-only",
        }
        fixture["debianSignedReleaseEvidence"] = [observation]
        fixture["debianSignedReleaseEvidenceSha256"] = "f" * 64
        self.assertTrue(RENDERER.render(fixture).startswith(b"%PDF-"))
        for extra in [
            {"publisherAuthenticated": True},
            {"publisherFreshnessVerified": True},
            {"packageIndexHashesVerified": True},
            {"installedPackageOriginVerified": True},
            {"remediationAuthorized": True},
            {"signerFingerprints": ["../secrets"]},
            {"localKeyringSha256": "unsigned"},
        ]:
            with self.subTest(extra=extra):
                fixture["debianSignedReleaseEvidence"] = [dict(observation, **extra)]
                with self.assertRaises(ValueError):
                    RENDERER.render(fixture)
        fixture["debianSignedReleaseEvidence"] = [observation, observation]
        with self.assertRaises(ValueError):
            RENDERER.render(fixture)

    def test_apt_repository_pdf_rejects_signature_claims_and_duplicate_source_ids(self):
        fixture = identity_fixture()
        item = {
            "schemaVersion": 1, "sourceReportId": "debian-packages-run",
            "sourceReportSha256": "a" * 64, "state": "observed",
            "provenanceScope": "configured-apt-indexes-only",
            "indexEntries": 2, "debianLabelEntries": 2, "otherLabelEntries": 0,
            "suites": ["bookworm", "bookworm-security"], "suiteConsistent": True,
            "policySha256": "b" * 64, "releaseCodename": "bookworm",
            "publisherAuthenticated": False, "repositorySignatureVerified": False,
            "installedPackageOriginVerified": False,
        }
        fixture["debianAptIndexEvidence"] = [item]
        fixture["debianAptIndexEvidenceSha256"] = "c" * 64
        self.assertTrue(RENDERER.render(fixture).startswith(b"%PDF-"))
        for fields in [
            {"publisherAuthenticated": True},
            {"repositorySignatureVerified": True},
            {"installedPackageOriginVerified": True},
            {"policySha256": "../../private"},
            {"suites": ["https://credentials.invalid"]},
        ]:
            with self.subTest(fields=fields):
                fixture["debianAptIndexEvidence"] = [dict(item, **fields)]
                with self.assertRaises(ValueError):
                    RENDERER.render(fixture)
        fixture["debianAptIndexEvidence"] = [item, item]
        with self.assertRaises(ValueError):
            RENDERER.render(fixture)
        fixture["debianAptIndexEvidence"] = [item]
        fixture["debianAptIndexEvidenceSha256"] = "invalid"
        with self.assertRaises(ValueError):
            RENDERER.render(fixture)

    def test_debian_pdf_rejects_false_trust_duplicate_finding_and_missing_digest(self):
        fixture = identity_fixture()
        base = {
            'schemaVersion': 1, 'sourceReportId': 'original-debian-report',
            'findingId': 'trivy_CVE-2024-6119_one',
            'sourceReportSha256': 'a' * 64, 'fullSnapshotSha256': 'b' * 64,
            'derivedExcerptSha256': 'c' * 64,
            'candidateStatus': 'provisional', 'candidateVerdict': 'affected',
            'trustedVerdict': 'unknown', 'publisherAuthenticated': False,
            'publisherFreshnessVerified': False, 'remediationAuthorized': False,
            'conflictingWithTrivy': False,
        }
        fixture['debianTrackerEvidence'] = [base]
        fixture['debianTrackerEvidenceSha256'] = 'd' * 64
        cases = [
            dict(base, publisherAuthenticated=True),
            dict(base, publisherFreshnessVerified=True),
            dict(base, remediationAuthorized=True),
            dict(base, trustedVerdict='fixed_or_not_affected'),
            dict(base, derivedExcerptSha256='unsafe'),
            dict(base, candidateStatus='unavailable', candidateVerdict='affected'),
        ]
        for invalid in cases:
            with self.subTest(invalid=invalid):
                fixture['debianTrackerEvidence'] = [invalid]
                with self.assertRaises(ValueError):
                    RENDERER.render(fixture)
        fixture['debianTrackerEvidence'] = [base, base]
        with self.assertRaisesRegex(ValueError, 'Повторяющийся'):
            RENDERER.render(fixture)
        fixture['debianTrackerEvidence'] = [base]
        fixture['debianTrackerEvidenceSha256'] = 'broken'
        with self.assertRaisesRegex(ValueError, 'контрольная сумма'):
            RENDERER.render(fixture)


if __name__ == '__main__':
    unittest.main()
