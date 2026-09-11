#!/usr/bin/env python3
"""Actual OpenSCAP package predicates against the runner; synthetic source only.

Only the HCP host identity reader is substituted so an ordinary disposable Linux
runner can exercise Astra routing. Package collection and OVAL evaluation are
real. This is not vendor database acceptance or an Astra release certification.
"""
import argparse
import hashlib
import importlib.util
import json
import http.server
import os
import ssl
import threading
import tempfile
from pathlib import Path
import subprocess
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('oval_adapter', ROOT / 'ansible/scripts/hcp-oval-audit.py')
OVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OVAL)


def content(timestamp):
    definitions = []
    for number, kind, test in ((1, 'vulnerability', 1), (2, 'vulnerability', 2),
                               (3, 'patch', 1), (4, 'inventory', 1), (5, 'compliance', 2)):
        definitions.append('''<definition id="oval:hcp.acceptance:def:{number}" version="1" class="{kind}">
          <metadata><title>Synthetic acceptance {kind} {number}</title>
          <affected family="unix"><platform>HCP synthetic fixture</platform></affected>
          <reference source="CVE" ref_id="CVE-2099-999999"/>
          <description>SYNTHETIC TEST ONLY. No vendor CVE claim. Check the installed bash package.</description></metadata>
          <criteria operator="AND"><criterion test_ref="oval:hcp.acceptance:tst:{test}" comment="Read installed bash package"/></criteria>
          </definition>'''.format(number=number, kind=kind, test=test))
    return '''<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
 xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
 xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
 <generator><oval:product_name>HCP synthetic acceptance fixture</oval:product_name>
 <oval:product_version>1</oval:product_version><oval:schema_version>5.11.1</oval:schema_version>
 <oval:timestamp>{timestamp}</oval:timestamp></generator>
 <definitions>{definitions}</definitions>
 <tests>
 <linux:dpkginfo_test id="oval:hcp.acceptance:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="Installed bash EVR is greater than zero">
 <linux:object object_ref="oval:hcp.acceptance:obj:1"/><linux:state state_ref="oval:hcp.acceptance:ste:1"/></linux:dpkginfo_test>
 <linux:dpkginfo_test id="oval:hcp.acceptance:tst:2" version="1" check="all" check_existence="at_least_one_exists" comment="Installed bash EVR is exactly zero">
 <linux:object object_ref="oval:hcp.acceptance:obj:1"/><linux:state state_ref="oval:hcp.acceptance:ste:2"/></linux:dpkginfo_test>
 </tests>
 <objects><linux:dpkginfo_object id="oval:hcp.acceptance:obj:1" version="1"><linux:name>bash</linux:name></linux:dpkginfo_object></objects>
 <states>
 <linux:dpkginfo_state id="oval:hcp.acceptance:ste:1" version="1"><linux:evr datatype="debian_evr_string" operation="greater than">0:0</linux:evr></linux:dpkginfo_state>
 <linux:dpkginfo_state id="oval:hcp.acceptance:ste:2" version="1"><linux:evr datatype="debian_evr_string" operation="equals">0:0</linux:evr></linux:dpkginfo_state>
 </states>
</oval_definitions>
'''.format(timestamp=timestamp, definitions=''.join(definitions)).encode()


def execute(argv, expected=(0,)):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    if result.returncode not in expected:
        raise RuntimeError('Command failed: ' + repr(argv) + '\n' + result.stdout + '\n' + result.stderr)
    return result


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def verify_https_download(source, output):
    """Local trusted TLS mirror: exercise the actual downloader, no public API."""
    with tempfile.TemporaryDirectory(prefix='hcp-oval-tls-') as directory:
        root = Path(directory)
        cert, key = root / 'cert.pem', root / 'key.pem'
        execute(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                 '-keyout', str(key), '-out', str(cert)])
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', 'https://127.0.0.1:' + str(self.server.server_port) + '/database.xml')
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/xml')
                    self.send_header('Content-Length', str(len(source)))
                    self.end_headers()
                    self.wfile.write(source)
            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        configuration = OVAL.parse_config({'mode': 'online', 'url': 'https://localhost:' + str(server.server_port) + '/database.xml',
            'sha256': hashlib.sha256(source).hexdigest(), 'releasePattern': '*'})
        try:
            with patch.dict(os.environ, {'SSL_CERT_FILE': str(cert), 'NO_PROXY': 'localhost,127.0.0.1', 'no_proxy': 'localhost,127.0.0.1'}):
                downloaded = OVAL.prepare(configuration, str(root / 'download.xml'))
                assert downloaded['ok'] and (root / 'download.xml').read_bytes() == source
                mismatched = dict(configuration, sha256='0' * 64)
                try:
                    OVAL.prepare(mismatched, str(root / 'mismatch.xml'))
                except ValueError as error:
                    assert 'SHA-256' in str(error)
                else:
                    raise AssertionError('Downloaded hash mismatch was accepted')
                assert not (root / 'mismatch.xml').exists()
                redirected = dict(configuration, url=configuration['url'].replace('/database.xml', '/redirect'))
                try:
                    OVAL.prepare(redirected, str(root / 'redirect.xml'))
                except ValueError:
                    pass
                else:
                    raise AssertionError('Cross-origin redirect was accepted')
                assert not (root / 'redirect.xml').exists()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    result = {'actualLocalTrustedHttpsDownload': True, 'hashMismatchRejected': True,
              'crossOriginRedirectRejected': True, 'publicNetworkUsed': False}
    save(output / 'https-download-evidence.json', result)
    return result


def verify_playbook(output):
    """Actual copy/evaluate/fetch/cleanup with the runner's real non-Astra ID."""
    before = set(Path('/tmp').glob('hcp-astra-oval-*'))
    inventory = output / 'inventory.ini'
    inventory.write_text('[linux_hosts]\nnon-astra-runner ansible_connection=local ansible_python_interpreter=/usr/bin/python3\n')
    settings = {'report_run_id': 'run-oval-acceptance', 'hcp_reports_dir': str(output / 'playbook-reports'),
                'hcp_oval_config': {'mode': 'local', 'path': '/usr/share/oval/db.xml', 'releasePattern': '*'}}
    result = execute(['ansible-playbook', '-i', str(inventory), str(ROOT / 'ansible/playbooks/astra-oval-audit.yml'),
                      '-e', json.dumps(settings)])
    (output / 'playbook-stdout.txt').write_text(result.stdout)
    (output / 'playbook-stderr.txt').write_text(result.stderr)
    report = json.loads((output / 'playbook-reports/non-astra-runner-astra-oval-run-oval-acceptance.json').read_text())
    assert report['scanner']['partial'] and not report['scanner']['evaluationPerformed']
    assert report['scanner']['hostIdentity']['id'] != 'astra'
    assert report['scanner']['uniqueCveCount'] is None
    assert set(Path('/tmp').glob('hcp-astra-oval-*')) == before, 'Target temporary files remain'
    result = {'productionPlaybookExecuted': True, 'nonAstraRejected': True, 'reportFetched': True, 'targetCleanup': True}
    save(output / 'playbook-evidence.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    actual_os = Path('/etc/os-release').read_text()
    version = execute(['oscap', '--version']).stdout
    package_version = execute(['dpkg-query', '-W', '-f=${Version}', 'bash']).stdout
    source = content(OVAL.now().strftime('%Y-%m-%dT%H:%M:%SZ'))
    source_path = output / 'synthetic-oval.xml'
    source_path.write_bytes(source)
    execute(['oscap', 'oval', 'validate', str(source_path)])
    native = execute(['oscap', 'oval', 'eval', '--results', str(output / 'native-results.xml'), str(source_path)], expected=(0, 2))
    (output / 'native-stdout.txt').write_text(native.stdout)
    (output / 'native-stderr.txt').write_text(native.stderr)
    config = {'mode': 'local', 'path': str(source_path), 'sha256': hashlib.sha256(source).hexdigest(),
              'releasePattern': '*', 'architectures': [], 'maxAgeDays': 30}
    reports = []
    # Distinct family identifiers exercise routing, not OS compatibility claims.
    for release in ('1.6.7.15', '1.7.6', '1.8', '12.4-custom'):
        options = argparse.Namespace(config=json.dumps(config), input='', inventory_host='synthetic-runner', run_id='fixture-' + release)
        with patch.object(OVAL, 'host_identity', return_value={'id': 'astra', 'astraVersion': release,
                         'architecture': 'x86_64', 'prettyName': 'Synthetic identity; actual OS in provenance.json'}):
            report = OVAL.evaluate(options)
        save(output / ('report-' + release + '.json'), report)
        scanner = report['scanner']
        assert scanner['evaluationPerformed'], scanner
        assert not scanner['partial'], scanner['partialReasons']
        assert scanner['definitionCount'] == scanner['evaluatedDefinitionCount'] == 5
        assert scanner['resultCounts'] == {'true': 3, 'false': 2}, scanner['resultCounts']
        assert scanner['uniqueCveCount'] == 1 and scanner['cveIds'] == ['CVE-2099-999999']
        assert scanner['fullCveCoverage'] is False
        assert scanner['database']['vendorSignature'] == 'not_checked'
        assert any(item['values'].get('name') == 'bash' and item['values'].get('version') for item in scanner['packageItems'])
        failed = [finding for finding in report['findings'] if finding['status'] == 'failed']
        assert len(failed) == 1 and failed[0]['id'] == 'oval:hcp.acceptance:def:1', failed
        assert failed[0]['vulnerability']['cvss'] is None
        reports.append({'declaredIdentityFixture': release, 'definitionCount': scanner['definitionCount'],
                        'nativePackageProbe': 'bash', 'uniqueSyntheticCveCount': scanner['uniqueCveCount']})
    source_path.write_bytes(source + b'\n')
    with patch.object(OVAL, 'host_identity', return_value={'id': 'astra', 'astraVersion': '1.7.6', 'architecture': 'x86_64'}):
        rejected = OVAL.evaluate(options)
    save(output / 'hash-mismatch-report.json', rejected)
    assert rejected['scanner']['partial'] and not rejected['scanner']['evaluationPerformed']
    assert rejected['scanner']['uniqueCveCount'] is None
    source_path.write_bytes(source)
    download_evidence = verify_https_download(source, output)
    playbook_evidence = verify_playbook(output)
    save(output / 'provenance.json', {'scope': 'Real OpenSCAP + dpkg predicates; synthetic OVAL, substituted identity only',
        'vendorDatabaseVerified': False, 'astraReleaseVerified': False, 'actualOsRelease': actual_os,
        'oscapVersion': version, 'bashVersion': package_version, 'sourceSha256': config['sha256'], 'checks': reports,
        'hashMismatchRejected': True, 'httpsDownload': download_evidence, 'productionPlaybook': playbook_evidence})
    print(json.dumps({'ok': True, 'checks': reports, 'vendorDatabaseVerified': False, 'astraReleaseVerified': False}, indent=2))


if __name__ == '__main__':
    main()
