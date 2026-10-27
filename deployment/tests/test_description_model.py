"""Exercise the model download against a local server with Argos' client policy."""
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.request
import zipfile


script = Path(__file__).resolve().parents[1] / 'install-description-model.py'
spec = importlib.util.spec_from_file_location('description_model', script)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


class DescriptionModelTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / 'fixture.argosmodel'
        with zipfile.ZipFile(self.archive, 'w') as archive:
            for name in model.FILES:
                data = json.dumps({'from_code': 'en', 'to_code': 'ru', 'package_version': '1.9'}) if name == 'metadata.json' else 'fixture weights, not a real translation model'
                archive.writestr(model.PREFIX + name, data)
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.destination = self.root / 'installed'

    @contextmanager
    def download(self, body=None):
        payload = self.archive.read_bytes() if body is None else body
        agents = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                agent = self.headers.get('User-Agent')
                agents.append(agent)
                if agent != 'ArgosTranslate':
                    self.send_error(403)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with patch.object(model, 'URL', f'http://127.0.0.1:{server.server_port}/model'), \
                 patch.object(model, 'SHA256', self.digest), \
                 patch.object(model.urllib.request, 'urlopen', opener.open), \
                 patch('sys.argv', [str(script), '--destination', str(self.destination)]):
                yield agents
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_download_identifies_as_argos_and_installs_verified_archive(self):
        with self.download() as agents:
            model.main()
        self.assertEqual(agents, ['ArgosTranslate'])
        self.assertEqual((self.destination / 'archive-sha256.txt').read_text(), self.digest + '\n')
        self.assertEqual(json.loads((self.destination / 'metadata.json').read_text())['to_code'], 'ru')
        self.assertTrue((self.destination / 'model/model.bin').is_file())

    def test_download_rejects_changed_bytes_before_installation(self):
        with self.download(self.archive.read_bytes() + b'changed'):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                model.main()
        self.assertFalse(self.destination.exists())

    def test_download_enforces_size_bound_before_installation(self):
        with self.download(), patch.object(model, 'MAX_ARCHIVE', self.archive.stat().st_size - 1):
            with self.assertRaisesRegex(ValueError, 'size limit'):
                model.main()
        self.assertFalse(self.destination.exists())


if __name__ == '__main__':
    unittest.main()
