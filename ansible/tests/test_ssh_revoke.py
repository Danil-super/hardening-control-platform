"""Controller-boundary tests. No SSH or target file mutation takes place."""
import contextlib
import importlib.util
import io
import json
import socket
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hcp_revoke', Path(__file__).parents[1] / 'scripts/hcp-ssh-revoke.py')
revoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(revoke)


class Channel:
    def shutdown_write(self): pass
    def recv_exit_status(self): return 1


class Stream(io.BytesIO):
    channel = Channel()


class BadHostKeyException(Exception): pass
class AuthenticationException(Exception): pass


class RevokePartialResultTests(unittest.TestCase):
    def result(self, remote=None, connect_error=None, command_error=None):
        class Client:
            def exec_command(self, *args, **kwargs):
                if command_error is not None:
                    raise command_error
                stdin = io.StringIO()
                stdin.channel = Channel()
                return stdin, Stream(json.dumps(remote).encode()), Stream(b'')
            def close(self): pass
        config = {'credentialId': 'a' * 64, 'user': 'fixture', 'publicKey': 'ssh-ed25519 Zml4dHVyZQ=='}
        fake_paramiko = types.SimpleNamespace(BadHostKeyException=BadHostKeyException, AuthenticationException=AuthenticationException)
        output = io.StringIO()
        with patch.object(revoke, 'connect', return_value=Client(), side_effect=connect_error), \
             patch.object(sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(json.dumps(config).encode()))), \
             patch.dict(sys.modules, {'paramiko': fake_paramiko}), contextlib.redirect_stdout(output):
            self.assertEqual(revoke.main(), 1)
        return json.loads(output.getvalue())

    def test_known_partial_revocation_survives_helper_json_boundary(self):
        self.assertEqual(self.result({'ok': False, 'error': 'unsafe_sudo_rule', 'keyRemoved': True}),
                         {'ok': False, 'error': 'unsafe_sudo_rule', 'keyRemoved': True})

    def test_known_no_change_is_preserved_but_unknown_is_not_fabricated(self):
        self.assertIs(self.result({'ok': False, 'error': 'revocation_failed', 'keyRemoved': False})['keyRemoved'], False)
        self.assertNotIn('keyRemoved', self.result({'ok': False, 'error': 'revocation_failed'}))
        self.assertNotIn('keyRemoved', self.result({'ok': False, 'error': 'revocation_failed', 'keyRemoved': 'true'}))

    def test_pre_dispatch_failures_prove_no_key_removal_but_post_dispatch_timeout_does_not(self):
        for error, code in ((revoke.RevokeError('host_not_trusted'), 'host_not_trusted'),
                            (BadHostKeyException(), 'host_key_changed'),
                            (AuthenticationException(), 'key_auth_failed'),
                            (socket.timeout(), 'ssh_timeout'),
                            (FileNotFoundError(), 'host_not_trusted'),
                            (ConnectionError(), 'revocation_failed')):
            with self.subTest(code=code):
                self.assertEqual(self.result(connect_error=error), {'ok': False, 'error': code, 'keyRemoved': False})
        self.assertEqual(self.result(command_error=socket.timeout()), {'ok': False, 'error': 'ssh_timeout'})

    def test_missing_dependency_did_not_dispatch_a_remote_command(self):
        output = io.StringIO()
        with patch.dict(sys.modules, {'paramiko': None}), contextlib.redirect_stdout(output):
            self.assertEqual(revoke.main(), 1)
        self.assertEqual(json.loads(output.getvalue()), {'ok': False, 'error': 'ssh_dependency_missing', 'keyRemoved': False})
