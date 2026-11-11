"""Real Ansible SSH prompt negotiation with a delayed, local-only transport fixture."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SSH_FIXTURE = r'''#!/usr/bin/env python3
import json, os, re, sys, time
command = sys.argv[-1]
prompt = re.search(r'\[sudo via ansible, key=[^\]]+\] password:', command)
success = re.search(r'BECOME-SUCCESS-[a-z]+', command)
if prompt and success:
    time.sleep(float(os.environ['HCP_FIXTURE_SUDO_DELAY']))
    try:
        sys.stdout.write(prompt.group()); sys.stdout.flush()
        assert sys.stdin.buffer.readline().strip() == b'fixture-only'
        print(success.group(), flush=True)
        sys.stdin.buffer.read()
        print(json.dumps({'ping': 'pong', 'changed': False}), flush=True)
    except BrokenPipeError:
        pass
else:
    print('/tmp')
'''


@unittest.skipUnless(shutil.which('ansible-playbook'), 'requires real ansible-playbook')
class AnsiblePromptTimeoutTests(unittest.TestCase):
    def invoke(self, delay, timeout=None):
        with tempfile.TemporaryDirectory(prefix='hcp-sudo-timeout-') as directory:
            root = Path(directory)
            ssh = root / 'ssh'
            ssh.write_text(SSH_FIXTURE)
            ssh.chmod(0o700)
            inventory = root / 'inventory.ini'
            inventory.write_text(
                '[all]\nfixture ansible_host=127.0.0.1 ansible_user=fixture '
                'ansible_connection=ssh ansible_python_interpreter=/usr/bin/python3 '
                f'ansible_ssh_executable={ssh} ansible_ssh_pipelining=True '
                'ansible_become_password=fixture-only\n'
            )
            playbook = root / 'playbook.json'
            playbook.write_text(json.dumps([{
                'hosts': 'all', 'gather_facts': False, 'become': True,
                'tasks': [{'name': 'Wait for delayed sudo prompt', 'ansible.builtin.ping': {}}],
            }]))
            env = {key: value for key, value in os.environ.items() if not key.startswith('ANSIBLE_')}
            env.update(ANSIBLE_CONFIG=str(REPO / 'ansible.cfg'), ANSIBLE_LOCAL_TEMP=str(root / 'tmp'),
                       ANSIBLE_NOCOLOR='1', HCP_FIXTURE_SUDO_DELAY=str(delay))
            command = ['ansible-playbook', '-i', str(inventory), str(playbook)]
            if timeout is not None:
                command.extend(['--timeout', str(timeout)])
            return subprocess.run(command, cwd=REPO, env=env, capture_output=True, text=True, timeout=50)

    def test_default_allows_sudo_prompt_after_thirteen_seconds(self):
        result = self.invoke(delay=13)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r'ok=1\s+changed=0\s+unreachable=0\s+failed=0')

    def test_explicit_short_timeout_still_rejects_a_late_prompt(self):
        result = self.invoke(delay=5, timeout=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Timeout (3s) waiting for privilege escalation prompt', result.stdout + result.stderr)
