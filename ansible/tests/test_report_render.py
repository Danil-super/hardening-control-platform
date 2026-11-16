"""The controller's PDF/HTML budget must survive exec and process failure."""

import importlib.util
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'hcp-report-render.py'
SPEC = importlib.util.spec_from_file_location('hcp_report_render', SCRIPT)
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)


class ReportRenderTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)

    def holder(self, mode):
        # Exec the same fixed prlimit used by production; no wrapper stays alive.
        program = '''
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('render', sys.argv[1])
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
fds = module.acquire(sys.argv[2], sys.argv[3])
os.execv('/usr/bin/prlimit', ['/usr/bin/prlimit', '--as=1073741824', '--', sys.executable, '-c',
    'import sys; print("READY", flush=True); sys.stdin.buffer.read()'])
'''
        child = subprocess.Popen([sys.executable, '-c', program, str(SCRIPT), mode, str(self.state)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def stop():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
        self.addCleanup(stop)
        self.assertTrue(select.select([child.stdout], [], [], 5)[0], 'holder did not start')
        self.assertEqual(child.stdout.readline(), b'READY\n')
        return child

    def attempt(self, mode, state=None):
        args = ['pdf'] if mode == 'pdf' else [mode, '/private/original.xml']
        return subprocess.run([sys.executable, str(SCRIPT), *args], input=b'', capture_output=True,
                              env={**os.environ, 'HCP_STATE_DIR': str(state or self.state)}, timeout=5)

    def release(self, child):
        child.kill()
        child.communicate(timeout=5)

    def assert_busy(self, mode):
        result = self.attempt(mode)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(str(self.state).encode(), result.stderr)

    def test_two_pdf_processes_exclude_a_third_and_html_until_exit(self):
        first = self.holder('pdf')
        second = self.holder('pdf')
        self.assert_busy('pdf')
        self.assert_busy('oval')
        self.assert_busy('xccdf')
        self.release(first)
        third = self.holder('pdf')
        self.release(second)
        self.assert_busy('oval')
        self.release(third)
        html = self.holder('oval')
        self.assert_busy('pdf')
        self.release(html)
        self.holder('pdf')

    def test_html_excludes_all_other_generators_across_exec_and_sigkill(self):
        html = self.holder('xccdf')
        for mode in ('pdf', 'oval', 'xccdf'):
            self.assert_busy(mode)
        self.release(html)
        self.holder('oval')

    def test_failed_admission_does_not_leave_a_shared_lock(self):
        first, second = self.holder('pdf'), self.holder('pdf')
        for _ in range(3):
            self.assert_busy('pdf')
        self.release(first)
        self.release(second)
        self.holder('xccdf')

    def test_only_fixed_commands_and_resource_limits_are_allowed(self):
        pdf = RENDER.command(['pdf'])
        self.assertEqual(pdf, ['/usr/bin/prlimit', '--as=1073741824', '--cpu=115', '--fsize=12582912', '--',
                               '/usr/bin/python3', str(SCRIPT.with_name('hcp-final-report-pdf.py'))])
        for mode in ('oval', 'xccdf'):
            command = RENDER.command([mode, '/private/original.xml'])
            self.assertEqual(command[:9], ['/usr/bin/prlimit', '--as=1610612736', '--cpu=90', '--fsize=268435456', '--',
                                          '/usr/bin/oscap', mode, 'generate', 'report'])
            self.assertEqual(command[9:], (['--oval-template', '', '--sce-template', ''] if mode == 'xccdf' else []) + ['/private/original.xml'])
        for args in ([], ['sh'], ['pdf', '/tmp/other.py'], ['oval'], ['xccdf', '--help'], ['oval', '/tmp/a', 'extra']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                RENDER.command(args)

    def test_exec_failure_releases_all_locks_and_never_exposes_diagnostics(self):
        with patch.dict(os.environ, HCP_STATE_DIR=str(self.state)), patch.object(sys, 'argv', [str(SCRIPT), 'pdf']), \
                patch.object(RENDER.os, 'execv', side_effect=OSError('PRIVATE_PATH')), patch('sys.stderr') as stderr:
            self.assertEqual(RENDER.main(), 70)
            self.assertNotIn('PRIVATE_PATH', str(stderr.write.call_args_list))
        self.holder('xccdf')

    def test_invalid_cli_never_creates_state_or_runs_an_external_command(self):
        state = self.state / 'not-created'
        result = subprocess.run([sys.executable, str(SCRIPT), 'pdf', '/tmp/other.py'], capture_output=True,
                                env={**os.environ, 'HCP_STATE_DIR': str(state)}, timeout=5)
        self.assertEqual(result.returncode, 70)
        self.assertEqual(result.stdout, b'')
        self.assertFalse(state.exists())

    def test_lock_paths_reject_symlinks_nonregular_and_public_files_without_hanging(self):
        locks = self.state / 'render-locks'
        external = self.state / 'external'
        external.mkdir(mode=0o700)
        locks.symlink_to(external, target_is_directory=True)
        self.assertEqual(self.attempt('pdf').returncode, 70)
        locks.unlink()
        locks.mkdir(mode=0o700)
        gate = locks / 'gate.lock'
        victim = self.state / 'victim'
        victim.write_bytes(b'unchanged')
        gate.symlink_to(victim)
        self.assertEqual(self.attempt('pdf').returncode, 70)
        self.assertEqual(victim.read_bytes(), b'unchanged')
        gate.unlink()
        os.mkfifo(gate, 0o600)
        self.assertEqual(self.attempt('pdf').returncode, 70)
        gate.unlink()
        gate.write_bytes(b'')
        gate.chmod(0o644)
        self.assertEqual(self.attempt('pdf').returncode, 70)
        gate.chmod(0o600)
        link = self.state / 'linked-gate'
        os.link(gate, link)
        self.assertEqual(self.attempt('pdf').returncode, 70)
        link.unlink()
        locks.chmod(0o755)
        self.assertEqual(self.attempt('pdf').returncode, 70)


if __name__ == '__main__':
    unittest.main()
