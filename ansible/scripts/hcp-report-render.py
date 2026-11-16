#!/usr/bin/python3
"""Controller-only, shared PDF/HTML admission with locks held through exec."""

import errno
import fcntl
import os
from pathlib import Path
import stat
import sys


class Busy(Exception):
    pass


def command(args):
    if args == ['pdf']:
        return ['/usr/bin/prlimit', '--as=1073741824', '--cpu=115', '--fsize=12582912', '--',
                '/usr/bin/python3', str(Path(__file__).with_name('hcp-final-report-pdf.py'))]
    if len(args) == 2 and args[0] in ('oval', 'xccdf') and os.path.isabs(args[1]) and '\0' not in args[1]:
        # ARF embeds results; never discover and load adjacent companion XML.
        templates = ['--oval-template', '', '--sce-template', ''] if args[0] == 'xccdf' else []
        return ['/usr/bin/prlimit', '--as=1610612736', '--cpu=90', '--fsize=268435456', '--',
                '/usr/bin/oscap', args[0], 'generate', 'report', *templates, args[1]]
    raise ValueError('Unsupported renderer')


def lock(directory, name, operation):
    # Never unlink: every process must lock the same inode.
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise OSError('Unsafe lock file')
        try:
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                raise Busy() from None
            raise
        os.set_inheritable(fd, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def acquire(mode, state):
    if mode not in ('pdf', 'oval', 'xccdf'):
        raise ValueError('Unsupported renderer')
    os.makedirs(state, mode=0o700, exist_ok=True)
    root = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.mkdir('render-locks', mode=0o700, dir_fd=root)
        except FileExistsError:
            pass
        directory = os.open('render-locks', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    finally:
        os.close(root)
    fds = []
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise OSError('Unsafe lock directory')
        fds.append(lock(directory, 'gate.lock', fcntl.LOCK_SH if mode == 'pdf' else fcntl.LOCK_EX))
        if mode == 'pdf':
            for slot in range(2):
                try:
                    fds.append(lock(directory, f'pdf-{slot}.lock', fcntl.LOCK_EX))
                    break
                except Busy:
                    continue
            else:
                raise Busy()
        return fds
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise
    finally:
        os.close(directory)


def main():
    fds = []
    try:
        argv = command(sys.argv[1:])
        state = os.environ.get('HCP_STATE_DIR') or str(Path(__file__).resolve().parents[1])
        fds = acquire(sys.argv[1], state)
        os.execv(argv[0], argv)
    except Busy:
        print('Report rendering busy; retry later.', file=sys.stderr)
        return 75
    except (OSError, ValueError):
        print('Report renderer unavailable.', file=sys.stderr)
        return 70
    finally:
        for fd in fds:
            os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
