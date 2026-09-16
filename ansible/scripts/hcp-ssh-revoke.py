#!/usr/bin/env python3
"""Revoke exactly one HCP per-host public key through a pinned SSH session.

The target host key is loaded only from HCP known_hosts.  This helper neither
accepts a password nor learns a server key from the network.
"""
from __future__ import print_function

import base64
import json
import logging
import os
import re
import shlex
import socket
import sys

logging.disable(logging.CRITICAL)


class RevokeError(Exception):
    def __init__(self, code):
        self.code = code
        Exception.__init__(self, code)


REMOTE_PROGRAM = r'''
import json, os, pwd, re, stat, sys, tempfile

def answer(value):
    sys.stdout.write(json.dumps(value, separators=(',', ':')))
    sys.stdout.flush()

def fail(code):
    answer({'ok': False, 'error': code})
    raise SystemExit(1)

try:
    value = json.load(sys.stdin)
    user = value.get('user')
    public_key = value.get('publicKey')
    if not isinstance(user, str) or not re.match(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$', user):
        fail('bad_identity')
    if not isinstance(public_key, str) or not re.match(r'^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?$', public_key):
        fail('bad_key')
    account = pwd.getpwnam(user)
    home = account.pw_dir
    ssh_directory = os.path.join(home, '.ssh')
    authorized = os.path.join(ssh_directory, 'authorized_keys')
    ssh_info = os.lstat(ssh_directory)
    if stat.S_ISLNK(ssh_info.st_mode) or not stat.S_ISDIR(ssh_info.st_mode):
        fail('unsafe_authorized_keys')
    key_info = os.lstat(authorized)
    if stat.S_ISLNK(key_info.st_mode) or not stat.S_ISREG(key_info.st_mode):
        fail('unsafe_authorized_keys')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(authorized, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail('unsafe_authorized_keys')
        raw = os.read(descriptor, min(before.st_size + 1, 4 * 1024 * 1024 + 1))
        if len(raw) > 4 * 1024 * 1024:
            fail('unsafe_authorized_keys')
        if os.fstat(descriptor).st_ino != before.st_ino:
            fail('unsafe_authorized_keys')
    finally:
        os.close(descriptor)
    try:
        content = raw.decode('utf-8')
    except UnicodeDecodeError:
        fail('unsafe_authorized_keys')
    expected = public_key.split()[:2]
    kept = []
    removed = False
    for line in content.splitlines(True):
        parts = line.strip().split()
        if len(parts) >= 2 and parts[:2] == expected:
            removed = True
            continue
        kept.append(line)
    if not removed:
        answer({'ok': False, 'error': 'key_not_present'})
        raise SystemExit(1)
    lock = os.path.join(ssh_directory, '.hcp-key-revoke-lock')
    try:
        os.mkdir(lock, 0o700)
    except OSError:
        fail('credential_busy')
    temporary = None
    try:
        # Refuse a replacement between read and write; a user-controlled
        # authorized_keys must not be redirected through a symlink.
        current = os.lstat(authorized)
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or current.st_ino != before.st_ino:
            fail('unsafe_authorized_keys')
        descriptor, temporary = tempfile.mkstemp(prefix='.hcp-authorized-', dir=ssh_directory)
        try:
            os.fchmod(descriptor, stat.S_IMODE(before.st_mode))
            os.fchown(descriptor, before.st_uid, before.st_gid)
            os.write(descriptor, ''.join(kept).encode('utf-8'))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, authorized)
        temporary = None
    finally:
        if temporary:
            try: os.unlink(temporary)
            except OSError: pass
        try: os.rmdir(lock)
        except OSError: pass
    answer({'ok': True, 'status': 'removed'})
except SystemExit:
    raise
except KeyError:
    fail('bad_identity')
except Exception:
    fail('revocation_failed')
'''


def connect(config):
    import paramiko
    client = paramiko.SSHClient()
    try:
        client.load_host_keys(config['knownHostsPath'])
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        pattern = config['address'] if config['port'] == 22 else '[%s]:%s' % (config['address'], config['port'])
        if not client.get_host_keys().lookup(pattern):
            raise RevokeError('host_not_trusted')
        client.connect(config['address'], port=config['port'], username=config['user'], key_filename=config['keyPath'],
                       allow_agent=False, look_for_keys=False, timeout=10, banner_timeout=10, auth_timeout=15)
        return client
    except Exception:
        client.close()
        raise


def revoke(config):
    encoded = base64.b64encode(REMOTE_PROGRAM.encode('utf-8')).decode('ascii')
    python = "import base64;exec(compile(base64.b64decode(%r), '<hcp-key-revoke>', 'exec'))" % encoded
    command = "if [ \"$(id -u)\" = 0 ]; then exec python3 -c %s; else exec sudo -n -- python3 -c %s; fi" % (shlex.quote(python), shlex.quote(python))
    client = connect(config)
    try:
        stdin, stdout, stderr = client.exec_command('/bin/sh -c ' + shlex.quote(command), timeout=30, get_pty=False)
        stdin.write(json.dumps({'user': config['user'], 'publicKey': config['publicKey']}) + '\n')
        stdin.flush()
        stdin.channel.shutdown_write()
        output = stdout.read(65536).decode('utf-8', 'replace')
        stderr.read(65536)
        status = stdout.channel.recv_exit_status()
        try:
            result = json.loads(output)
        except Exception:
            raise RevokeError('revocation_failed')
        if status or not result.get('ok') or result.get('status') != 'removed':
            code = result.get('error') if isinstance(result.get('error'), str) else 'revocation_failed'
            raise RevokeError(code)
        return {'ok': True, 'status': 'removed'}
    finally:
        client.close()


def main():
    try:
        import paramiko
    except ImportError:
        print(json.dumps({'ok': False, 'error': 'ssh_dependency_missing'}))
        return 1
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise RevokeError('bad_request')
        config = json.loads(raw.decode('utf-8'))
        if not isinstance(config, dict):
            raise RevokeError('bad_request')
        result = revoke(config)
    except RevokeError as error:
        result = {'ok': False, 'error': error.code}
    except paramiko.BadHostKeyException:
        result = {'ok': False, 'error': 'host_key_changed'}
    except paramiko.AuthenticationException:
        result = {'ok': False, 'error': 'key_auth_failed'}
    except (socket.timeout, TimeoutError):
        result = {'ok': False, 'error': 'ssh_timeout'}
    except FileNotFoundError:
        result = {'ok': False, 'error': 'host_not_trusted'}
    except Exception:
        result = {'ok': False, 'error': 'revocation_failed'}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())
