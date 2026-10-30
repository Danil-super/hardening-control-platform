"""Test-only transport: real filesystem xattrs without requiring an SELinux host.

Only the two names are translated. The production parser, archive, manifests,
read-back verification, inode replacement and process restart stay unchanged.
This is not a substitute for native enforcing SELinux acceptance.
"""
import contextlib
from unittest.mock import patch


@contextlib.contextmanager
def translated_xattrs(module):
    names = {"security.PDPL": "user.hcp-test-pdpl", "security.selinux": "user.hcp-test-selinux"}
    reverse = {value: name for name, value in names.items()}
    original = {name: getattr(module.os, name) for name in ("getxattr", "setxattr", "removexattr", "listxattr")}

    def get(path, name, **kwargs):
        return original["getxattr"](path, names.get(name, name), **kwargs)

    def set_value(path, name, value, **kwargs):
        return original["setxattr"](path, names.get(name, name), value, **kwargs)

    def remove(path, name, **kwargs):
        return original["removexattr"](path, names.get(name, name), **kwargs)

    def list_values(path, **kwargs):
        return [reverse.get(name, name) for name in original["listxattr"](path, **kwargs)]

    with patch.object(module.os, "getxattr", side_effect=get), patch.object(module.os, "setxattr", side_effect=set_value), patch.object(module.os, "removexattr", side_effect=remove), patch.object(module.os, "listxattr", side_effect=list_values):
        yield
