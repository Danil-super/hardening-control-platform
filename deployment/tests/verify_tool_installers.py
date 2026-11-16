"""Check all shipped pip copies, including their separately vendored libraries."""
import json
import re
import subprocess
import sys


PYTHONS = (
    "/usr/local/bin/python3.13",
    "/opt/hcp-tools/ansible-modern/bin/python",
    "/opt/hcp-tools/ssh-audit/bin/python",
    "/opt/hcp-tools/translation/bin/python",
)
# These floors cover the reviewed urllib3 and MessagePack advisories.
MINIMUM = {"pip": (26, 3), "urllib3": (2, 8, 0), "msgpack": (1, 2, 3)}
PROBE = """
import importlib.metadata, importlib.util, json
from pathlib import Path
p = Path(importlib.util.find_spec('pip').origin).parent
versions = dict(line.strip().split('==', 1) for line in
                (p / '_vendor' / 'vendor.txt').read_text().splitlines()
                if '==' in line)
print(json.dumps({'pip': importlib.metadata.version('pip'),
                  'urllib3': versions['urllib3'], 'msgpack': versions['msgpack']}))
"""


def main():
    results = []
    for python in PYTHONS:
        row = {"python": python, "errors": []}
        try:
            versions = json.loads(subprocess.check_output(
                [python, "-I", "-c", PROBE], text=True, timeout=30))
            row["versions"] = versions
            for package, minimum in MINIMUM.items():
                version = versions[package]
                if not re.fullmatch(r"\d+(?:\.\d+)+", version) or tuple(map(int, version.split("."))) < minimum:
                    row["errors"].append(f"{package}: unsupported version {version}")
            subprocess.run([python, "-I", "-m", "pip", "check"], check=True,
                           capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
            row["errors"].append(type(error).__name__)
        results.append(row)
    ok = not any(row["errors"] for row in results)
    print(json.dumps({"ok": ok, "installers": results}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
