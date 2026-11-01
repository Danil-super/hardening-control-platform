#!/usr/bin/env bash
set -euo pipefail

# This entry point changes only an owned disposable QEMU guest. The Python
# controller refuses non-GitHub-hosted runners and work outside RUNNER_TEMP.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/linux_rpm_vm_integration.py" "$@"
