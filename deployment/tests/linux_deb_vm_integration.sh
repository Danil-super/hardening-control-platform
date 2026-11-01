#!/usr/bin/env bash
set -euo pipefail

# Only the owned disposable KVM guest receives firewall/service changes. The
# controller refuses non-GitHub-hosted runners and pre-existing work paths.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/linux_deb_vm_integration.py" "$@"
