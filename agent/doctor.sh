#!/usr/bin/env bash
set -euo pipefail

PROFILE="${PROFILE:-basic_linux}"
BRIDGE_URL="${HCP_AGENT_URL:-http://127.0.0.1:8765}"

usage() {
  cat <<'EOF'
Hardening Control Platform agent diagnostics

Usage:
  ./doctor.sh [options]

Options:
  --profile ID   Audit profile for local test, default: basic_linux
  --url URL      Bridge URL, default: http://127.0.0.1:8765
  -h, --help     Show this help

The script checks local files, Python syntax, one audit run and bridge health.
It does not change OS configuration.
EOF
}

log() {
  printf '[hcp-agent-doctor] %s\n' "$1"
}

warn() {
  printf '[hcp-agent-doctor] warning: %s\n' "$1" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:?Missing value for --profile}"
      shift 2
      ;;
    --url)
      BRIDGE_URL="${2:?Missing value for --url}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "Checking python3"
command -v python3 >/dev/null
python3 --version

log "Checking agent files"
test -f "${SCRIPT_DIR}/agent.py"
test -f "${SCRIPT_DIR}/server.py"

log "Checking Python syntax"
python3 -m py_compile "${SCRIPT_DIR}/agent.py" "${SCRIPT_DIR}/server.py"
rm -rf "${SCRIPT_DIR}/__pycache__"

log "Running audit test for profile ${PROFILE}"
python3 "${SCRIPT_DIR}/agent.py" audit --profile "$PROFILE" >/tmp/hcp-agent-doctor-report.json
python3 - <<'PY'
import json
from pathlib import Path

report = json.loads(Path("/tmp/hcp-agent-doctor-report.json").read_text(encoding="utf-8"))
required = {"auditId", "createdAt", "hostname", "os", "profileId", "summary", "findings"}
missing = sorted(required - set(report))
if missing:
    raise SystemExit(f"Missing report fields: {', '.join(missing)}")
if not isinstance(report["findings"], list):
    raise SystemExit("Report field findings must be a list")
summary = report["summary"]
print(
    f"report_ok profile={report['profileId']} score={summary.get('score')} "
    f"findings={len(report['findings'])}"
)
PY

log "Checking bridge health at ${BRIDGE_URL}/health"
if command -v curl >/dev/null; then
  if curl --silent --show-error --fail --max-time 3 "${BRIDGE_URL%/}/health" >/tmp/hcp-agent-doctor-health.json; then
    cat /tmp/hcp-agent-doctor-health.json
    printf '\n'
  else
    warn "Bridge is not reachable. Start it with: python3 server.py"
  fi
else
  warn "curl not found, skipping bridge health check"
fi

log "Done."
