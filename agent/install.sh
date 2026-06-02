#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/hardening-control-platform/agent}"
SERVICE_NAME="${SERVICE_NAME:-hcp-agent-bridge}"
HOST="${HCP_AGENT_HOST:-127.0.0.1}"
PORT="${HCP_AGENT_PORT:-8765}"
ENABLE_SERVICE=0
START_SERVICE=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Hardening Control Platform agent installer

Usage:
  sudo ./install.sh [options]

Options:
  --install-dir PATH  Agent installation directory, default: /opt/hardening-control-platform/agent
  --service-name NAME systemd service name, default: hcp-agent-bridge
  --host HOST         Bridge listen host, default: 127.0.0.1
  --port PORT         Bridge listen port, default: 8765
  --enable            Enable service autostart
  --start             Start service after installation
  --dry-run           Print planned actions without writing files
  -h, --help          Show this help

The installed agent is audit-only. It does not change OS configuration.
EOF
}

log() {
  printf '[hcp-agent-install] %s\n' "$1"
}

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[dry-run] %q' "$1"
    shift
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
    return 0
  fi
  "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir)
      INSTALL_DIR="${2:?Missing value for --install-dir}"
      shift 2
      ;;
    --service-name)
      SERVICE_NAME="${2:?Missing value for --service-name}"
      shift 2
      ;;
    --host)
      HOST="${2:?Missing value for --host}"
      shift 2
      ;;
    --port)
      PORT="${2:?Missing value for --port}"
      shift 2
      ;;
    --enable)
      ENABLE_SERVICE=1
      shift
      ;;
    --start)
      START_SERVICE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
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

if [[ "$DRY_RUN" -eq 0 && "${EUID}" -ne 0 ]]; then
  echo "Run this script with sudo or use --dry-run to preview actions." >&2
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_TEMPLATE="${SOURCE_DIR}/systemd/hcp-agent-bridge.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ ! -f "${SOURCE_DIR}/agent.py" || ! -f "${SOURCE_DIR}/server.py" ]]; then
  echo "agent.py and server.py must be located next to install.sh." >&2
  exit 1
fi

if [[ ! -f "$SERVICE_TEMPLATE" ]]; then
  echo "Service template not found: $SERVICE_TEMPLATE" >&2
  exit 1
fi

log "Installing agent files to ${INSTALL_DIR}"
run install -d -m 0755 "$INSTALL_DIR"
run install -m 0644 "${SOURCE_DIR}/agent.py" "${INSTALL_DIR}/agent.py"
run install -m 0644 "${SOURCE_DIR}/server.py" "${INSTALL_DIR}/server.py"

log "Installing systemd service ${SERVICE_NAME}.service"
if [[ "$DRY_RUN" -eq 1 ]]; then
  log "Would render ${SERVICE_TEMPLATE} to ${SERVICE_PATH}"
else
  sed \
    -e "s#__INSTALL_DIR__#${INSTALL_DIR}#g" \
    -e "s#__HOST__#${HOST}#g" \
    -e "s#__PORT__#${PORT}#g" \
    "$SERVICE_TEMPLATE" > "$SERVICE_PATH"
  chmod 0644 "$SERVICE_PATH"
fi

run systemctl daemon-reload

if [[ "$ENABLE_SERVICE" -eq 1 ]]; then
  run systemctl enable "${SERVICE_NAME}.service"
fi

if [[ "$START_SERVICE" -eq 1 ]]; then
  run systemctl restart "${SERVICE_NAME}.service"
fi

log "Done."
log "Health check: curl http://${HOST}:${PORT}/health"
log "Manual start: sudo systemctl start ${SERVICE_NAME}.service"
log "Status: sudo systemctl status ${SERVICE_NAME}.service"
