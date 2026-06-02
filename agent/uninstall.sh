#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/hardening-control-platform/agent}"
SERVICE_NAME="${SERVICE_NAME:-hcp-agent-bridge}"
REMOVE_FILES=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Hardening Control Platform agent uninstaller

Usage:
  sudo ./uninstall.sh [options]

Options:
  --service-name NAME systemd service name, default: hcp-agent-bridge
  --install-dir PATH  Agent installation directory, default: /opt/hardening-control-platform/agent
  --remove-files      Remove installed agent files from install directory
  --dry-run           Print planned actions without changing the system
  -h, --help          Show this help

By default the script stops/disables the service and removes the unit file.
Installed files are removed only with --remove-files.
EOF
}

log() {
  printf '[hcp-agent-uninstall] %s\n' "$1"
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
    --service-name)
      SERVICE_NAME="${2:?Missing value for --service-name}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:?Missing value for --install-dir}"
      shift 2
      ;;
    --remove-files)
      REMOVE_FILES=1
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

SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

log "Stopping ${SERVICE_NAME}.service if it exists"
if [[ "$DRY_RUN" -eq 1 ]]; then
  run systemctl stop "${SERVICE_NAME}.service"
else
  systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
fi

log "Disabling ${SERVICE_NAME}.service if it is enabled"
if [[ "$DRY_RUN" -eq 1 ]]; then
  run systemctl disable "${SERVICE_NAME}.service"
else
  systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  log "Would remove ${SERVICE_PATH}"
else
  rm -f "$SERVICE_PATH"
fi

run systemctl daemon-reload

if [[ "$REMOVE_FILES" -eq 1 ]]; then
  log "Removing installed files from ${INSTALL_DIR}"
  run rm -rf "$INSTALL_DIR"
else
  log "Keeping installed files in ${INSTALL_DIR}. Use --remove-files to delete them."
fi

log "Done."
