#!/usr/bin/env bash
# Reuse only the disposable lab's native binary/cache; keep acceptance state separate.
set -euo pipefail

hcp_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
hcp_output="${1:-${hcp_repo_root}/.lab/trivy-matching-acceptance}"
if [[ -e "${hcp_output}/protocol.json" ]]; then
  echo "Choose a new output directory; an earlier Trivy acceptance protocol exists." >&2
  exit 1
fi
mkdir -p "${hcp_output}"
compose=(docker compose -f "${hcp_repo_root}/deployment/lab/docker-compose.yml")
hcp_source="$("${compose[@]}" exec -T hcp mktemp -d /tmp/hcp-trivy-acceptance-source.XXXXXX)"
hcp_evidence="$("${compose[@]}" exec -T hcp mktemp -d /tmp/hcp-trivy-acceptance-evidence.XXXXXX)"

finish() {
  local status=$?
  trap - EXIT
  "${compose[@]}" cp "hcp:${hcp_evidence}/." "${hcp_output}" || status=1
  "${compose[@]}" exec -T hcp rm -rf -- "${hcp_source}" "${hcp_evidence}" || true
  exit "${status}"
}
trap finish EXIT

"${compose[@]}" exec -T hcp mkdir -p "${hcp_source}/web/tests"
"${compose[@]}" exec -T hcp ln -s /app/web/node_modules "${hcp_source}/web/node_modules"
"${compose[@]}" cp "${hcp_repo_root}/web/lib" "hcp:${hcp_source}/web/"
"${compose[@]}" cp "${hcp_repo_root}/web/tests/_typescript-loader.mjs" "hcp:${hcp_source}/web/tests/"
"${compose[@]}" cp "${hcp_repo_root}/deployment/tests/verify_trivy_matching.mjs" "hcp:${hcp_source}/verify_trivy_matching.mjs"
"${compose[@]}" exec -T hcp node "${hcp_source}/verify_trivy_matching.mjs" \
  --web-dir "${hcp_source}/web" --cache-dir /var/lib/hcp/trivy-cache --output "${hcp_evidence}"
