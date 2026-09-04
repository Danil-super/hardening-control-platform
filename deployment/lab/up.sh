#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"
mkdir -p .lab

if [ ! -f .lab/hcp-lab ]; then
  ssh-keygen -q -t ed25519 -N "" -f .lab/hcp-lab -C hcp-lab
fi

export HCP_LAB_PUBLIC_KEY="$(cat .lab/hcp-lab.pub)"
: > .lab/known_hosts
docker compose -f deployment/lab/docker-compose.yml up --build -d lab-target

attempt=0
while :; do
  if ssh-keyscan -p 2222 127.0.0.1 > .lab/known_hosts.raw 2>/dev/null && [ -s .lab/known_hosts.raw ]; then
    sed 's/\[127\.0\.0\.1\]:2222/lab-target/' .lab/known_hosts.raw > .lab/known_hosts
    rm .lab/known_hosts.raw
    break
  fi
  rm -f .lab/known_hosts.raw
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 15 ]; then
    echo "Lab SSH target did not start." >&2
    exit 1
  fi
  sleep 1
done

docker compose -f deployment/lab/docker-compose.yml up --build -d hcp
echo "Lab is ready: http://127.0.0.1:3001 (password: lab-only-password)"
