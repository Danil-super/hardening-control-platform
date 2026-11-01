#!/bin/sh
set -eu
umask 077

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"
mkdir -p .lab

if [ ! -f .lab/hcp-lab ]; then
  ssh-keygen -q -t ed25519 -N "" -f .lab/hcp-lab -C hcp-lab
fi

if [ ! -f .lab/hcp-lab.pub ]; then
  ssh-keygen -y -P '' -f .lab/hcp-lab > .lab/hcp-lab.pub
fi
touch .lab/known_hosts
docker compose -f deployment/lab/docker-compose.yml up --build -d lab-target lab-scheduled-target

: > .lab/known_hosts.next
for lab_service in lab-target lab-scheduled-target; do
  attempt=0
  while :; do
    # Trust comes from each locally managed container, not an unauthenticated
    # keyscan of the network endpoint. The targets use distinct key volumes.
    if docker compose -f deployment/lab/docker-compose.yml exec -T "$lab_service" \
      cat /etc/ssh/host_keys/ssh_host_ed25519_key.pub > .lab/known_hosts.raw 2>/dev/null && [ -s .lab/known_hosts.raw ]; then
      sed "s/^/$lab_service /" .lab/known_hosts.raw >> .lab/known_hosts.next
      rm .lab/known_hosts.raw
      break
    fi
    rm -f .lab/known_hosts.raw
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 15 ]; then
      rm -f .lab/known_hosts.next
      echo "Lab SSH target $lab_service did not start." >&2
      exit 1
    fi
    sleep 1
  done
done
# A new fixture may add trust, but no previously pinned line may disappear.
if [ -s .lab/known_hosts ] && ! awk 'NR == FNR { previous[$0] = 1; next } { delete previous[$0] } END { for (line in previous) exit 1 }' .lab/known_hosts .lab/known_hosts.next; then
  rm -f .lab/known_hosts.next
  echo "Lab target host key changed. Review the container/volume change before resetting lab trust." >&2
  exit 1
fi
mv .lab/known_hosts.next .lab/known_hosts

docker compose -f deployment/lab/docker-compose.yml up --build -d --wait --wait-timeout 180 hcp
docker compose -f deployment/lab/docker-compose.yml exec --user node -T hcp \
  ansible -i /app/ansible/inventory.ini lab-insecure -m ping
echo "Lab is ready: http://127.0.0.1:3001 (password: lab-only-password)"
