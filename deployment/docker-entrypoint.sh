#!/bin/sh
set -eu
umask 077

runtime_ssh_dir="/home/node/.ssh"
mkdir -p /var/lib/hcp "$runtime_ssh_dir"
is_root="false"
if [ "$(id -u)" -eq 0 ]; then
  is_root="true"
  chown -R node:node /var/lib/hcp "$runtime_ssh_dir"
fi

install_key() {
  source_path="$1"
  destination_path="$2"
  mode="$3"

  if [ -r "$source_path" ]; then
    mkdir -p "$runtime_ssh_dir"
    chmod 700 "$runtime_ssh_dir"
    cp "$source_path" "$destination_path"
    chmod "$mode" "$destination_path"
    if [ "$is_root" = "true" ]; then
      chown node:node "$destination_path"
    fi
  fi
}

if [ ! -f /run/secrets/hcp-control ]; then
  echo "Missing SSH key: create secrets/hcp-control before starting HCP." >&2
  exit 64
fi
install_key "/run/secrets/hcp-control" "$runtime_ssh_dir/hcp-control" "600"
if ! ssh-keygen -y -P '' -f "$runtime_ssh_dir/hcp-control" > "$runtime_ssh_dir/hcp-control.pub" 2>/dev/null; then
  echo "HCP requires a valid dedicated SSH key without a passphrase (no ssh-agent is configured)." >&2
  exit 64
fi
chmod 644 "$runtime_ssh_dir/hcp-control.pub"

# Use the bind-mounted inventory only as an initial seed. Runtime edits belong
# to the node-owned persistent volume, independent of the host user's UID.
if [ ! -f /var/lib/hcp/inventory.ini ]; then
  if [ ! -f /run/secrets/inventory.ini ]; then
    echo "Missing inventory seed: copy ansible/inventory.example.ini to ansible/inventory.ini." >&2
    exit 64
  fi
  cp /run/secrets/inventory.ini /var/lib/hcp/inventory.ini
fi
chmod 600 /var/lib/hcp/inventory.ini
ln -sfn /var/lib/hcp/inventory.ini /app/ansible/inventory.ini

known_hosts_path="${HCP_KNOWN_HOSTS_PATH:-$runtime_ssh_dir/known_hosts}"
mkdir -p "$(dirname "$known_hosts_path")"
if [ ! -s "$known_hosts_path" ] && [ -r "/run/secrets/known_hosts" ]; then
  install_key "/run/secrets/known_hosts" "$known_hosts_path" "600"
fi
if [ "$known_hosts_path" != "$runtime_ssh_dir/known_hosts" ]; then
  rm -f "$runtime_ssh_dir/known_hosts"
  ln -s "$known_hosts_path" "$runtime_ssh_dir/known_hosts"
fi

if [ "$is_root" = "true" ]; then
  chown node:node /var/lib/hcp/inventory.ini "$runtime_ssh_dir/hcp-control.pub"
  exec setpriv --reuid=node --regid=node --init-groups "$@"
fi

exec "$@"
