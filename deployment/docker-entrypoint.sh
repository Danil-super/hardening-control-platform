#!/bin/sh
set -eu

runtime_ssh_dir="/home/node/.ssh"
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

install_key "/run/secrets/hcp-control" "$runtime_ssh_dir/hcp-control" "600"
install_key "/run/secrets/known_hosts" "$runtime_ssh_dir/known_hosts" "644"

if [ "$is_root" = "true" ]; then
  exec setpriv --reuid=node --regid=node --init-groups "$@"
fi

exec "$@"
