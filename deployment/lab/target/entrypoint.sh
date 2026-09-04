#!/bin/sh
set -eu

test -n "${HCP_LAB_PUBLIC_KEY:-}" || { echo "HCP_LAB_PUBLIC_KEY is required" >&2; exit 64; }
printf '%s\n' "$HCP_LAB_PUBLIC_KEY" > /home/lab/.ssh/authorized_keys
chown -R lab:lab /home/lab/.ssh
chmod 700 /home/lab/.ssh
chmod 600 /home/lab/.ssh/authorized_keys

# Intentional lab-only finding: the basic profile must detect this listener.
busybox nc -lk -p 23 >/dev/null 2>&1 &
ufw default allow incoming >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true
exec /usr/sbin/sshd -D -e
