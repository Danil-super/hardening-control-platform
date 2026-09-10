#!/bin/sh
set -eu

test -s /run/secrets/lab-authorized-key || { echo "Run ./deployment/lab/up.sh to generate the lab SSH key." >&2; exit 64; }
cp /run/secrets/lab-authorized-key /home/lab/.ssh/authorized_keys
chown -R lab:lab /home/lab/.ssh
chmod 700 /home/lab/.ssh
chmod 600 /home/lab/.ssh/authorized_keys

if [ ! -f /etc/ssh/host_keys/ssh_host_ed25519_key ]; then
  ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/host_keys/ssh_host_ed25519_key
fi

# Port-based finding only: this listener does not implement the Telnet protocol.
python3 -u -c 'import socket
with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 23))
    server.listen(32)
    while True:
        client, _ = server.accept()
        with client:
            try:
                client.sendall(b"HCP LAB test listener\r\n")
            except OSError:
                pass' &
exec /usr/sbin/sshd -D -e
