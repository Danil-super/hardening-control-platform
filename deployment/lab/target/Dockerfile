FROM debian:bookworm-slim

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server python3 sudo busybox iproute2 ufw \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --create-home --shell /bin/bash lab \
  && echo 'lab ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/lab \
  && chmod 440 /etc/sudoers.d/lab \
  && mkdir -p /run/sshd /home/lab/.ssh /etc/ssh/host_keys \
  && rm -f /etc/ssh/ssh_host_* \
  && printf '%s\n' 'HostKey /etc/ssh/host_keys/ssh_host_ed25519_key' 'PermitRootLogin yes' 'PasswordAuthentication no' 'PermitEmptyPasswords no' 'MaxAuthTries 8' >> /etc/ssh/sshd_config

COPY entrypoint.sh /usr/local/bin/lab-entrypoint
RUN chmod 755 /usr/local/bin/lab-entrypoint

EXPOSE 22 23
ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
