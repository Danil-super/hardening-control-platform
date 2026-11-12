ARG NODE_IMAGE=node:24-bookworm-slim@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553
ARG PYTHON_IMAGE=python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72
ARG TRIVY_IMAGE=aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
FROM ${TRIVY_IMAGE} AS trivy

FROM ${PYTHON_IMAGE} AS ansible-modern

# Separate controller Python supports current targets without replacing either
# the Debian Python used by ReportLab or Python on any audited server.
COPY deployment/requirements/ansible-modern.txt /opt/hcp-tools/requirements/ansible-modern.txt
RUN python3.13 -m venv /opt/hcp-tools/ansible-modern \
  && /opt/hcp-tools/ansible-modern/bin/python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/hcp-tools/requirements/ansible-modern.txt \
  && /opt/hcp-tools/ansible-modern/bin/python -m pip check

FROM ${NODE_IMAGE} AS dependencies

WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci

FROM ${NODE_IMAGE} AS build

WORKDIR /app
COPY --from=dependencies /app/web/node_modules ./web/node_modules
COPY web ./web
RUN cd web && npm run build

FROM ${NODE_IMAGE} AS runtime

# Disable the inherited APT retry path until its security update is installed.
# Explicit base packages are refreshed even when the base image is cached.
RUN apt-get -o Acquire::Retries=0 update \
  && apt-get -o Acquire::Retries=0 install -y --no-install-recommends apt libpcre2-8-0 liblzma5 tzdata ansible ca-certificates fonts-dejavu-core iproute2 iputils-ping lynis nmap openscap-scanner openssh-client python3 python3-paramiko python3-reportlab python3-venv util-linux \
  && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' apt)" ge 2.6.2 \
  && rm -rf /var/lib/apt/lists/*

# The global CLI has its own advisories outside the application's lockfile.
# Keep its update pinned and include it in the separate whole-image scan.
RUN npm install --global --ignore-scripts --no-fund npm@12.2.2 \
  && npm --version

COPY --from=ansible-modern /usr/local/bin/python3.13 /usr/local/bin/python3.13
COPY --from=ansible-modern /usr/local/lib/python3.13 /usr/local/lib/python3.13
COPY --from=ansible-modern /usr/local/lib/libpython3.13.so.1.0 /usr/local/lib/libpython3.13.so.1.0
COPY --from=ansible-modern /opt/hcp-tools/ansible-modern /opt/hcp-tools/ansible-modern
COPY deployment/requirements /opt/hcp-tools/requirements
RUN ldconfig \
  && /opt/hcp-tools/ansible-modern/bin/ansible --version \
  && /usr/bin/python3 -c "import reportlab"

# Debian bookworm packages ssh-audit 2.5, whose JSON omits recommendations and
# lacks --skip-rate-test. Keep the supported scanner isolated from system Python.
RUN python3 -m venv /opt/hcp-tools/ssh-audit \
  && /opt/hcp-tools/ssh-audit/bin/python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/hcp-tools/requirements/ssh-audit.txt \
  && /opt/hcp-tools/ssh-audit/bin/python -m pip check \
  && ln -s /opt/hcp-tools/ssh-audit/bin/ssh-audit /usr/local/bin/ssh-audit \
  && ssh-audit --help

# Public CVE prose is translated offline. Pin both the engine and model bytes;
# runtime translation never sends host reports to a third-party service.
COPY deployment/install-description-model.py /opt/hcp-tools/install-description-model.py
RUN python3 -m venv /opt/hcp-tools/translation \
  && /opt/hcp-tools/translation/bin/python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/hcp-tools/requirements/translation.txt \
  && /opt/hcp-tools/translation/bin/python -m pip check \
  && python3 /opt/hcp-tools/install-description-model.py --destination /opt/hcp-tools/translation/model

ENV NODE_ENV=production \
  HOME=/home/node \
  PORT=3000 \
  HCP_REPORTS_DIR=/var/lib/hcp/reports \
  HCP_STATE_DIR=/var/lib/hcp \
  HCP_TRIVY_MODE=online \
  HCP_ANSIBLE_MODERN_BIN_DIR=/opt/hcp-tools/ansible-modern/bin

WORKDIR /app
COPY --chown=node:node --from=dependencies /app/web/node_modules ./web/node_modules
COPY --chown=node:node --from=build /app/web/.next ./web/.next
COPY --chown=node:node --from=build /app/web/.hcp-report-reader ./web/.hcp-report-reader
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --chown=node:node web/package.json web/package-lock.json ./web/
COPY --chown=node:node web/public ./web/public
COPY --chown=node:node ansible ./ansible
COPY --chown=node:node ansible.cfg ./ansible.cfg
COPY --chown=node:node deployment/docker-entrypoint.sh /usr/local/bin/hcp-entrypoint
COPY --chown=node:node deployment/hcp-scheduled-audit /usr/local/bin/hcp-scheduled-audit

RUN mkdir -p /var/lib/hcp/reports /var/lib/hcp/sbom /var/lib/hcp/trivy-cache /home/node/.ssh /home/node/.ansible/tmp \
  && chown -R node:node /var/lib/hcp /home/node/.ssh /home/node/.ansible /app \
  && chmod 700 /home/node/.ssh /home/node/.ansible /home/node/.ansible/tmp \
  && chmod 755 /usr/local/bin/hcp-entrypoint /usr/local/bin/hcp-scheduled-audit

WORKDIR /app/web
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/hcp-entrypoint"]
CMD ["npm", "start", "--", "--hostname", "0.0.0.0"]
