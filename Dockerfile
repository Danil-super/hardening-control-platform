ARG TRIVY_IMAGE=aquasec/trivy:0.74.0
FROM ${TRIVY_IMAGE} AS trivy

FROM node:24-bookworm-slim AS dependencies

WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci

FROM node:24-bookworm-slim AS build

WORKDIR /app
COPY --from=dependencies /app/web/node_modules ./web/node_modules
COPY web ./web
RUN cd web && npm run build

FROM node:24-bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends ansible ca-certificates lynis nmap openscap-scanner openssh-client python3 python3-venv util-linux \
  && rm -rf /var/lib/apt/lists/*

# Debian bookworm packages ssh-audit 2.5, whose JSON omits recommendations and
# lacks --skip-rate-test. Keep the supported scanner isolated from system Python.
RUN python3 -m venv /opt/hcp-tools/ssh-audit \
  && /opt/hcp-tools/ssh-audit/bin/pip install --no-cache-dir --only-binary=:all: ssh-audit==3.3.0 \
  && ln -s /opt/hcp-tools/ssh-audit/bin/ssh-audit /usr/local/bin/ssh-audit \
  && ssh-audit --help

ENV NODE_ENV=production \
  HOME=/home/node \
  PORT=3000 \
  HCP_REPORTS_DIR=/var/lib/hcp/reports \
  HCP_STATE_DIR=/var/lib/hcp \
  HCP_TRIVY_MODE=online

WORKDIR /app
COPY --chown=node:node --from=dependencies /app/web/node_modules ./web/node_modules
COPY --chown=node:node --from=build /app/web/.next ./web/.next
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --chown=node:node web/package.json web/package-lock.json ./web/
COPY --chown=node:node web/public ./web/public
COPY --chown=node:node ansible ./ansible
COPY --chown=node:node ansible.cfg ./ansible.cfg
COPY --chown=node:node deployment/docker-entrypoint.sh /usr/local/bin/hcp-entrypoint
COPY --chown=node:node deployment/hcp-scheduled-audit /usr/local/bin/hcp-scheduled-audit

RUN mkdir -p /var/lib/hcp/reports /var/lib/hcp/sbom /var/lib/hcp/trivy-cache /home/node/.ssh \
  && chown -R node:node /var/lib/hcp /home/node/.ssh /app \
  && chmod 700 /home/node/.ssh \
  && chmod 755 /usr/local/bin/hcp-entrypoint /usr/local/bin/hcp-scheduled-audit

WORKDIR /app/web
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/hcp-entrypoint"]
CMD ["npm", "start", "--", "--hostname", "0.0.0.0"]
