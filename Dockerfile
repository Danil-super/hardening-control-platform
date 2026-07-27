FROM node:22-bookworm-slim AS dependencies

WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci

FROM node:22-bookworm-slim AS build

WORKDIR /app
COPY --from=dependencies /app/web/node_modules ./web/node_modules
COPY web ./web
RUN cd web && npm run build

FROM node:22-bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends ansible ca-certificates lynis nmap openssh-client python3 ssh-audit util-linux \
  && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
  PORT=3000 \
  HCP_REPORTS_DIR=/var/lib/hcp/reports \
  HCP_STATE_DIR=/var/lib/hcp

WORKDIR /app
COPY --chown=node:node --from=dependencies /app/web/node_modules ./web/node_modules
COPY --chown=node:node --from=build /app/web/.next ./web/.next
COPY --chown=node:node web/package.json web/package-lock.json ./web/
COPY --chown=node:node web/public ./web/public
COPY --chown=node:node ansible ./ansible
COPY --chown=node:node ansible.cfg ./ansible.cfg
COPY --chown=node:node deployment/docker-entrypoint.sh /usr/local/bin/hcp-entrypoint

RUN mkdir -p /var/lib/hcp/reports /home/node/.ssh \
  && chown -R node:node /var/lib/hcp /home/node/.ssh /app \
  && chmod 700 /home/node/.ssh \
  && chmod 755 /usr/local/bin/hcp-entrypoint

WORKDIR /app/web
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/hcp-entrypoint"]
CMD ["npm", "start", "--", "--hostname", "0.0.0.0"]
