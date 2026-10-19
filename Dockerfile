# SOC Range container image. Build: docker compose build (see README, "Run with Docker").
# Base: node:22.23.3-alpine3.24, pinned by digest (multi-arch index, checked against Docker Hub 2026-10-16).
# Written out in both FROM lines (not via ARG) so Dependabot can see and update the tag and digest together.

# ---- deps: production dependencies only, from the lockfile ----
FROM node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && npm cache clean --force

# ---- runtime ----
FROM node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
ENV NODE_ENV=production \
    # Listen on the container's own interface so a published port can reach the app. This is the only
    # place SOCSIM_HOST is set; compose.yaml publishes the port on the host's 127.0.0.1 only.
    SOCSIM_HOST=0.0.0.0 \
    SOCSIM_DATA_DIR=/data

# The app never needs npm, npx, corepack or yarn at runtime: remove them to shrink the attack surface
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
           /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg \
  && mkdir /data && chown 1000:1000 /data

WORKDIR /app
# App code is owned by root and read-only to the app user
COPY --from=deps /app/node_modules ./node_modules
COPY package.json server.js config.json ./
COPY src ./src
COPY public ./public
# rules/*.json are edited from the UI (rules, intel, playbooks), so the app user must be able to write them
COPY --chown=1000:1000 rules ./rules

# Numeric UID/GID of the image's built-in `node` user, so runtimes can verify it is not root
USER 1000:1000
EXPOSE 5000
VOLUME ["/data"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:5000/api/generator').then(r => r.json()).then(g => process.exit(typeof g.running === 'boolean' ? 0 : 1)).catch(() => process.exit(1))"]
CMD ["node", "server.js"]
