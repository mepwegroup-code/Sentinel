# Sentinel OS: reproducible Coolify Dockerfile build.
# Git repository + Dockerfile build pack; internal HTTP port 3000.
FROM node:22-bookworm-slim AS builder
WORKDIR /app

COPY package*.json ./
RUN npm install --no-audit --no-fund

COPY . .
RUN npm run check && npm run build

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    PORT=3000 \
    SENTINEL_DATA_DIR=/app/data
WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund \
  && npm cache clean --force \
  && mkdir -p /app/data \
  && chown -R node:node /app/data

COPY --from=builder --chown=node:node /app/dist ./dist
COPY --from=builder --chown=node:node /app/agent ./agent

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.cjs"]
