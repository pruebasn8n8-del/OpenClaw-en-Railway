FROM node:22-bookworm-slim

# Minimal system dependencies (no Chromium — WhatsApp via Baileys doesn't need it)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    python3 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Skip browser downloads (not needed for WhatsApp/Baileys)
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=true

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Create persistent directories
RUN mkdir -p /data/.openclaw /data/workspace

# OpenClaw environment
ENV OPENCLAW_STATE_DIR=/data/.openclaw
ENV OPENCLAW_WORKSPACE_DIR=/data/workspace
ENV NODE_ENV=production

# Clone and build OpenClaw, then clean up build artifacts to minimize image size
WORKDIR /app
RUN git clone --depth 1 https://github.com/openclaw/openclaw.git . && \
    pnpm install --frozen-lockfile && \
    pnpm build && \
    pnpm ui:install && \
    pnpm ui:build && \
    pnpm store prune && \
    rm -rf .git /tmp/* /root/.npm /root/.cache

# Copy wrapper files
COPY server.cjs /app/server.cjs
COPY setup.html /app/setup.html

EXPOSE 8080

CMD ["node", "/app/server.cjs"]
