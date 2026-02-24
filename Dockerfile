FROM node:22-bookworm

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    git \
    curl \
    python3 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Instalar pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Crear directorios persistentes
RUN mkdir -p /data/.openclaw /data/workspace

# Variables de entorno de OpenClaw
ENV OPENCLAW_STATE_DIR=/data/.openclaw
ENV OPENCLAW_WORKSPACE_DIR=/data/workspace
ENV NODE_ENV=production

# Clonar y construir OpenClaw
WORKDIR /app
RUN git clone --depth 1 https://github.com/openclaw/openclaw.git . && \
    pnpm install --frozen-lockfile && \
    pnpm build && \
    pnpm ui:install && \
    pnpm ui:build

# Copiar el servidor wrapper
COPY server.cjs /app/server.cjs
COPY setup.html /app/setup.html

# Puerto (Railway asigna $PORT)
EXPOSE 8080

CMD ["node", "/app/server.cjs"]
