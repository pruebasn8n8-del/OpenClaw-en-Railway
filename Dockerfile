FROM node:22-bookworm

# Instalar dependencias del sistema + Chromium para browser automation
RUN apt-get update && apt-get install -y \
    git \
    curl \
    python3 \
    build-essential \
    chromium \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxss1 \
    libxtst6 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Usar Chromium del sistema (evitar descarga de Puppeteer)
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium
# Flags necesarios para correr Chromium sin sandbox en containers
ENV CHROMIUM_FLAGS="--no-sandbox --disable-setuid-sandbox --disable-dev-shm-usage --disable-gpu"

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

# Forzar DNS público en runtime (HF Spaces bloquea DNS de WhatsApp)
CMD ["/bin/sh", "-c", "echo 'nameserver 8.8.8.8\\nnameserver 1.1.1.1\\nnameserver 8.8.4.4' > /etc/resolv.conf && node /app/server.cjs"]
