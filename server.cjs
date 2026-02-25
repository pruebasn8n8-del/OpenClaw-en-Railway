const http = require("http");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// === CONFIG ===
const PORT = process.env.PORT || 8080;
const GATEWAY_PORT = 18789;
const SETUP_PASSWORD = process.env.SETUP_PASSWORD || "admin123";
const STATE_DIR = process.env.OPENCLAW_STATE_DIR || "/data/.openclaw";
const WORKSPACE_DIR = process.env.OPENCLAW_WORKSPACE_DIR || "/data/workspace";
let OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || "";
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || "meta-llama/llama-3.3-70b-versatile";
const OPENROUTER_FALLBACK = process.env.OPENROUTER_FALLBACK || "meta-llama/llama-3.1-8b-instant";

// Auto-generate gateway token if not set
let GATEWAY_TOKEN = process.env.OPENCLAW_GATEWAY_TOKEN || "";
const tokenPath = path.join(STATE_DIR, "gateway.token");
if (!GATEWAY_TOKEN) {
  if (fs.existsSync(tokenPath)) {
    GATEWAY_TOKEN = fs.readFileSync(tokenPath, "utf8").trim();
  } else {
    GATEWAY_TOKEN = crypto.randomBytes(32).toString("hex");
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(tokenPath, GATEWAY_TOKEN);
  }
}

let gatewayProcess = null;
let gatewayReady = false;
let setupComplete = false;

// Check if already configured
const configPath = path.join(STATE_DIR, "openclaw.json");

// Borrar config inválido o parchear config existente
if (fs.existsSync(configPath)) {
  try {
    const existing = JSON.parse(fs.readFileSync(configPath, "utf8"));
    if (existing.gateway && existing.gateway.mode) {
      console.log("[wrapper] Deleting invalid config...");
      fs.unlinkSync(configPath);
    } else {
      // Patch: ensure gateway settings are correct
      let patched = false;
      if (!existing.gateway) { existing.gateway = {}; patched = true; }
      if (!existing.gateway.trustedProxies) {
        existing.gateway.trustedProxies = ["127.0.0.1", "::1"];
        patched = true;
      }
      if (!existing.gateway.controlUi) { existing.gateway.controlUi = {}; patched = true; }
      if (!existing.gateway.controlUi.allowedOrigins) {
        existing.gateway.controlUi.allowedOrigins = ["*"];
        patched = true;
      }
      if (patched) {
        fs.writeFileSync(configPath, JSON.stringify(existing, null, 2));
        console.log("[wrapper] Patched config: trustedProxies + allowedOrigins");
      }
    }
  } catch (e) {
    fs.unlinkSync(configPath);
  }
}

setupComplete = fs.existsSync(configPath);

// === OPENCLAW CONFIG GENERATOR ===
function generateConfig(options = {}) {
  const config = {
    agents: {
      defaults: {
        model: "openrouter/" + (options.model || OPENROUTER_MODEL),
      },
    },
    gateway: {
      trustedProxies: ["127.0.0.1", "::1"],
      controlUi: {
        allowedOrigins: ["*"],
      },
    },
    channels: {
      whatsapp: {
        dmPolicy: options.whatsappPolicy || "pairing",
        allowFrom: [],
      },
    },
  };
  if (options.whatsappPolicy === "open") {
    config.channels.whatsapp.allowFrom = ["*"];
  }
  return config;
}

// === GATEWAY MANAGEMENT ===
function startGateway() {
  if (gatewayProcess) return;

  console.log("[wrapper] Starting OpenClaw gateway...");

  const env = {
    ...process.env,
    HOME: STATE_DIR.replace("/.openclaw", ""),
    OPENCLAW_STATE_DIR: STATE_DIR,
    OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
    OPENCLAW_GATEWAY_TOKEN: GATEWAY_TOKEN,
    OPENROUTER_API_KEY: OPENROUTER_API_KEY,
    NODE_ENV: "production",
  };

gatewayProcess = spawn("node", ["--max-old-space-size=1024", "dist/index.js", "gateway", "--port", String(GATEWAY_PORT), "--allow-unconfigured"], {
    cwd: "/app",
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  gatewayProcess.stdout.on("data", (d) => {
    const line = d.toString();
    process.stdout.write(`[gateway] ${line}`);
    if (line.includes("listening") || line.includes("ready") || line.includes("Gateway")) {
      gatewayReady = true;
    }
  });

  gatewayProcess.stderr.on("data", (d) => {
    process.stderr.write(`[gateway:err] ${d}`);
  });

  gatewayProcess.on("exit", (code) => {
    console.log(`[wrapper] Gateway exited with code ${code}`);
    gatewayProcess = null;
    gatewayReady = false;
    // Auto-restart after 5s
    setTimeout(startGateway, 5000);
  });

  // Give it time to start
  setTimeout(() => { gatewayReady = true; }, 10000);
}

// === RUN OPENCLAW ONBOARD ===
function runOnboard(groqKey, model, callback) {
  console.log("[wrapper] Running openclaw onboard...");

  // Write config directly
  const config = generateConfig({ model });
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  console.log("[wrapper] Config written to", configPath);

  setupComplete = true;
  callback(null);
}

// === PROXY TO GATEWAY ===
function proxyToGateway(req, res) {
  const externalHost = req.headers.host || "";
  const options = {
    hostname: "127.0.0.1",
    port: GATEWAY_PORT,
    path: req.url,
    method: req.method,
    headers: {
      ...req.headers,
      host: `127.0.0.1:${GATEWAY_PORT}`,
      "x-forwarded-host": externalHost,
      "x-forwarded-proto": "https",
      origin: `http://127.0.0.1:${GATEWAY_PORT}`,
    },
  };

  const proxy = http.request(options, (proxyRes) => {
    // Rewrite Location headers that point to internal gateway
    const headers = { ...proxyRes.headers };
    if (headers.location) {
      headers.location = headers.location
        .replace(`http://127.0.0.1:${GATEWAY_PORT}`, `https://${externalHost}`)
        .replace(`http://localhost:${GATEWAY_PORT}`, `https://${externalHost}`);
    }
    res.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(res);
  });

  proxy.on("error", () => {
    res.writeHead(502);
    res.end("Gateway not ready. Try again in a few seconds.");
  });

  req.pipe(proxy);
}

// === SETUP PAGE ===
function serveSetup(req, res) {
  if (req.method === "GET") {
    let html = fs.readFileSync("/app/setup.html", "utf8");
    html = html.replace("{{GATEWAY_TOKEN}}", GATEWAY_TOKEN);
    html = html.replace("{{OPENROUTER_MODEL}}", OPENROUTER_MODEL);
    html = html.replace("{{OPENROUTER_FALLBACK}}", OPENROUTER_FALLBACK);
    html = html.replace("{{SETUP_COMPLETE}}", setupComplete ? "true" : "false");
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
    return;
  }

  if (req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        const data = JSON.parse(body);

        if (data.action === "setup") {
          // Update env
          if (data.openrouterKey) {
            process.env.OPENROUTER_API_KEY = data.openrouterKey;
            OPENROUTER_API_KEY = data.openrouterKey;
          }

          runOnboard(data.openrouterKey, data.model, (err) => {
            if (err) {
              res.writeHead(500, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: err.message }));
              return;
            }
            // Start or restart gateway
            if (gatewayProcess) {
              gatewayProcess.kill();
              gatewayProcess = null;
            }
            setTimeout(startGateway, 1000);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              success: true,
              gatewayToken: GATEWAY_TOKEN,
              message: "Setup complete! Gateway starting...",
            }));
          });
        } else if (data.action === "restart") {
          if (gatewayProcess) gatewayProcess.kill();
          gatewayProcess = null;
          setTimeout(startGateway, 1000);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true }));
        } else {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Unknown action" }));
        }
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
  }
}

// === AUTH CHECK ===
function checkAuth(req) {
  const auth = req.headers.authorization;
  if (!auth) return false;
  const [, encoded] = auth.split(" ");
  const decoded = Buffer.from(encoded, "base64").toString();
  const [, password] = decoded.split(":");
  return password === SETUP_PASSWORD;
}

// === HTTP SERVER ===
const server = http.createServer((req, res) => {
  // Health check
  if (req.url === "/healthz") {
    res.writeHead(200);
    res.end("ok");
    return;
  }

  // Setup page (password protected)
  if (req.url.startsWith("/setup")) {
    if (!checkAuth(req)) {
      res.writeHead(401, {
        "WWW-Authenticate": 'Basic realm="OpenClaw Setup"',
        "Content-Type": "text/plain",
      });
      res.end("Authentication required");
      return;
    }
    serveSetup(req, res);
    return;
  }

  // Auth redirect: /auth → /?token=TOKEN (convenience link)
  if (req.url === "/auth") {
    res.writeHead(302, { Location: `/?token=${encodeURIComponent(GATEWAY_TOKEN)}` });
    res.end();
    return;
  }

  // Status endpoint
  if (req.url === "/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      setupComplete,
      gatewayReady,
      gatewayToken: GATEWAY_TOKEN,
    }));
    return;
  }

  // Everything else → proxy to gateway
  if (setupComplete && gatewayReady) {
    proxyToGateway(req, res);
  } else if (setupComplete && !gatewayReady) {
    res.writeHead(503, { "Content-Type": "text/html" });
    res.end("<h1>Gateway starting...</h1><p>Refresh in 10 seconds.</p><script>setTimeout(()=>location.reload(),10000)</script>");
  } else {
    // Redirect to setup
    res.writeHead(302, { Location: "/setup" });
    res.end();
  }
});

// WebSocket upgrade → proxy to gateway
server.on("upgrade", (req, socket, head) => {
  const options = {
    hostname: "127.0.0.1",
    port: GATEWAY_PORT,
    path: req.url,
    method: "GET",
    headers: {
      ...req.headers,
      host: `127.0.0.1:${GATEWAY_PORT}`,
      origin: `http://127.0.0.1:${GATEWAY_PORT}`,
    },
  };

  const proxy = http.request(options);
  proxy.on("upgrade", (proxyRes, proxySocket, proxyHead) => {
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\n` +
      Object.entries(proxyRes.headers).map(([k, v]) => `${k}: ${v}`).join("\r\n") +
      "\r\n\r\n"
    );
    proxySocket.pipe(socket);
    socket.pipe(proxySocket);
  });
  proxy.on("error", () => socket.end());
  proxy.end();
});

// === START ===
console.log(`[wrapper] OpenClaw Railway Wrapper`);
console.log(`[wrapper] Port: ${PORT}`);
console.log(`[wrapper] State: ${STATE_DIR}`);
console.log(`[wrapper] OpenRouter model: ${OPENROUTER_MODEL}`);
console.log(`[wrapper] Setup complete: ${setupComplete}`);

if (setupComplete) {
  startGateway();
}

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[wrapper] Server listening on port ${PORT}`);
  console.log(`[wrapper] Setup: http://0.0.0.0:${PORT}/setup`);
});
