const http = require("http");
const https = require("https");
const { spawn, execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const dns = require("dns");

// HF Spaces blocks WhatsApp DNS — override to use public resolvers
dns.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4"]);

// === CONFIG ===
const PORT = process.env.PORT || 8080;
const GATEWAY_PORT = 18789;
const SETUP_PASSWORD = process.env.SETUP_PASSWORD || "admin123";
const STATE_DIR = process.env.OPENCLAW_STATE_DIR || "/data/.openclaw";
const WORKSPACE_DIR = process.env.OPENCLAW_WORKSPACE_DIR || "/data/workspace";
let OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || "";
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || "openai/gpt-4o-mini";
const OPENROUTER_FALLBACK = process.env.OPENROUTER_FALLBACK || "openai/gpt-3.5-turbo";

// HF Dataset backup for persistent WhatsApp session
const HF_TOKEN = process.env.HF_TOKEN || "";
const HF_DATASET = process.env.HF_DATASET || ""; // e.g. "AndrewQroqbot/openclaw-session"

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
      if (!existing.gateway.controlUi.dangerouslyDisableDeviceAuth) {
        existing.gateway.controlUi.dangerouslyDisableDeviceAuth = true;
        patched = true;
      }
      // Always sync model from env var (fixes Groq-only model IDs like versatile/instant)
      const model = existing.agents?.defaults?.model || "";
      const expectedModel = "openrouter/" + OPENROUTER_MODEL;
      if (model !== expectedModel) {
        existing.agents = existing.agents || {};
        existing.agents.defaults = existing.agents.defaults || {};
        existing.agents.defaults.model = expectedModel;
        patched = true;
        console.log("[wrapper] Patched config: model", model || "(none)", "→", expectedModel);
      }
      // Force dmPolicy to open so anyone can chat
      if (!existing.channels) { existing.channels = {}; patched = true; }
      if (!existing.channels.whatsapp) { existing.channels.whatsapp = {}; patched = true; }
      if (existing.channels.whatsapp.dmPolicy !== "open") {
        existing.channels.whatsapp.dmPolicy = "open";
        existing.channels.whatsapp.allowFrom = ["*"];
        patched = true;
        console.log("[wrapper] Patched config: dmPolicy → open");
      }
      if (patched) {
        fs.writeFileSync(configPath, JSON.stringify(existing, null, 2));
        console.log("[wrapper] Patched config: trustedProxies + allowedOrigins + dmPolicy + model");
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
        dangerouslyDisableDeviceAuth: true,
      },
    },
    channels: {
      whatsapp: {
        dmPolicy: "open",
        allowFrom: ["*"],
      },
    },
  };
  return config;
}

// === DOCTOR FIX ===
function runDoctorFix(env, callback) {
  console.log("[wrapper] Running openclaw doctor --fix...");
  let done = false;
  const finish = () => { if (!done) { done = true; callback(); } };
  const doctor = spawn("node", ["dist/index.js", "doctor", "--fix", "--yes"], {
    cwd: "/app",
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  doctor.stdout.on("data", (d) => process.stdout.write(`[doctor] ${d}`));
  doctor.stderr.on("data", (d) => process.stderr.write(`[doctor:err] ${d}`));
  doctor.on("exit", (code) => {
    console.log(`[doctor] exited with code ${code}`);
    finish();
  });
  // Fallback: si no termina en 30s, continuar igual
  setTimeout(() => { if (!doctor.killed) doctor.kill(); finish(); }, 30000);
}

// === HF DATASET BACKUP/RESTORE ===
function hfHttpGet(url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname, port: 443,
      path: u.pathname + u.search,
      method: "GET",
      headers: { Authorization: `Bearer ${HF_TOKEN}` },
    }, (res) => {
      if (res.statusCode === 404) { resolve(null); return; }
      const chunks = [];
      res.on("data", d => chunks.push(d));
      res.on("end", () => {
        if (res.statusCode >= 400) reject(new Error(`HTTP ${res.statusCode}`));
        else resolve(Buffer.concat(chunks));
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function hfUpload(dataset, filePath, base64Content) {
  return new Promise((resolve, reject) => {
    const ndjson = [
      JSON.stringify({ key: "header", summary: "Update session backup", description: "" }),
      JSON.stringify({ key: "file", type: "upsert", path: filePath, encoding: "base64", content: base64Content }),
    ].join("\n");
    const body = Buffer.from(ndjson);
    const req = https.request({
      hostname: "huggingface.co", port: 443,
      path: `/api/datasets/${dataset}/commit/main`,
      method: "POST",
      headers: {
        Authorization: `Bearer ${HF_TOKEN}`,
        "Content-Type": "application/x-ndjson",
        "Content-Length": body.length,
      },
    }, (res) => {
      const chunks = [];
      res.on("data", d => chunks.push(d));
      res.on("end", () => {
        const resp = Buffer.concat(chunks).toString();
        if (res.statusCode >= 400) reject(new Error(`HTTP ${res.statusCode}: ${resp}`));
        else resolve(resp);
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

async function restoreSessionFromHF() {
  if (!HF_TOKEN || !HF_DATASET) return;
  console.log("[hf-backup] Checking for session backup in", HF_DATASET);
  try {
    const data = await hfHttpGet(
      `https://huggingface.co/datasets/${HF_DATASET}/resolve/main/session.tar.gz`
    );
    if (!data || data.length === 0) {
      console.log("[hf-backup] No backup found.");
      return;
    }
    const tmpFile = "/tmp/hf-session-restore.tar.gz";
    fs.writeFileSync(tmpFile, data);
    const parentDir = path.dirname(STATE_DIR);
    fs.mkdirSync(parentDir, { recursive: true });
    execSync(`tar -xzf "${tmpFile}" -C "${parentDir}"`, { stdio: "pipe" });
    fs.unlinkSync(tmpFile);
    console.log("[hf-backup] Session restored from HF Dataset (" + data.length + " bytes).");
  } catch (e) {
    console.log("[hf-backup] Restore failed:", e.message);
  }
}

let backupInProgress = false;
async function backupSessionToHF() {
  if (!HF_TOKEN || !HF_DATASET) return;
  if (!fs.existsSync(STATE_DIR)) return;
  if (backupInProgress) return;
  backupInProgress = true;
  console.log("[hf-backup] Backing up session to HF Dataset...");
  try {
    const tmpFile = "/tmp/hf-session-backup.tar.gz";
    const parentDir = path.dirname(STATE_DIR);
    const dirName = path.basename(STATE_DIR);
    execSync(`tar -czf "${tmpFile}" -C "${parentDir}" "${dirName}"`, { stdio: "pipe" });
    const content = fs.readFileSync(tmpFile).toString("base64");
    fs.unlinkSync(tmpFile);
    await hfUpload(HF_DATASET, "session.tar.gz", content);
    console.log("[hf-backup] Session backed up successfully.");
  } catch (e) {
    console.error("[hf-backup] Backup failed:", e.message);
  } finally {
    backupInProgress = false;
  }
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
    // Force public DNS — HF Spaces blocks WhatsApp DNS resolution
    NODE_OPTIONS: ((process.env.NODE_OPTIONS || "") + " --dns-result-order=ipv4first").trim(),
  };

  runDoctorFix(env, () => {
    _spawnGateway(env);
  });
}

// Tail the gateway JSONL log file and pipe to stdout
let logWatcherActive = false;
function watchGatewayLog() {
  if (logWatcherActive) return;
  const logDir = "/tmp/openclaw";
  const getLogPath = () => {
    const d = new Date().toISOString().slice(0, 10);
    return `${logDir}/openclaw-${d}.log`;
  };

  let logPath = getLogPath();
  let logPos = 0;

  function readNew() {
    const currentPath = getLogPath();
    if (currentPath !== logPath) { logPath = currentPath; logPos = 0; }
    if (!fs.existsSync(logPath)) return;
    try {
      const stat = fs.statSync(logPath);
      if (stat.size <= logPos) return;
      const fd = fs.openSync(logPath, "r");
      const buf = Buffer.alloc(stat.size - logPos);
      fs.readSync(fd, buf, 0, buf.length, logPos);
      fs.closeSync(fd);
      logPos = stat.size;
      buf.toString().split("\n").filter(l => l.trim()).forEach(line => {
        try {
          const entry = JSON.parse(line);
          const level = entry.level || "info";
          const msg = entry.msg || entry.message || line;
          const ctx = entry.channel ? `[${entry.channel}] ` : "";
          process.stdout.write(`[log:${level}] ${ctx}${msg}\n`);
        } catch {
          process.stdout.write(`[log] ${line}\n`);
        }
      });
    } catch {}
  }

  logWatcherActive = true;
  setInterval(readNew, 2000);
}

function _spawnGateway(env) {
  gatewayProcess = spawn("node", ["--max-old-space-size=1024", "dist/index.js", "gateway", "--port", String(GATEWAY_PORT), "--allow-unconfigured"], {
    cwd: "/app",
    env: { ...env, LOG_LEVEL: "info" },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let whatsappConnected = false;

  gatewayProcess.stdout.on("data", (d) => {
    const line = d.toString();
    process.stdout.write(`[gateway] ${line}`);
    if (line.includes("listening") || line.includes("ready") || line.includes("Gateway")) {
      gatewayReady = true;
      watchGatewayLog();
    }
    // Trigger backup when WhatsApp connects
    if (!whatsappConnected && (
      line.includes("Listening for personal WhatsApp") ||
      line.includes("starting provider") ||
      line.includes("connection opened")
    )) {
      whatsappConnected = true;
      console.log("[hf-backup] WhatsApp connected — scheduling backup in 10s");
      setTimeout(() => backupSessionToHF().catch(() => {}), 10000);
    }
  });

  gatewayProcess.stderr.on("data", (d) => {
    process.stderr.write(`[gateway:err] ${d}`);
  });

  gatewayProcess.on("exit", (code) => {
    console.log(`[wrapper] Gateway exited with code ${code}`);
    gatewayProcess = null;
    gatewayReady = false;
    // Backup session before restart
    backupSessionToHF().catch(() => {}).finally(() => {
      setTimeout(startGateway, 5000);
    });
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

  // Pairing approval endpoint (password protected)
  if (req.url.startsWith("/pairing")) {
    if (!checkAuth(req)) {
      res.writeHead(401, { "WWW-Authenticate": 'Basic realm="OpenClaw Setup"', "Content-Type": "text/plain" });
      res.end("Authentication required");
      return;
    }
    const parsedUrl = new URL(req.url, "http://x");
    const code = parsedUrl.searchParams.get("code");
    const channel = parsedUrl.searchParams.get("channel") || "whatsapp";

    if (!code) {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<html><body style="font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px">
        <h2>Approve WhatsApp Pairing</h2>
        <form method="GET" action="/pairing">
          <input name="code" placeholder="Pairing code (e.g. VU8ATNS7)" style="padding:8px;width:300px;background:#161b22;border:1px solid #30363d;color:#e6edf3">
          <input name="channel" value="whatsapp" style="padding:8px;width:100px;background:#161b22;border:1px solid #30363d;color:#e6edf3">
          <button type="submit" style="padding:8px 16px;background:#238636;border:none;color:white;cursor:pointer">Approve</button>
        </form>
      </body></html>`);
      return;
    }

    const gatewayEnv = {
      ...process.env,
      OPENCLAW_STATE_DIR: STATE_DIR,
      OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
      OPENCLAW_GATEWAY_TOKEN: GATEWAY_TOKEN,
    };
    const proc = spawn("node", ["dist/index.js", "pairing", "approve", channel, code], {
      cwd: "/app", env: gatewayEnv, stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    proc.stdout.on("data", d => { out += d; });
    proc.stderr.on("data", d => { out += d; });
    proc.on("exit", (exitCode) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<html><body style="font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px">
        <h2>Pairing Result (code ${exitCode})</h2>
        <pre>${out || "(no output)"}</pre>
        <a href="/pairing" style="color:#58a6ff">← Approve another</a>
      </body></html>`);
    });
    return;
  }

  // Auth redirect: /auth → /?token=TOKEN (convenience link)
  if (req.url === "/auth") {
    res.writeHead(302, { Location: `/?token=${encodeURIComponent(GATEWAY_TOKEN)}` });
    res.end();
    return;
  }

  // Diagnostic logs endpoint: /diag/logs
  if (req.url.startsWith("/diag/logs")) {
    const logDir = "/tmp/openclaw";
    const d = new Date().toISOString().slice(0, 10);
    const logPath = `${logDir}/openclaw-${d}.log`;
    const tail = parseInt(new URL(req.url, "http://x").searchParams.get("tail") || "200");
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    if (!fs.existsSync(logPath)) {
      res.end(`Log file not found: ${logPath}\nAvailable in ${logDir}:\n` +
        (fs.existsSync(logDir) ? fs.readdirSync(logDir).join("\n") : "(dir missing)"));
      return;
    }
    const lines = fs.readFileSync(logPath, "utf8").split("\n").filter(l => l.trim());
    const recent = lines.slice(-tail);
    res.end(recent.join("\n"));
    return;
  }

  // Manual backup trigger
  if (req.url === "/diag/backup") {
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    if (!HF_TOKEN || !HF_DATASET) {
      res.end("HF backup not configured. Set HF_TOKEN and HF_DATASET env vars.");
      return;
    }
    backupSessionToHF()
      .then(() => {})
      .catch(() => {});
    res.end("Backup triggered. Check logs for result.");
    return;
  }

  // Status endpoint
  if (req.url === "/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      setupComplete,
      gatewayReady,
      gatewayToken: GATEWAY_TOKEN,
      hfBackup: !!(HF_TOKEN && HF_DATASET),
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
console.log(`[wrapper] HF backup: ${HF_TOKEN && HF_DATASET ? HF_DATASET : "disabled"}`);
console.log(`[wrapper] OpenRouter model: ${OPENROUTER_MODEL}`);

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[wrapper] Server listening on port ${PORT}`);
  console.log(`[wrapper] Setup: http://0.0.0.0:${PORT}/setup`);
});

if (setupComplete) {
  // Restore session from HF Dataset, then start gateway
  restoreSessionFromHF()
    .catch(() => {})
    .finally(() => {
      startGateway();
      // Re-check setupComplete after restore (session files might have been restored)
      setupComplete = fs.existsSync(configPath);
    });
  // Periodic backup every 5 minutes
  setInterval(() => backupSessionToHF().catch(() => {}), 5 * 60 * 1000);
}
