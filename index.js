const express = require("express");
const https = require("https");
const dns = require("dns").promises;
const WebSocket = require("ws");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────
// CATEGORY MAP
// ─────────────────────────────
const categories = [
  { id: 1, name: "Safe",       allow: true  },
  { id: 2, name: "Suspicious", allow: false },
  { id: 3, name: "Blocked",    allow: false },
  { id: 0, name: "Unknown",    allow: false }
];

function mapCategory(num) {
  for (const c of categories) {
    if (Number(c.id) === Number(num)) return [c.name, c.allow];
  }
  return ["Unknown", false];
}

// ─────────────────────────────
// EXTRACT HOSTNAME
// ─────────────────────────────
function extractHostname(input) {
  input = input.trim();
  try {
    if (input.startsWith("http://") || input.startsWith("https://")) {
      return new URL(input).hostname;
    }
    return input.split("/")[0].toLowerCase();
  } catch {
    return input.toLowerCase();
  }
}

// ─────────────────────────────
// DNS RESOLVE — get real IP for domain
// ─────────────────────────────
async function resolveIP(domain) {
  try {
    const result = await dns.lookup(domain, { family: 4 });
    return result.address;
  } catch {
    return "0.0.0.0";
  }
}

// ─────────────────────────────
// LIGHTSPEED LOOKUP (with real resolved IP)
// ─────────────────────────────
async function lightspeed(domain) {
  const host = extractHostname(domain);

  // KEY FIX: resolve the domain's actual IP so Lightspeed categorises correctly
  const resolvedIP = await resolveIP(host);
  console.log(`[dns] ${host} → ${resolvedIP}`);

  return new Promise((resolve) => {
    let done = false;

    const ws = new WebSocket(
      "wss://production-gc.lsfilter.com?a=0ef9b862-b74f-4e8d-8aad-be549c5f452a&customer_id=74-1082-F000&agentType=chrome_extension&agentVersion=3.777.0&userGuid=00000000-0000-0000-0000-000000000000"
    );

    const timeout = setTimeout(() => {
      if (!done) {
        done = true;
        ws.terminate();
        resolve(["Timeout", false]);
      }
    }, 7000);

    ws.on("open", () => {
      ws.send(JSON.stringify({
        action:     "dy_lookup",
        host:       host,
        ip:         resolvedIP,   // ← real resolved IP, not hardcoded
        customerId: "74-1082-F000",
      }));
    });

    ws.on("message", (msg) => {
      if (done) return;
      done = true;
      clearTimeout(timeout);
      ws.close();

      try {
        const json = JSON.parse(msg.toString());
        console.log(`[lightspeed] ${host} → cat=${json.cat}`);
        resolve(mapCategory(json.cat));
      } catch {
        resolve(["Error", false]);
      }
    });

    ws.on("error", (err) => {
      if (!done) {
        done = true;
        clearTimeout(timeout);
        console.error(`[lightspeed] WS error for ${host}:`, err.message);
        resolve(["Connection Error", false]);
      }
    });
  });
}

// ─────────────────────────────
// REVERSE IP LOOKUP
// ─────────────────────────────
async function reverseIP(ip) {
  return new Promise((resolve) => {
    https.get(
      `https://api.hackertarget.com/reverseiplookup/?q=${ip}`,
      (res) => {
        let data = "";
        res.on("data", c => data += c);
        res.on("end", () => {
          const domains = data
            .split("\n")
            .map(x => x.trim())
            .filter(Boolean)
            .filter(x => !x.toLowerCase().startsWith("error"));
          resolve(domains.length ? domains : [ip]);
        });
      }
    ).on("error", () => resolve([ip]));
  });
}

// ─────────────────────────────
// SCAN A LIST OF DOMAINS/URLs
// ─────────────────────────────
async function scanDomains(targets) {
  const results = [];
  for (const raw of targets) {
    const domain = extractHostname(raw);
    if (!domain) continue;
    const [category, allowed] = await lightspeed(domain);
    results.push({ domain, raw, category, allowed });
    console.log(`${allowed ? "✅" : "❌"} ${domain} → ${category}`);
  }
  return results;
}

// ─────────────────────────────
// SCAN BY IP
// ─────────────────────────────
async function scanIP(ip) {
  console.log(`\n🔍 Scanning IP: ${ip}`);
  const domains = await reverseIP(ip);
  const targets = domains.slice(0, 30).map(d => extractHostname(d));
  return scanDomains(targets);
}

// ─────────────────────────────
// RENDER RESULTS
// ─────────────────────────────
function renderResults(results) {
  if (!results.length) return `<p style="color:#555">None.</p>`;
  return results.map(r => {
    const color = r.category === "Safe" ? "ok" : r.category === "Unknown" ? "unk" : "bad";
    return `
      <div class="box">
        <b>${r.domain}</b>
        <span class="${color} tag">${r.allowed ? "✅ SAFE" : "❌ BLOCKED"} — ${r.category}</span>
      </div>`;
  }).join("");
}

// ─────────────────────────────
// STYLES
// ─────────────────────────────
const pageStyles = `
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Share Tech Mono', monospace;
      background: #080808;
      color: #ddd;
      padding: 30px;
      max-width: 860px;
      margin: 0 auto;
    }
    h1 { color: #00ff88; font-size: 22px; margin-bottom: 6px; }
    nav { margin: 14px 0 24px; }
    nav a { color: #00ff88; text-decoration: none; margin-right: 20px; font-size: 14px; }
    nav a:hover { text-decoration: underline; }
    .section {
      background: #111;
      border: 1px solid #222;
      border-radius: 10px;
      padding: 18px;
      margin-bottom: 18px;
    }
    .section h2 { font-size: 13px; color: #888; margin-bottom: 12px; letter-spacing: 1px; }
    .box {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #1a1a1a;
      border-radius: 6px;
      padding: 10px 14px;
      margin: 6px 0;
      font-size: 13px;
      flex-wrap: wrap;
      gap: 6px;
    }
    .tag { font-size: 12px; padding: 3px 10px; border-radius: 20px; background:#0f0f0f; }
    .ok  { color: #00ff88; }
    .bad { color: #ff4444; }
    .unk { color: #ffaa00; }

    .ip-grid { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 14px; }
    .ip-btn {
      flex: 1;
      min-width: 200px;
      background: #1a1a1a;
      border: 2px solid #2a2a2a;
      border-radius: 10px;
      padding: 20px;
      text-align: center;
      cursor: pointer;
      text-decoration: none;
      color: #ddd;
      transition: border-color 0.2s, background 0.2s;
      display: block;
    }
    .ip-btn:hover { border-color: #00ff88; background: #0e1a14; }
    .ip-btn .ip-addr { font-size: 20px; color: #00ff88; display: block; margin-bottom: 6px; }
    .ip-btn .ip-label { font-size: 12px; color: #555; }

    textarea, input[type=text] {
      background: #111;
      color: white;
      border: 1px solid #333;
      border-radius: 6px;
      padding: 10px 14px;
      font-family: 'Share Tech Mono', monospace;
      font-size: 13px;
      width: 100%;
    }
    textarea { height: 120px; resize: vertical; }
    button[type=submit] {
      margin-top: 12px;
      padding: 10px 28px;
      background: #00ff88;
      color: #080808;
      border: none;
      border-radius: 6px;
      font-weight: bold;
      font-family: 'Share Tech Mono', monospace;
      font-size: 14px;
      cursor: pointer;
    }
    button[type=submit]:hover { background: #00cc6a; }
    p { color: #777; font-size: 13px; line-height: 1.7; margin-bottom: 8px; }
    code { color: #00ff88; }
  </style>
`;

// ─────────────────────────────
// ROUTES
// ─────────────────────────────

app.get("/", (req, res) => {
  res.send(`<html><head>${pageStyles}</head><body>
    <h1>⚡ Network Scanner</h1>
    <nav>
      <a href="/check">🔗 Check Domains/URLs</a>
      <a href="/scan">📡 Scan by IP</a>
    </nav>
    <div class="section">
      <p>Check specific CDN subdomains/links, or pick an IP to reverse-scan all its domains.</p>
    </div>
  </body></html>`);
});

// ── CHECK: specific domains/URLs ──
app.get("/check", (req, res) => {
  res.send(`<html><head>${pageStyles}</head><body>
    <h1>🔗 Check Domains / URLs</h1>
    <nav><a href="/">← Home</a></nav>
    <div class="section">
      <p>One domain or full URL per line.</p>
      <p>Full subdomains checked exactly — e.g. <code>ultralink4225.b-cdn.net</code></p>
      <form method="POST" action="/check">
        <textarea name="domains" placeholder="ultralink4225.b-cdn.net&#10;https://example.com/page&#10;cdn.something.net"></textarea>
        <button type="submit">▶ Check</button>
      </form>
    </div>
  </body></html>`);
});

app.post("/check", async (req, res) => {
  const raw = (req.body.domains || "").trim();
  const lines = raw.split("\n").map(x => x.trim()).filter(Boolean);
  if (!lines.length) return res.redirect("/check");

  const results = await scanDomains(lines);
  const safe    = results.filter(r => r.allowed);
  const blocked = results.filter(r => !r.allowed);

  res.send(`<html><head>${pageStyles}</head><body>
    <h1>🔗 Results</h1>
    <nav><a href="/check">← Check another</a> &nbsp; <a href="/">Home</a></nav>
    <div class="section">
      <h2>✅ UNBLOCKED (${safe.length})</h2>
      ${renderResults(safe)}
    </div>
    <div class="section">
      <h2>❌ BLOCKED / UNKNOWN (${blocked.length})</h2>
      ${renderResults(blocked)}
    </div>
  </body></html>`);
});

// ── SCAN: pick from 2 IPs ──
app.get("/scan", (req, res) => {
  res.send(`<html><head>${pageStyles}</head><body>
    <h1>📡 Scan by IP</h1>
    <nav><a href="/">← Home</a></nav>
    <div class="section">
      <p>Choose a server to reverse-lookup and test all its domains:</p>
      <div class="ip-grid">
        <a class="ip-btn" href="/scan/159.195.59.55">
          <span class="ip-addr">159.195.59.55</span>
          <span class="ip-label">Server A</span>
        </a>
        <a class="ip-btn" href="/scan/15.204.230.233">
          <span class="ip-addr">15.204.230.233</span>
          <span class="ip-label">Server B</span>
        </a>
      </div>
    </div>
  </body></html>`);
});

app.get("/scan/:ip", async (req, res) => {
  const ip = req.params.ip;
  const results = await scanIP(ip);
  const safe    = results.filter(r => r.allowed);
  const blocked = results.filter(r => !r.allowed);

  res.send(`<html><head>${pageStyles}</head><body>
    <h1>📡 Results: ${ip}</h1>
    <nav><a href="/scan">← Pick another IP</a> &nbsp; <a href="/">Home</a></nav>
    <div class="section">
      <h2>✅ UNBLOCKED (${safe.length})</h2>
      ${renderResults(safe)}
    </div>
    <div class="section">
      <h2>❌ BLOCKED / UNKNOWN (${blocked.length})</h2>
      ${renderResults(blocked)}
    </div>
  </body></html>`);
});

// ─────────────────────────────
// START
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`⚡ Scanner running on port ${PORT}`);
});
