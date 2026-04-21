const express = require("express");
const https = require("https");
const WebSocket = require("ws");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────
// CATEGORY MAP
// ─────────────────────────────
const categories = [
  { id: 1, name: "Safe", allow: true },
  { id: 2, name: "Suspicious", allow: false },
  { id: 3, name: "Blocked", allow: false },
  { id: 0, name: "Unknown", allow: false }
];

function mapCategory(num) {
  for (const c of categories) {
    if (Number(c.id) === Number(num)) {
      return [c.name, c.allow];
    }
  }
  return ["Unknown", false];
}

// ─────────────────────────────
// EXTRACT HOSTNAME FROM URL OR DOMAIN
// ─────────────────────────────
function extractHostname(input) {
  input = input.trim();
  try {
    // If it looks like a URL, parse it
    if (input.startsWith("http://") || input.startsWith("https://")) {
      return new URL(input).hostname;
    }
    // Strip any path manually
    return input.split("/")[0].toLowerCase();
  } catch {
    return input.toLowerCase();
  }
}

// ─────────────────────────────
// LIGHTSPEED LOOKUP
// ─────────────────────────────
async function lightspeed(domain) {
  // Always use the exact hostname, not a base domain
  const host = extractHostname(domain);

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
        action: "dy_lookup",
        host: host,           // ← full subdomain, e.g. ultralink4225.b-cdn.net
        ip: "174.85.104.135",
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
            .filter(x => !x.toLowerCase().startsWith("error")); // ignore API error messages

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
  let domains = await reverseIP(ip);
  // Take up to 30 actual reverse-IP results (no generic seeds)
  const targets = domains.slice(0, 30).map(d => extractHostname(d));
  return scanDomains(targets);
}

// ─────────────────────────────
// RENDER RESULTS TABLE
// ─────────────────────────────
function renderResults(results) {
  if (!results.length) return `<p style="color:orange">No results found.</p>`;

  return results.map(r => {
    const color = r.category === "Safe" ? "ok" : r.category === "Unknown" ? "unk" : "bad";
    return `
      <div class="box">
        <b>${r.domain}</b><br>
        <span class="${color}">${r.allowed ? "✅ SAFE" : "❌ BLOCKED"}</span>
        → <i>${r.category}</i>
      </div>
    `;
  }).join("");
}

// ─────────────────────────────
// UI / ROUTES
// ─────────────────────────────
const pageStyles = `
  <style>
    body { font-family: 'Courier New', monospace; background:#0b0b0b; color:white; padding:30px; max-width:900px; margin:0 auto; }
    h1 { color:lime; letter-spacing:2px; }
    h2 { color:#aaa; font-size:14px; }
    .section { margin:20px 0; padding:15px; background:#1c1c1c; border-radius:10px; border:1px solid #333; }
    .box { margin:6px 0; padding:10px; background:#2a2a2a; border-radius:6px; font-size:13px; }
    .ok  { color:lime; font-weight:bold; }
    .bad { color:red;  font-weight:bold; }
    .unk { color:orange; font-weight:bold; }
    input, textarea {
      background:#111; color:white; border:1px solid #444; border-radius:6px;
      padding:8px 12px; font-family:monospace; font-size:14px; width:100%; box-sizing:border-box;
    }
    textarea { height:100px; resize:vertical; }
    button {
      margin-top:10px; padding:10px 24px; background:lime; color:black;
      border:none; border-radius:6px; font-weight:bold; font-size:15px; cursor:pointer;
    }
    button:hover { background:#00cc00; }
    a { color:lime; }
    nav { margin-bottom:30px; }
    nav a { margin-right:20px; font-size:16px; }
  </style>
`;

app.get("/", (req, res) => {
  res.send(`
    <html><head>${pageStyles}</head><body>
      <h1>⚡ Network Scanner</h1>
      <nav>
        <a href="/check">🔗 Check Domains/URLs</a>
        <a href="/scan">📡 Scan by IP</a>
      </nav>
      <div class="section">
        <p>Use <b>Check Domains/URLs</b> to test specific links (like CDN subdomains).</p>
        <p>Use <b>Scan by IP</b> to reverse-lookup an IP and test all its domains.</p>
      </div>
    </body></html>
  `);
});

// ─── CHECK: specific domains/URLs ───
app.get("/check", (req, res) => {
  res.send(`
    <html><head>${pageStyles}</head><body>
      <h1>🔗 Check Domains / URLs</h1>
      <nav><a href="/">← Home</a></nav>
      <div class="section">
        <p>Paste one domain or URL per line. Full subdomains work — e.g. <code>ultralink4225.b-cdn.net</code></p>
        <form method="POST" action="/check">
          <textarea name="domains" placeholder="ultralink4225.b-cdn.net&#10;https://example.com/page&#10;cdn.something.net"></textarea>
          <button type="submit">▶ Check</button>
        </form>
      </div>
    </body></html>
  `);
});

app.post("/check", async (req, res) => {
  const raw = (req.body.domains || "").trim();
  const lines = raw.split("\n").map(x => x.trim()).filter(Boolean);

  if (!lines.length) {
    return res.redirect("/check");
  }

  const results = await scanDomains(lines);
  const safe = results.filter(r => r.allowed);
  const blocked = results.filter(r => !r.allowed);

  res.send(`
    <html><head>${pageStyles}</head><body>
      <h1>🔗 Check Results</h1>
      <nav><a href="/check">← Check another</a> &nbsp; <a href="/">Home</a></nav>

      <div class="section">
        <h2>✅ UNBLOCKED (${safe.length})</h2>
        ${safe.length ? renderResults(safe) : '<p style="color:#666">None found.</p>'}
      </div>

      <div class="section">
        <h2>❌ BLOCKED / UNKNOWN (${blocked.length})</h2>
        ${blocked.length ? renderResults(blocked) : '<p style="color:#666">None.</p>'}
      </div>
    </body></html>
  `);
});

// ─── SCAN: by IP ───
app.get("/scan", (req, res) => {
  res.send(`
    <html><head>${pageStyles}</head><body>
      <h1>📡 Scan by IP</h1>
      <nav><a href="/">← Home</a></nav>
      <div class="section">
        <p>Enter an IP to reverse-lookup and scan all associated domains.</p>
        <form method="POST" action="/scan">
          <input type="text" name="ip" placeholder="e.g. 159.195.59.55" />
          <button type="submit">▶ Scan</button>
        </form>
      </div>
    </body></html>
  `);
});

app.post("/scan", async (req, res) => {
  const ip = (req.body.ip || "").trim();
  if (!ip) return res.redirect("/scan");

  const results = await scanIP(ip);
  const safe = results.filter(r => r.allowed);
  const blocked = results.filter(r => !r.allowed);

  res.send(`
    <html><head>${pageStyles}</head><body>
      <h1>📡 Scan Results: ${ip}</h1>
      <nav><a href="/scan">← Scan another</a> &nbsp; <a href="/">Home</a></nav>

      <div class="section">
        <h2>✅ UNBLOCKED (${safe.length})</h2>
        ${safe.length ? renderResults(safe) : '<p style="color:#666">None found.</p>'}
      </div>

      <div class="section">
        <h2>❌ BLOCKED / UNKNOWN (${blocked.length})</h2>
        ${blocked.length ? renderResults(blocked) : '<p style="color:#666">None.</p>'}
      </div>
    </body></html>
  `);
});

// ─────────────────────────────
// START
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`⚡ Scanner running on port ${PORT}`);
});
