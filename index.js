const express = require("express");
const https = require("https");
const WebSocket = require("ws");

const app = express();
const PORT = process.env.PORT || 10000;

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
// LIGHTSPEED LOOKUP (SAFE)
// ─────────────────────────────
async function lightspeed(domain) {
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
        host: domain,
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
        resolve(mapCategory(json.cat));
      } catch {
        resolve(["Error", false]);
      }
    });

    ws.on("error", () => {
      if (!done) {
        done = true;
        clearTimeout(timeout);
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
            .filter(Boolean);

          resolve(domains.length ? domains : [ip]);
        });
      }
    ).on("error", () => resolve([ip]));
  });
}

// ─────────────────────────────
// SCANNER CORE (STABLE + RANKED)
// ─────────────────────────────
async function scanIP(ip) {
  console.log(`\n🔍 Scanning IP: ${ip}`);

  const cdnSeeds = [
    "cdn.example.com",
    "static.example.com",
    "assets.example.com",
    "jsdelivr.net",
    "unpkg.com",
    "cloudfront.net",
    "fastly.net",
    "b-cdn.net"
  ];

  let domains = await reverseIP(ip);

  const targets = [...domains.slice(0, 20), ...cdnSeeds];

  const results = [];

  for (const domain of targets) {
    const [category, allowed] = await lightspeed(domain);

    results.push({
      domain,
      category,
      allowed
    });

    console.log(
      `${allowed ? "✅" : "❌"} ${domain} → ${category}`
    );
  }

  return results;
}

// ─────────────────────────────
// UI
// ─────────────────────────────
app.get("/", (req, res) => {
  res.send(`
    <html>
      <body style="background:#0b0b0b;color:white;font-family:Arial;text-align:center;">
        <h1>⚡ Network Scanner Dashboard</h1>
        <a href="/scan" style="color:lime;font-size:20px;">▶ Start Scan</a>
      </body>
    </html>
  `);
});

app.get("/scan", async (req, res) => {
  const ips = ["159.195.59.55", "15.204.230.233"];

  let html = `
    <html>
    <head>
      <style>
        body { font-family: Arial; background:#0b0b0b; color:white; padding:20px; }
        .ip { margin:20px 0; padding:10px; background:#1c1c1c; border-radius:10px; }
        .box { margin:5px 0; padding:6px; background:#2a2a2a; border-radius:6px; }
        .ok { color:lime; }
        .bad { color:red; }
        .unk { color:orange; }
      </style>
    </head>
    <body>
      <h1>🔍 Scan Running...</h1>
  `;

  for (const ip of ips) {
    html += `<div class="ip"><h2>IP: ${ip}</h2>`;

    const results = await scanIP(ip);

    for (const r of results) {
      const color =
        r.category === "Safe"
          ? "ok"
          : r.category === "Unknown"
          ? "unk"
          : "bad";

      html += `
        <div class="box">
          <b>${r.domain}</b><br>
          <span class="${color}">
            ${r.allowed ? "SAFE" : "BLOCKED"}
          </span>
          → ${r.category}
        </div>
      `;
    }

    html += `</div>`;
  }

  html += `<h2>✅ Scan Complete</h2></body></html>`;
  res.send(html);
});

// ─────────────────────────────
// START SERVER
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`⚡ Scanner running on port ${PORT}`);
});
