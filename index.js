// index.js — SMART + CDN-AWARE LIGHTSPEED SCANNER

const express = require("express");
const https = require("https");
const WebSocket = require("ws");

const app = express();
const PORT = process.env.PORT || 10000;

// ─────────────────────────────
// CATEGORY SYSTEM
// ─────────────────────────────
const lightspeedjson = [
  { CategoryNumber: 1, CategoryName: "Safe", Allow: 1 },
  { CategoryNumber: 2, CategoryName: "Suspicious", Allow: 0 },
  { CategoryNumber: 3, CategoryName: "Blocked", Allow: 0 },
  { CategoryNumber: 0, CategoryName: "Unknown", Allow: 0 }
];

function lightspeedCategorize(num) {
  for (const item of lightspeedjson) {
    if (Number(item.CategoryNumber) === Number(num)) {
      return [item.CategoryName, item.Allow === 1];
    }
  }
  return ["Unknown", false];
}

// ─────────────────────────────
// LIGHTSPEED CHECK (SAFE + TIMEOUT)
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
        resolve(lightspeedCategorize(json.cat));
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
async function reverseIPLookup(ip) {
  return new Promise((resolve) => {
    https.get(
      `https://api.hackertarget.com/reverseiplookup/?q=${ip}`,
      (res) => {
        let data = "";

        res.on("data", chunk => data += chunk);

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
// SMART + CDN SCANNER
// ─────────────────────────────
async function smartCheckIP(ip) {
  console.log(`\n🔍 SMART scanning IP: ${ip}`);

  let allowedResults = [];
  let seen = new Set();

  // ─────────────────────────────
  // CDN / STATIC TARGETS
  // ─────────────────────────────
  const cdnSeeds = [
    "cdn.example.com",
    "static.example.com",
    "assets.example.com",
    "jsdelivr.net",
    "unpkg.com",
    "cloudfront.net",
    "akamai.net",
    "fastly.net"
  ];

  let domains = await reverseIPLookup(ip);
  domains = domains.slice(0, 20);

  const allTargets = [...domains, ...cdnSeeds];

  let attempts = 0;
  const MAX_ATTEMPTS = 3;

  while (allowedResults.length < 5 && attempts < MAX_ATTEMPTS) {
    attempts++;

    console.log(`🔄 Attempt ${attempts}`);

    const batch = allTargets
      .filter(d => !seen.has(d))
      .slice(0, 25);

    batch.forEach(d => seen.add(d));

    const results = await Promise.all(
      batch.map(async (domain) => {
        const [category, allowed] = await lightspeed(domain);

        const result = { domain, category, allowed };

        console.log(
          `${allowed ? "✅ UNBLOCKED" : "❌ BLOCKED"} ${domain} → ${category}`
        );

        if (allowed && allowedResults.length < 5) {
          allowedResults.push(result);
        }

        return result;
      })
    );

    if (allowedResults.length >= 5) break;
  }

  return allowedResults;
}

// ─────────────────────────────
// UI
// ─────────────────────────────

app.get("/", (req, res) => {
  res.send(`
    <html>
      <body style="background:#0b0b0b;color:white;font-family:Arial;text-align:center;">
        <h1>⚡ SMART CDN Scanner</h1>
        <a href="/check" style="color:lime;font-size:20px;">▶ Start Scan</a>
      </body>
    </html>
  `);
});

app.get("/check", async (req, res) => {
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
      </style>
    </head>
    <body>
    <h1>🔍 Smart CDN Scan Running...</h1>
  `;

  for (const ip of ips) {
    html += `<div class="ip"><h2>IP: ${ip}</h2>`;

    const results = await smartCheckIP(ip);

    for (const r of results) {
      html += `
        <div class="box">
          <b>${r.domain}</b><br>
          <span class="${r.allowed ? "ok" : "bad"}">
            ${r.allowed ? "UNBLOCKED" : "BLOCKED"}
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
  console.log(`⚡ Smart CDN Scanner running on port ${PORT}`);
});
