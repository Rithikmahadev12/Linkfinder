// index.js — SMART Lightspeed Scanner

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
// LIGHTSPEED LOOKUP (SAFE + TIMEOUT)
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
// MULTI-SOURCE REVERSE IP (SMARTER)
// ─────────────────────────────
async function reverseIPLookup(ip) {
  const urls = [
    `https://api.hackertarget.com/reverseiplookup/?q=${ip}`,
    `https://api.viewdns.info/reverseip/?host=${ip}&apikey=free`
  ];

  for (const url of urls) {
    const data = await new Promise((resolve) => {
      https.get(url, (res) => {
        let body = "";
        res.on("data", c => body += c);
        res.on("end", () => resolve(body));
      }).on("error", () => resolve(""));
    });

    const domains = data
      .split("\n")
      .map(x => x.trim())
      .filter(Boolean)
      .filter(x => !x.includes("error"));

    if (domains.length > 0) return domains;
  }

  return [ip];
}

// ─────────────────────────────
// SMART SCANNER (FINDS 5 UNBLOCKED)
// ─────────────────────────────
async function smartCheckIP(ip, sendProgress) {
  console.log(`\n🔍 SMART scanning IP: ${ip}`);

  let seen = new Set();
  let allowedResults = [];
  let attempts = 0;
  const MAX_ATTEMPTS = 3;

  while (allowedResults.length < 5 && attempts < MAX_ATTEMPTS) {
    attempts++;

    let domains = await reverseIPLookup(ip);

    // expand pool if needed
    domains = domains.slice(0, 20);

    // filter duplicates
    domains = domains.filter(d => !seen.has(d));
    domains.forEach(d => seen.add(d));

    console.log(`🔄 Attempt ${attempts}, scanning ${domains.length} domains`);

    // parallel scan (faster)
    const results = await Promise.all(
      domains.map(async (domain) => {
        const [category, allowed] = await lightspeed(domain);

        const result = { domain, category, allowed };

        if (allowed && allowedResults.length < 5) {
          allowedResults.push(result);
        }

        sendProgress(result, allowedResults.length);

        return result;
      })
    );

    if (allowedResults.length >= 5) break;
  }

  return allowedResults;
}

// ─────────────────────────────
// UI ROUTES
// ─────────────────────────────

app.get("/", (req, res) => {
  res.send(`
    <html>
    <body style="background:#0b0b0b;color:white;font-family:Arial;text-align:center;">
      <h1>⚡ SMART Lightspeed Scanner</h1>
      <a href="/check" style="color:lime;font-size:20px;">▶ Start Smart Scan</a>
    </body>
    </html>
  `);
});

app.get("/check", async (req, res) => {
  const ips = ["159.195.59.55", "15.204.230.233"];

  res.setHeader("Content-Type", "text/html");

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
    <h1>🔍 Smart Scan Running...</h1>
  `;

  for (const ip of ips) {
    html += `<div class="ip"><h2>IP: ${ip}</h2>`;

    const results = await smartCheckIP(ip, (result, count) => {
      console.log(`Progress: ${count}/5 allowed`);
    });

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

  html += `<h2>✅ Smart Scan Complete</h2></body></html>`;

  res.send(html);
});

// ─────────────────────────────
// START
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`⚡ SMART scanner running on port ${PORT}`);
});
