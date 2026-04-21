// index.js — Lightspeed IP Checker (FAST + UI + SAFE)

const express = require("express");
const https = require("https");
const WebSocket = require("ws");

const app = express();
const PORT = process.env.PORT || 10000;

// ─────────────────────────────
// CATEGORY SYSTEM (fallback)
// ─────────────────────────────
const lightspeedjson = [
  { CategoryNumber: 1, CategoryName: "Safe", Allow: 1 },
  { CategoryNumber: 2, CategoryName: "Suspicious", Allow: 0 },
  { CategoryNumber: 3, CategoryName: "Blocked", Allow: 0 },
  { CategoryNumber: 0, CategoryName: "Uncategorized", Allow: 0 }
];

function lightspeedCategorize(num) {
  for (const item of lightspeedjson) {
    if (Number(item.CategoryNumber) === Number(num)) {
      return [item.CategoryName, item.Allow === 1];
    }
  }
  return ["Uncategorized", false];
}

// ─────────────────────────────
// LIGHTSPEED LOOKUP (SAFE + TIMEOUT)
// ─────────────────────────────
async function lightspeed(url) {
  return new Promise((resolve) => {
    let finished = false;

    const ws = new WebSocket(
      "wss://production-gc.lsfilter.com?a=0ef9b862-b74f-4e8d-8aad-be549c5f452a&customer_id=74-1082-F000&agentType=chrome_extension&agentVersion=3.777.0&userGuid=00000000-0000-0000-0000-000000000000"
    );

    const timeout = setTimeout(() => {
      if (!finished) {
        finished = true;
        ws.terminate();
        resolve(["Timeout", false]);
      }
    }, 8000);

    ws.on("open", () => {
      ws.send(JSON.stringify({
        action: "dy_lookup",
        host: url,
        ip: "174.85.104.135",
        customerId: "74-1082-F000",
      }));
    });

    ws.on("message", (msg) => {
      if (finished) return;
      finished = true;

      clearTimeout(timeout);
      ws.close();

      try {
        const json = JSON.parse(msg.toString());
        const result = lightspeedCategorize(json.cat);
        resolve(result);
      } catch {
        resolve(["Error", false]);
      }
    });

    ws.on("error", () => {
      if (!finished) {
        finished = true;
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
            .trim()
            .split("\n")
            .filter(Boolean);

          resolve(domains.length ? domains : [ip]);
        });
      }
    ).on("error", () => resolve([ip]));
  });
}

// ─────────────────────────────
// CHECK IP (FAST + LIMIT 5 + PARALLEL)
// ─────────────────────────────
async function checkIP(ip) {
  console.log(`\n🔍 Checking IP: ${ip}`);

  let domains = await reverseIPLookup(ip);

  // LIMIT TO 5 DOMAINS
  domains = domains.slice(0, 5);

  // RUN IN PARALLEL (FASTER)
  const results = await Promise.all(
    domains.map(async (domain) => {
      const [category, allowed] = await lightspeed(domain);

      console.log(
        `${allowed ? "✅" : "❌"} ${domain} → ${category}`
      );

      return { domain, category, allowed };
    })
  );

  return results;
}

// ─────────────────────────────
// ROUTES
// ─────────────────────────────

app.get("/", (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Lightspeed Checker</title>
      </head>
      <body style="font-family:Arial;background:#0b0b0b;color:white;text-align:center;">
        <h1>⚡ Lightspeed IP Checker</h1>
        <p>Fast scan system (5 domains max per IP)</p>
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
      <title>Scan Results</title>
      <style>
        body { font-family: Arial; background:#0b0b0b; color:white; padding:20px; }
        .ip { margin-top:20px; padding:10px; background:#1c1c1c; border-radius:10px; }
        .box { padding:8px; margin:6px 0; background:#2a2a2a; border-radius:6px; }
        .ok { color:lime; }
        .bad { color:red; }
      </style>
    </head>
    <body>
      <h1>🔍 Scan Running...</h1>
  `;

  for (const ip of ips) {
    html += `<div class="ip"><h2>IP: ${ip}</h2>`;

    const results = await checkIP(ip);

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

  html += `
      <h2>✅ Scan Complete</h2>
      <a href="/" style="color:lime;">Back</a>
    </body>
    </html>
  `;

  res.send(html);
});

// ─────────────────────────────
// START SERVER
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`⚡ Server running on port ${PORT}`);
});
