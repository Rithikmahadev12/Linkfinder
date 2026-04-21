// check.js  (for Render)

const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");
const https = require("https");
const express = require("express");

// ✅ Fallback category system (Option 2 — no JSON file needed)
const lightspeedjson = [
  { CategoryNumber: 1, CategoryName: "Safe", Allow: 1 },
  { CategoryNumber: 2, CategoryName: "Suspicious", Allow: 0 },
  { CategoryNumber: 3, CategoryName: "Blocked", Allow: 0 },
  { CategoryNumber: 0, CategoryName: "Uncategorized", Allow: 0 }
];

function lightspeedCategorize(num) {
  for (let i = 0; i < lightspeedjson.length; i++) {
    if (Number(lightspeedjson[i]["CategoryNumber"]) === Number(num)) {
      return [
        lightspeedjson[i]["CategoryName"],
        lightspeedjson[i]["Allow"] === 1
      ];
    }
  }
  return ["Uncategorized", false];
}

async function lightspeed(url) {
  return new Promise((resolve) => {
    const ws = new WebSocket(
      "wss://production-gc.lsfilter.com?a=0ef9b862-b74f-4e8d-8aad-be549c5f452a&customer_id=74-1082-F000&agentType=chrome_extension&agentVersion=3.777.0&userGuid=00000000-0000-0000-0000-000000000000"
    );

    ws.on("open", () => {
      ws.send(JSON.stringify({
        action: "dy_lookup",
        host: url,
        ip: "174.85.104.135",
        customerId: "74-1082-F000",
      }));
    });

    ws.on("message", (msg) => {
      ws.close();
      try {
        const json = JSON.parse(msg.toString());
        const result = lightspeedCategorize(json.cat);
        resolve(result || ["Uncategorized", false]);
      } catch (e) {
        resolve(["Error", false]);
      }
    });

    ws.on("error", () => resolve(["Connection Error", false]));
  });
}

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
            .filter(line => line.trim());
          resolve(domains.length ? domains : [ip]);
        });
      }
    ).on("error", () => resolve([ip]));
  });
}

async function checkIP(ip) {
  console.log(`Checking IP: ${ip}`);
  const domains = await reverseIPLookup(ip);
  const results = [];

  for (const domain of domains) {
    try {
      const [category, allowed] = await lightspeed(domain);
      results.push({ domain, category, allowed });

      console.log(
        `  ${allowed ? "✅" : "❌"} ${domain} → ${category}`
      );
    } catch (err) {
      results.push({
        domain,
        category: "Error",
        allowed: false
      });
    }

    await new Promise(r => setTimeout(r, 800));
  }

  return results;
}

// ─────────────────────────────
// Express Server for Render
// ─────────────────────────────

const app = express();
const PORT = process.env.PORT || 10000;

app.get("/", (req, res) => {
  res.send(`
    <h1>Lightspeed IP Checker</h1>
    <p><a href="/check">Click here to run the scan</a></p>
    <p>System running without lightspeed.json (fallback mode enabled)</p>
  `);
});

app.get("/check", async (req, res) => {
  res.setHeader("Content-Type", "text/plain");
  res.write("Starting Lightspeed scan...\n\n");

  const ips = ["159.195.59.55", "15.204.230.233"];

  for (const ip of ips) {
    res.write(`\n=== Checking IP: ${ip} ===\n`);

    const results = await checkIP(ip);

    results.forEach(r => {
      const status = r.allowed ? "✅ UNBLOCKED" : "❌ BLOCKED";
      res.write(`${status} | ${r.domain} → ${r.category}\n`);
    });
  }

  res.write("\n\n✅ Scan completed!");
  res.end();
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
