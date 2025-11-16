const fs = require("fs");
const path = require("path");
const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// 🔑 API Keys
const VT_API_KEY = "76d7e13aa9b40e62cd4b096a09a1de19ba6bb70f0e158dd558dfe44c86ab08d0";
const GOOGLE_API_KEY = "AIzaSyD1N9V3fedrSj7lZL9ylv6ZETYascbhRso";
const FIREBASE_DB_URL = "https://cyberscan-logs-default-rtdb.firebaseio.com";

// ✅ Validate URL
function isValidUrl(str) {
  try {
    const url = new URL(str);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

// 📜 Log Input
function logUserInput(ipRaw, ua, route, input) {
  const ip = (ipRaw || "").split(",")[0].trim();
  if (ua && ua.includes("Go-http-client")) return;

  const log = {
    timestamp: new Date().toISOString(),
    ip,
    userAgent: ua,
    route,
    input,
  };

  // 🔥 Firebase
  axios.post(`${FIREBASE_DB_URL}/logs.json`, log)
    .then(() => console.log("✅ Logged to Firebase:", route))
    .catch((err) => console.error("❌ Firebase log error:", err.message));

  // 📝 Local file
  const line = `[${new Date().toLocaleString()}] [${ip}] [${ua}] ${route} -> ${JSON.stringify(input)}\n`;
  fs.appendFile(path.join(__dirname, "logs.txt"), line, (err) => {
    if (err) console.error("❌ Local log error:", err.message);
  });
}

// 🔍 VirusTotal URL Scan
app.post("/scan", async (req, res) => {
  const url = req.body.url;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const ua = req.headers["user-agent"];

  if (!url) return res.status(400).send("Missing URL");
  if (!isValidUrl(url)) return res.status(400).send("Invalid URL");

  logUserInput(ip, ua, "/scan", url);

  try {
    const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    const submitData = await submitRes.json();
    const analysisId = submitData.data.id;

    await new Promise((r) => setTimeout(r, 4000));

    const analysisRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { "x-apikey": VT_API_KEY },
    });

    const data = await analysisRes.json();
    res.json(data);
  } catch (err) {
    console.error("❌ VT scan error:", err.message);
    res.status(500).send("Error scanning");
  }
});

// 🛡️ Google Safe Browsing
app.post("/check-url", async (req, res) => {
  const url = req.body.url;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const ua = req.headers["user-agent"];

  if (!url) return res.status(400).send("Missing URL");
  if (!isValidUrl(url)) return res.status(400).send("Invalid URL");

  logUserInput(ip, ua, "/check-url", url);

  const body = {
    client: { clientId: "cyberscan", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }
    );
    const result = await response.json();
    res.json(result);
  } catch (err) {
    console.error("❌ Google URL check error:", err.message);
    res.status(500).send("Error checking URL");
  }
});

// 🔐 Pwned Passwords
app.post("/check-password", async (req, res) => {
  const password = req.body.password;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const ua = req.headers["user-agent"];

  if (!password) return res.status(400).send("Missing password");

  logUserInput(ip, ua, "/check-password", password);

  try {
    const hash = crypto.createHash("sha1").update(password).digest("hex").toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await response.text();

    const found = text.includes(suffix);
    res.json({ breached: found });
  } catch (err) {
    console.error("❌ Password check error:", err.message);
    res.status(500).send("Error checking password");
  }
});

// 📧 HIBP Email Breach Check
// 📧 Email Breach Check
// 📧 Email Breach Check (no API key, reverse-engineered)
app.post("/check-email", async (req, res) => {
  const email = req.body.email;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const ua = req.headers["user-agent"];

  if (!email) return res.status(400).send("Missing email");
  logUserInput(ip, ua, "/check-email", email);

  try {
    const response = await fetch(
      `https://haveibeenpwned.com/unifiedsearch/${encodeURIComponent(email)}`,
      {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
          "Accept":
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          "Referer": "https://haveibeenpwned.com/"
        },
      }
    );

    const text = await response.text();

    if (response.status === 404) {
      // No breaches for this email
      return res.json({ Breaches: [] });
    }

    if (!response.ok) {
      console.error("❌ HIBP error:", response.status, text);
      return res.status(response.status).send("HIBP request failed");
    }

    // Try parsing JSON safely
    let data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      console.error("❌ Failed to parse HIBP response as JSON:", text);
      return res.status(500).send("Failed to parse HIBP response");
    }

    res.json(data);
  } catch (err) {
    console.error("❌ Email check error:", err.message);
    res.status(500).send("Error checking email");
  }
});

// 🌍 Get user's IP info (via ip-api)
app.get("/ipinfo", async (req, res) => {
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.socket.remoteAddress;
  const ua = req.headers["user-agent"];

  logUserInput(ip, ua, "/ipinfo", "IP lookup");

  try {
    // Use ip-api to fetch IP info for the requester's IP
    const response = await fetch(`http://ip-api.com/json/${ip}`);
    const data = await response.json();

    res.json(data);
  } catch (err) {
    console.error("❌ IP info error:", err.message);
    res.status(500).json({ status: "fail", error: err.message });
  }
});

// 🔁 Redirect Checker Proxy
app.get("/redirect-check", async (req, res) => {
  const { url, timeout = 5, maxhops = 10, meta = 1 } = req.query;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const ua = req.headers["user-agent"];

  if (!url) return res.status(400).send("Missing URL");
  if (!isValidUrl(url)) return res.status(400).send("Invalid URL");

  logUserInput(ip, ua, "/redirect-check", url);

  const apiUrl = `https://api.redirect-checker.net/?url=${encodeURIComponent(
    url
  )}&timeout=${timeout}&maxhops=${maxhops}&meta-refresh=${meta}&format=json`;

  try {
    const response = await fetch(apiUrl);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error("❌ Redirect checker error:", err.message);
    res.status(500).json({ error: "Failed to fetch redirect chain" });
  }
});

// 🌐 Home Page
app.get("/", (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const ua = req.headers["user-agent"];
  logUserInput(ip, ua, "/", "Visited home");

  res.send(`
    <h1>Hello!</h1>
    <p>This website is a school project coded and hosted by <strong>Ranveer</strong>.</p>
    <p>You can scan URLs, check for malware, password leaks, and email breaches here.</p>
  `);
});

// 🚀 Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
