const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const VT_API_KEY = "82e62a710af4abcd481965e951ccd9c585a49ad3b79e420f9e00f5fea97eb43e";

app.post("/scan", async (req, res) => {
  const url = req.body.url;
  if (!url) return res.status(400).send("Missing URL");

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

    const analysisRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { "x-apikey": VT_API_KEY },
      }
    );

    const data = await analysisRes.json();
    res.json(data);
  } catch (err) {
    console.error("Scan error:", err);
    res.status(500).send("Error scanning");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
