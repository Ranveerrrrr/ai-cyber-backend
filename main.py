from flask import Flask, request, jsonify
import requests
import re

app = Flask(__name__)

@app.route("/")
def home():
    return "AI Cyber Backend is Live!"

@app.route("/scan", methods=["POST"])
def scan_website():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    domain = re.sub(r"https?://", "", url).split("/")[0]
    
    # Mock scan result
    open_ports = ["80 (HTTP)", "443 (HTTPS)"]
    phishing = "login" in url.lower() or "verify" in url.lower()

    return jsonify({
        "domain": domain,
        "ports": open_ports,
        "phishing_detected": phishing
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000)
