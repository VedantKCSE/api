from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import ssl
import socket
import whois
import requests
from datetime import datetime
import re
from openai import OpenAI
import os
import json
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLInput(BaseModel):
    url: str

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days
        return f"{age} days"
    except Exception:
        return "Unknown"

def check_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return "Valid"
    except Exception:
        return "Invalid"

def check_https(url):
    return url.startswith("https")

def check_suspicious_keywords(url):
    suspicious_keywords = ["login", "verify", "bank", "update", "security", "confirm", "account", "free", "gift"]
    found = [kw for kw in suspicious_keywords if kw in url.lower()]
    return found

def check_url_structure(url):
    parsed = urlparse(url)
    length = len(url)
    has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.hostname or ""))
    return {
        "url_length": length,
        "contains_ip": has_ip,
        "num_dots": url.count('.')
    }

def get_redirects(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return len(response.history)
    except Exception:
        return "Error"

def get_page_content(url):
    try:
        response = requests.get(url, timeout=5)
        return response.text[:3000]
    except Exception:
        return ""

def compute_risk_score(analysis):
    score = 0
    if analysis["ssl_certificate"] == "Invalid":
        score += 20
    if not analysis["https_used"]:
        score += 15
    if len(analysis["suspicious_keywords"]) > 0:
        score += 20
    if analysis["url_structure"]["contains_ip"]:
        score += 20
    if analysis["url_structure"]["url_length"] > 75:
        score += 10
    if analysis["url_structure"]["num_dots"] > 3:
        score += 10
    if isinstance(analysis["redirect_count"], int) and analysis["redirect_count"] > 2:
        score += 5
    return min(score, 100)

def analyze_with_openai(analysis: dict):
    trimmed_snippet = analysis.get("content_snippet", "")[:300]

    prompt = f"""
You are a helpful assistant that analyzes URLs to check if they are safe or potentially phishing (fake or dangerous websites).

Here is the information about the URL:

- URL: {analysis['url']}
- Domain: {analysis['domain']}
- Domain Age: {analysis['domain_age']}
- SSL Certificate: {analysis['ssl_certificate']}
- HTTPS Used: {analysis['https_used']}
- Suspicious Keywords: {', '.join(analysis['suspicious_keywords'])}
- URL Length: {analysis['url_structure']['url_length']}
- Contains IP Address: {analysis['url_structure']['contains_ip']}
- Number of Dots: {analysis['url_structure']['num_dots']}
- Redirect Count: {analysis['redirect_count']}
- Page Snippet (first 300 characters): {trimmed_snippet}

Now based on this, return a JSON object with:
- "verdict": either "Phishing" or "Safe"
- "reason": explain in simple words why the URL is safe or dangerous. Do not use technical terms. Make sure even someone without technical knowledge can understand.

Only return a valid JSON object. Do not add anything else like explanations, markdown, or notes.
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content

@app.post("/analyze")
def analyze_url(input: URLInput):
    parsed = urlparse(input.url)
    domain = parsed.hostname

    analysis = {
        "url": input.url,
        "domain": domain,
        "domain_age": get_domain_age(domain),
        "ssl_certificate": check_ssl_certificate(domain),
        "https_used": check_https(input.url),
        "suspicious_keywords": check_suspicious_keywords(input.url),
        "url_structure": check_url_structure(input.url),
        "redirect_count": get_redirects(input.url),
        "content_snippet": get_page_content(input.url),
    }

    ai_verdict_raw = analyze_with_openai(analysis)
    try:
        ai_verdict = json.loads(ai_verdict_raw)
    except json.JSONDecodeError:
        ai_verdict = {
            "verdict": "Unknown",
            "reason": "Could not parse AI response."
        }

    return {
        "analysis": analysis,
        "verdict": ai_verdict,
        "is_phishing": ai_verdict.get("verdict", "").lower() == "phishing",
        "risk_score": compute_risk_score(analysis)
    }
