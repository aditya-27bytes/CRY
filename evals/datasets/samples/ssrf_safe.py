"""Safe sample: Outbound HTTP request to hardcoded trusted host (CWE-918 Safe Trap)."""

import requests

BASE_API_URL = "https://api.github.com/v1"


def fetch_github_status(endpoint: str) -> dict:
    # SAFE: Fixed trusted API base URL prevents SSRF to internal/cloud metadata networks
    clean_endpoint = endpoint.lstrip("/")
    url = f"{BASE_API_URL}/{clean_endpoint}"
    resp = requests.get(url, timeout=5)
    return resp.json()
