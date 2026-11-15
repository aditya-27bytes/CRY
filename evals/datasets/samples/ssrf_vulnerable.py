"""Vulnerable sample: Unvalidated user URL passed directly to HTTP client (CWE-918)."""

import requests


def fetch_remote_resource(req) -> str:
    # VULNERABLE: Direct user query parameter passed into requests.get enables SSRF to metadata 169.254.169.254
    return requests.get(req.query.get("target_url"), timeout=5).text
