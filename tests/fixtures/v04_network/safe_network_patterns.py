"""Safe fixture demonstrating secure HTTPS endpoints and standard integer constants."""

import requests

ALLOWED_HOSTS = {"api.github.com", "api.stripe.com"}


def fetch_github_repo(repo_name: str) -> dict[str, str]:
    # 1. Standard public HTTPS endpoint
    url = f"https://api.github.com/repos/{repo_name}"
    resp = requests.get(url, timeout=10)
    return resp.json()  # type: ignore[no-any-return]


def fetch_stripe_customer(cust_id: str) -> dict[str, str]:
    # 2. Standard public HTTPS API with auth
    url = f"https://api.stripe.com/v1/customers/{cust_id}"
    resp = requests.get(url, headers={"Authorization": "Bearer tok_live_test"}, timeout=10)
    return resp.json()  # type: ignore[no-any-return]


def calculate_data_limit() -> int:
    # 3. Standard large integer that is not an IP in a URL
    max_records = 2130706433
    magic_hex = 0xDEADBEEF
    return (max_records ^ magic_hex) & 0xFFFFFFFF


def safe_validated_fetch(user_url: str) -> str:
    # 4. Validated domain check before request
    import urllib.parse

    parsed = urllib.parse.urlparse(user_url)
    if parsed.hostname in ALLOWED_HOSTS and parsed.scheme == "https":
        return requests.get(user_url, timeout=5).text
    raise ValueError("Destination domain is not in the trusted allowlist")
