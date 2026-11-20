"""HTTP defense-in-depth security headers and Edge CDN/WAF detection."""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class HeaderCheck:
    """Evaluation result for a specific HTTP defense-in-depth security header."""

    name: str
    present: bool
    value: str | None
    recommendation: str
    severity: str


def detect_waf_or_cdn(headers: dict[str, str] | httpx.Headers) -> str | None:
    """Identify Edge CDN or WAF from response headers (Informational only)."""
    normalized = {k.lower(): v.lower() for k, v in headers.items()}
    server = normalized.get("server", "")
    via = normalized.get("via", "")

    if "cf-ray" in normalized or "cloudflare" in server or "cf-cache-status" in normalized:
        return "Cloudflare Edge / WAF"
    if "x-amz-cf-id" in normalized or "x-amz-cf-pop" in normalized or "cloudfront" in via:
        return "AWS CloudFront CDN"
    if "x-fastly-request-id" in normalized or "fastly" in via:
        return "Fastly Edge CDN"
    if "x-akamai-transformed" in normalized or "akamai" in server:
        return "Akamai Edge Platform"
    if "x-vercel-id" in normalized or "vercel" in server:
        return "Vercel Edge Platform"
    if "x-nf-request-id" in normalized or "netlify" in server:
        return "Netlify CDN"
    if "x-iinfo" in normalized or "incapsula" in server or "x-cdn" in normalized:
        return "Imperva / Incapsula WAF"
    if "x-sucuri-id" in normalized or "sucuri" in server:
        return "Sucuri Cloud WAF"
    if "envoy" in server or "x-envoy-upstream-service-time" in normalized:
        return "Envoy Proxy / Edge Ingress"
    if "nginx" in server:
        return "Nginx Web Server / Reverse Proxy"
    if "caddy" in server:
        return "Caddy Web Server"

    return None


def audit_http_security_headers_and_waf(
    target_url: str, timeout: float = 6.0
) -> tuple[list[HeaderCheck], str, str | None]:
    """Probe target server and audit HTTP security defense headers and detect WAF/CDN."""
    checks: list[HeaderCheck] = []
    waf_cdn: str | None = None

    # Determine candidate URLs to probe (smart scheme fallback)
    if target_url.startswith(("http://", "https://")):
        urls_to_try = [target_url]
    else:
        host_part = target_url.split("/")[0].split(":")[0].lower()
        is_local = host_part in ("localhost", "127.0.0.1", "::1")
        has_dev_port = any(f":{p}" in target_url for p in (80, 8080, 3000, 5000, 5173, 8000, 8443))
        if is_local or has_dev_port:
            urls_to_try = [f"http://{target_url}", f"https://{target_url}"]
        else:
            urls_to_try = [f"https://{target_url}", f"http://{target_url}"]

    headers_to_check = [
        (
            "Strict-Transport-Security",
            "Enforces HTTPS for all future visits, defeating SSL-stripping MitM attacks.",
            "max-age=31536000; includeSubDomains; preload",
            "HIGH",
        ),
        (
            "Content-Security-Policy",
            "Restricts script, frame, and style injection to neutralize XSS attacks.",
            "default-src 'self'; script-src 'self'",
            "HIGH",
        ),
        (
            "X-Frame-Options",
            "Prevents clickjacking by blocking unauthorized framing of your web app.",
            "DENY or SAMEORIGIN",
            "MEDIUM",
        ),
        (
            "X-Content-Type-Options",
            "Blocks browser MIME-type sniffing to prevent script execution from uploaded files.",
            "nosniff",
            "MEDIUM",
        ),
        (
            "Referrer-Policy",
            "Protects user privacy and avoids leaking sensitive tokens in Referer headers.",
            "strict-origin-when-cross-origin",
            "LOW",
        ),
        (
            "Permissions-Policy",
            "Controls browser access to camera, microphone, geolocation, and payment APIs.",
            "camera=(), microphone=(), geolocation=()",
            "LOW",
        ),
    ]

    server_headers: httpx.Headers | dict[str, str] | None = None
    for url in urls_to_try:
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
                resp = client.head(url)
                if resp.status_code == 405:
                    resp = client.get(url)
                server_headers = resp.headers
                waf_cdn = detect_waf_or_cdn(server_headers)
                break
        except Exception:
            continue

    if server_headers:
        score_points = 0
        for name, purpose, recommended, sev in headers_to_check:
            header_val = server_headers.get(name)
            is_present = bool(header_val)
            if is_present:
                score_points += 2 if sev == "HIGH" else 1

            checks.append(
                HeaderCheck(
                    name=name,
                    present=is_present,
                    value=header_val,
                    recommendation=f"{purpose} (Recommended: `{recommended}`)",
                    severity=sev,
                )
            )

        # Grade calculation
        max_points = 8
        ratio = score_points / max_points
        if ratio >= 0.9:
            grade = "A+"
        elif ratio >= 0.75:
            grade = "A"
        elif ratio >= 0.6:
            grade = "B"
        elif ratio >= 0.4:
            grade = "C"
        elif ratio >= 0.2:
            grade = "D"
        else:
            grade = "F"

        return checks, grade, waf_cdn

    # Fallback when HTTP call fails across all attempts or host is unreachable
    for name, purpose, recommended, sev in headers_to_check:
        checks.append(
            HeaderCheck(
                name=name,
                present=False,
                value=None,
                recommendation=f"{purpose} (Recommended: `{recommended}`)",
                severity=sev,
            )
        )
    return checks, "F", None


def audit_http_security_headers(
    target_url: str, timeout: float = 6.0
) -> tuple[list[HeaderCheck], str]:
    """Probe target server and audit HTTP security defense headers."""
    checks, grade, _ = audit_http_security_headers_and_waf(target_url, timeout=timeout)
    return checks, grade
