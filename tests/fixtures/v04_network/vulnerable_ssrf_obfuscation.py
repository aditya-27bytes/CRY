"""Vulnerable fixture demonstrating cloud metadata leaks and obfuscated IP SSRF bypasses."""

import urllib.request

import requests


def fetch_aws_metadata_v4() -> str:
    # 1. Hardcoded cloud metadata IPv4 (AWS/GCP/Azure IMDS)
    url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    return requests.get(url, timeout=5).text


def fetch_aws_metadata_v6() -> str:
    # 2. Hardcoded cloud metadata IPv6 (AWS IMDSv2 fd00:ec2::254)
    url = "http://[fd00:ec2::254]/latest/meta-data/"
    return requests.get(url, timeout=5).text


def fetch_link_local_config() -> str:
    # 3. Hardcoded generic link-local IP
    endpoint = "http://169.254.42.1/host-config.json"
    return requests.get(endpoint, timeout=5).text


def fetch_internal_service_decimal() -> str:
    # 4. Obfuscated Dword Decimal SSRF (2130706433 normalizes to 127.0.0.1)
    target = "http://2130706433:8000/admin/secrets"
    return requests.get(target, timeout=5).text


def fetch_internal_service_hex() -> str:
    # 5. Obfuscated Hexadecimal SSRF (0x7f000001 normalizes to 127.0.0.1)
    target = "http://0x7f000001:5000/private"
    return requests.get(target, timeout=5).text


def fetch_internal_service_octal() -> str:
    # 6. Obfuscated Octal Dotted SSRF (0177.0.0.1 normalizes to 127.0.0.1)
    target = "http://0177.0.0.1:9000/internal-metrics"
    return requests.get(target, timeout=5).text


def fetch_metadata_dword() -> str:
    # 7. Obfuscated Dword Decimal metadata SSRF (2852039166 normalizes to 169.254.169.254)
    target = "http://2852039166/latest/user-data"
    return urllib.request.urlopen(target).read().decode()


def fetch_internal_service_ipv6_mapped() -> str:
    # 8. Obfuscated IPv6-mapped IPv4 SSRF (::ffff:127.0.0.1 normalizes to 127.0.0.1)
    target = "http://[::ffff:127.0.0.1]:8080/internal"
    return requests.get(target, timeout=5).text
