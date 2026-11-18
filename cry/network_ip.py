"""IP normalization and SSRF obfuscation detection utility for CRY.

Supports:
- Dotted decimal (standard IPv4: 127.0.0.1, 169.254.169.254)
- Dword / Integer decimal notation (2130706433 -> 127.0.0.1, 2852039166 -> 169.254.169.254)
- Hexadecimal single-integer notation (0x7f000001 -> 127.0.0.1, 0xa9fea9fe -> 169.254.169.254)
- Dotted hexadecimal notation (0x7f.0x0.0x0.0x1 -> 127.0.0.1)
- Dotted octal notation (0177.0.0.1 -> 127.0.0.1, 0251.0376.0251.0376 -> 169.254.169.254)
- IPv6-mapped IPv4 notation (::ffff:127.0.0.1 -> 127.0.0.1, ::ffff:169.254.169.254)
- Cloud IMDS addresses (169.254.169.254, fd00:ec2::254)
- BSD shortened IPv4 formats (127.1 -> 127.0.0.1, 10.1 -> 10.0.0.1)
"""

import ipaddress
import re
from typing import Any

# Known Cloud Instance Metadata Service (IMDS) IPs
CLOUD_METADATA_IPS: set[str] = {
    "169.254.169.254",  # AWS, GCP, Azure, OpenStack IPv4 IMDS
    "169.254.169.253",  # Azure wire server DNS
    "fd00:ec2::254",  # AWS IMDSv2 IPv6 (official AWS documentation)
}

# Regex to detect possible obfuscated IP patterns in URLs or raw strings
OBFUSCATED_IP_TOKEN_REGEX = re.compile(
    r"""(?xi)
    (?:
        \b0x[0-9a-f]{1,8}\b                     # 32-bit hex (0x7f000001)
        |
        \b(?:0x[0-9a-f]{1,2}\.){3}0x[0-9a-f]{1,2}\b  # dotted hex
        |
        \b(?:0[0-7]{1,4}\.){1,3}(?:0[0-7]{1,4}|[0-9]{1,3})\b # dotted octal (0177.0.0.1)
        |
        \b(?:2130706433|2852039166|[1-9][0-9]{8,9})\b        # dword decimal
        |
        ::ffff:(?:[0-9]{1,3}\.){3}[0-9]{1,3}   # IPv6-mapped IPv4
        |
        \bfd00:ec2::254\b                       # AWS IMDS IPv6
    )
    """
)


def _parse_octet(part: str) -> int | None:
    """Parse a single octet which may be decimal, octal (0...), or hex (0x...)."""
    p = part.strip()
    if not p:
        return None
    try:
        if p.lower().startswith("0x"):
            val = int(p, 16)
        elif len(p) > 1 and p.startswith("0") and all(c in "01234567" for c in p):
            val = int(p, 8)
        elif p.isdigit():
            val = int(p, 10)
        else:
            return None
        return val
    except (ValueError, OverflowError):
        return None


def normalize_ip_address(
    value: str | int | Any,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse and normalize any standard or obfuscated IP format into an IPv4Address or IPv6Address.

    Returns None for malformed or non-IP inputs.
    """
    if isinstance(value, (int, float)):
        try:
            int_val = int(value)
            if 0 <= int_val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(int_val)
        except Exception:
            return None
        return None

    if not isinstance(value, str):
        return None

    raw = value.strip().strip("'\"`<>[]")
    if not raw:
        return None

    # 1. Check for standard IPv4 / IPv6 parse via ipaddress
    try:
        addr = ipaddress.ip_address(raw)
        # Extract underlying IPv4 if IPv6-mapped (e.g. ::ffff:127.0.0.1)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return addr.ipv4_mapped
        return addr
    except ValueError:
        pass

    # 2. Check for single 32-bit Hexadecimal notation (0x7f000001, 0xa9fea9fe)
    if raw.lower().startswith("0x"):
        try:
            int_val = int(raw, 16)
            if 0 <= int_val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(int_val)
        except (ValueError, OverflowError):
            pass

    # 3. Check for single 32-bit Dword Decimal notation (2130706433, 2852039166)
    if raw.isdigit():
        try:
            int_val = int(raw, 10)
            if 0 <= int_val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(int_val)
        except (ValueError, OverflowError):
            pass

    # 4. Check for Dotted Notation with mixed bases (Hex 0x.., Octal 0.., Decimal)
    if "." in raw:
        parts = raw.split(".")
        # Handle 4-part dotted (e.g., 0177.0.0.1, 0x7f.0.0.1, 0251.0376.0251.0376)
        if len(parts) == 4:
            octets: list[int] = []
            for p in parts:
                o = _parse_octet(p)
                if o is None or not (0 <= o <= 255):
                    octets = []
                    break
                octets.append(o)
            if len(octets) == 4:
                packed = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
                return ipaddress.IPv4Address(packed)

        # Handle 2-part BSD shortened notation (e.g., 127.1 -> 127.0.0.1)
        elif len(parts) == 2:
            o1 = _parse_octet(parts[0])
            o2 = _parse_octet(parts[1])
            if o1 is not None and o2 is not None and 0 <= o1 <= 255 and 0 <= o2 <= 0xFFFFFF:
                packed = (o1 << 24) | o2
                return ipaddress.IPv4Address(packed)

        # Handle 3-part BSD shortened notation (e.g., 127.0.1 -> 127.0.0.1)
        elif len(parts) == 3:
            o1 = _parse_octet(parts[0])
            o2 = _parse_octet(parts[1])
            o3 = _parse_octet(parts[2])
            if (
                o1 is not None
                and o2 is not None
                and o3 is not None
                and 0 <= o1 <= 255
                and 0 <= o2 <= 255
                and 0 <= o3 <= 0xFFFF
            ):
                packed = (o1 << 24) | (o2 << 16) | o3
                return ipaddress.IPv4Address(packed)

    return None


def normalize_ip(value: str | int | Any) -> str | None:
    """Normalize any standard or obfuscated IP representation to a canonical string (e.g. '127.0.0.1')."""
    addr = normalize_ip_address(value)
    if addr is not None:
        return str(addr)
    return None


def is_cloud_metadata(ip_or_host: str) -> bool:
    """Check if address is a known cloud provider instance metadata service (IMDS) IP."""
    norm = normalize_ip(ip_or_host)
    if norm and norm in CLOUD_METADATA_IPS:
        return True
    clean = ip_or_host.strip().lower().strip("[]")
    return clean in CLOUD_METADATA_IPS


def is_loopback(ip_or_host: str) -> bool:
    """Check if address is local loopback (127.0.0.0/8, ::1, or localhost)."""
    clean = ip_or_host.strip().lower()
    if clean in ("localhost", "127.0.0.1", "::1"):
        return True
    addr = normalize_ip_address(ip_or_host)
    if addr is not None:
        return addr.is_loopback
    return False


def is_private_rfc1918(ip_or_host: str) -> bool:
    """Check if address belongs to private RFC-1918 (10/8, 172.16/12, 192.168/16) or ULA (fc00::/7)."""
    addr = normalize_ip_address(ip_or_host)
    if addr is not None:
        return addr.is_private and not addr.is_loopback and not addr.is_link_local
    return False


def is_link_local(ip_or_host: str) -> bool:
    """Check if address is link-local (169.254.0.0/16 or fe80::/10)."""
    addr = normalize_ip_address(ip_or_host)
    if addr is not None:
        return addr.is_link_local
    return False


def is_internal(ip_or_host: str) -> bool:
    """Check if address or hostname is non-routable, internal, private, loopback, or cloud metadata."""
    clean = ip_or_host.strip().lower()
    if clean in ("localhost", "0.0.0.0", "::", "::1"):
        return True
    if any(clean.endswith(sfx) for sfx in (".local", ".internal", ".lan", ".corp", ".home")):
        return True
    if is_cloud_metadata(clean):
        return True
    addr = normalize_ip_address(ip_or_host)
    if addr is not None:
        return (
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or str(addr) in CLOUD_METADATA_IPS
        )
    return False


def get_ip_classification(ip_or_host: str) -> str:
    """Return a descriptive security category for the given IP address or hostname."""
    clean = ip_or_host.strip().lower()
    if is_cloud_metadata(clean):
        return "Cloud IMDS Metadata"
    if is_loopback(clean):
        return "Loopback"
    if is_link_local(clean):
        return "Link-Local"
    if is_private_rfc1918(clean):
        return "RFC-1918 Private"
    if any(clean.endswith(sfx) for sfx in (".local", ".internal", ".lan", ".corp", ".home")):
        return "Internal Hostname"

    addr = normalize_ip_address(clean)
    if addr is not None:
        if addr.is_global:
            return "Public Routable"
        if addr.is_multicast:
            return "Multicast"
        if addr.is_reserved:
            return "Reserved"

    return "External Host"


def detect_ip_obfuscation(raw_candidate: str) -> tuple[bool, str | None, str | None]:
    """Detect if a raw string uses an obfuscated IP representation to evade string-matching SSRF defenses.

    Returns:
        (is_obfuscated, normalized_ip, evasion_description)
    """
    clean = raw_candidate.strip().strip("'\"`<>[]")
    if not clean:
        return False, None, None

    # Case 1: Dword Decimal (e.g. 2130706433, 2852039166)
    if clean.isdigit() and len(clean) >= 8:
        norm = normalize_ip(clean)
        if norm and norm != clean:
            return True, norm, f"Dword integer decimal notation ({clean} -> {norm})"

    # Case 2: Hexadecimal (e.g. 0x7f000001, 0xa9fea9fe, 0x7f.0.0.1)
    if "0x" in clean.lower():
        norm = normalize_ip(clean)
        if norm and norm != clean:
            return True, norm, f"Hexadecimal notation ({clean} -> {norm})"

    # Case 3: Dotted Octal (e.g. 0177.0.0.1, 0251.0376.0251.0376)
    if "." in clean and any(
        part.startswith("0") and len(part) > 1 and part.isdigit() for part in clean.split(".")
    ):
        norm = normalize_ip(clean)
        if norm and norm != clean:
            return True, norm, f"Dotted octal notation ({clean} -> {norm})"

    # Case 4: IPv6-mapped IPv4 (e.g. ::ffff:127.0.0.1)
    if "::ffff:" in clean.lower():
        norm = normalize_ip(clean)
        if norm and norm != clean:
            return True, norm, f"IPv6-mapped IPv4 notation ({clean} -> {norm})"

    return False, None, None
