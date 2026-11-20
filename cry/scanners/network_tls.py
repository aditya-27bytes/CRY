"""SSL/TLS certificate inspection and cipher suite review."""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

WEAK_CIPHER_REGEX = re.compile(
    r"""\b(?:RC4|3DES|DES|MD5|NULL|EXPORT|CBC)\b""",
    re.IGNORECASE,
)


@dataclass
class SSLCertificateInfo:
    """Live SSL/TLS certificate attributes and cipher suite telemetry."""

    issuer: str
    subject: str
    valid_from: str
    valid_to: str
    days_remaining: int
    is_expired: bool
    tls_version: str
    cipher_suite: str
    weak_ciphers: list[str] = field(default_factory=list)
    legacy_protocols_supported: list[str] = field(default_factory=list)
    platform_limitation_note: str | None = None


def inspect_ssl_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    connect_host: str | None = None,
    check_legacy: bool = False,
) -> SSLCertificateInfo | None:
    """Connect via TLS socket and extract live certificate telemetry and cipher review."""
    context = ssl.create_default_context()
    context.check_hostname = True
    dest = connect_host or hostname

    try:
        with (
            socket.create_connection((dest, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cert: dict[str, Any] = ssock.getpeercert() or {}
            cipher = ssock.cipher()
            tls_version = ssock.version() or "Unknown"

            # Parse issuer
            issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
            issuer_name = (
                issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"
            )

            # Parse subject
            subject_dict = dict(x[0] for x in cert.get("subject", ()))
            subject_name = subject_dict.get("commonName") or "Unknown"

            # Parse expiration date
            not_after_str = cert.get("notAfter", "")
            days_left = 0
            is_expired = False
            valid_to_display = not_after_str

            if not_after_str:
                try:
                    # Format: 'May 15 12:00:00 2026 GMT'
                    expire_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=UTC
                    )
                    now_dt = datetime.now(UTC)
                    delta = expire_dt - now_dt
                    days_left = delta.days
                    is_expired = days_left < 0
                    valid_to_display = expire_dt.strftime("%Y-%m-%d %H:%M UTC")
                except Exception:
                    pass

            cipher_name = cipher[0] if cipher else "Unknown"
            weak_ciphers: list[str] = []
            if cipher_name != "Unknown" and WEAK_CIPHER_REGEX.search(cipher_name):
                weak_ciphers.append(cipher_name)

            legacy_protocols: list[str] = []
            platform_note: str | None = None
            if check_legacy:
                platform_note = (
                    "Probing legacy protocols (TLS 1.0/1.1) depends on host platform OpenSSL security level. "
                    "If system OpenSSL enforces SECLEVEL >= 2, legacy handshakes are refused by local crypto runtime."
                )
                for ver_name, ver_enum in [
                    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
                ]:
                    if ver_enum is None:
                        continue
                    try:
                        leg_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        leg_ctx.check_hostname = False
                        leg_ctx.verify_mode = ssl.CERT_NONE
                        leg_ctx.minimum_version = ver_enum
                        leg_ctx.maximum_version = ver_enum
                        with (
                            socket.create_connection((dest, port), timeout=timeout) as lsock,
                            leg_ctx.wrap_socket(lsock, server_hostname=hostname),
                        ):
                            legacy_protocols.append(ver_name)
                    except Exception:
                        pass

            return SSLCertificateInfo(
                issuer=issuer_name,
                subject=subject_name,
                valid_from=cert.get("notBefore", "Unknown"),
                valid_to=valid_to_display,
                days_remaining=days_left,
                is_expired=is_expired,
                tls_version=tls_version,
                cipher_suite=cipher_name,
                weak_ciphers=weak_ciphers,
                legacy_protocols_supported=legacy_protocols,
                platform_limitation_note=platform_note,
            )
    except Exception:
        return None
