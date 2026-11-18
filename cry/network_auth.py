"""Target authorization and audit logging engine for CRY active network checks.

Philosophy:
Never scan, probe, or contact a host the user has not proven they control,
except passive analysis of text found in the scanned project.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from cry.network_ip import (
    is_cloud_metadata,
    is_internal,
    normalize_ip,
)


@dataclass
class TargetAuthorization:
    """Record of verified proof of control for a target host."""

    target: str
    token: str
    created_at: str
    verified_at: str | None = None
    method: str | None = None  # 'dns_txt' or 'well_known'

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetAuthorization:
        return cls(
            target=data.get("target", ""),
            token=data.get("token", ""),
            created_at=data.get("created_at", ""),
            verified_at=data.get("verified_at"),
            method=data.get("method"),
        )


def get_cry_home_dir() -> Path:
    """Return the base ~/.cry directory for local user config and state.

    Falls back to current working directory .cry if ~/.cry is restricted or permission-denied.
    """
    custom = os.environ.get("CRY_HOME")
    if custom:
        p = Path(custom).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    try:
        p = Path.home() / ".cry"
        p.mkdir(parents=True, exist_ok=True)
        test_file = p / ".perm_check"
        test_file.touch()
        test_file.unlink(missing_ok=True)
        return p
    except (PermissionError, OSError):
        p = Path.cwd() / ".cry"
        p.mkdir(parents=True, exist_ok=True)
        return p


def get_authorizations_file() -> Path:
    """Return path to target authorizations file."""
    return get_cry_home_dir() / "authorizations.json"


def get_audit_log_file() -> Path:
    """Return path to network scans audit log."""
    return get_cry_home_dir() / "audit.log"


def load_authorizations() -> dict[str, TargetAuthorization]:
    """Load target authorizations from local JSON storage."""
    try:
        auth_file = get_authorizations_file()
        if not auth_file.exists():
            return {}
        content = auth_file.read_text(encoding="utf-8")
        raw = json.loads(content)
        records: dict[str, TargetAuthorization] = {}
        for target, data in raw.get("targets", {}).items():
            records[target.lower()] = TargetAuthorization.from_dict(data)
        return records
    except Exception:
        return {}


def save_authorizations(records: dict[str, TargetAuthorization]) -> None:
    """Save target authorizations to local JSON storage."""
    try:
        auth_file = get_authorizations_file()
        payload = {"targets": {k: v.to_dict() for k, v in records.items()}}
        auth_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        pass


def get_or_create_authorization(target: str) -> TargetAuthorization:
    """Retrieve existing authorization record or generate a new pending token."""
    records = load_authorizations()
    clean_target = target.strip().lower()
    if clean_target in records:
        return records[clean_target]

    token = f"cry-verify-{secrets.token_hex(12)}"
    now = datetime.now(UTC).isoformat()
    record = TargetAuthorization(
        target=clean_target,
        token=token,
        created_at=now,
        verified_at=None,
        method=None,
    )
    records[clean_target] = record
    save_authorizations(records)
    return record


def is_target_authorized(target: str) -> bool:
    """Check if target has a verified authorization on record."""
    records = load_authorizations()
    clean_target = target.strip().lower()
    record = records.get(clean_target)
    return record is not None and record.verified_at is not None


def revoke_authorization(target: str) -> bool:
    """Remove target authorization from local record."""
    records = load_authorizations()
    clean_target = target.strip().lower()
    if clean_target in records:
        del records[clean_target]
        save_authorizations(records)
        return True
    return False


def query_dns_txt(hostname: str) -> list[str]:
    """Query DNS TXT records using DNS-over-HTTPS fallback or system resolver.

    Mockable for unit tests. In offline environments or test mode, returns empty.
    """
    txt_records: list[str] = []
    # Primary: DoH query to standard RFC-8484 / JSON endpoint (Cloudflare / Google)
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={hostname}&type=TXT"
        headers = {"accept": "application/dns-json"}
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for ans in data.get("Answer", []):
                    if ans.get("type") == 16:  # TXT
                        txt_records.append(str(ans.get("data", "")).strip('"'))
    except Exception:
        pass

    return txt_records


def query_well_known_challenge(
    hostname: str,
    port: int | None = None,
    timeout: float = 4.0,
) -> str | None:
    """Fetch /.well-known/cry-challenge.txt over HTTPS/HTTP, respecting custom target ports."""
    candidates = []
    if port:
        candidates.extend(
            [
                f"http://{hostname}:{port}/.well-known/cry-challenge.txt",
                f"https://{hostname}:{port}/.well-known/cry-challenge.txt",
            ]
        )
    candidates.extend(
        [
            f"https://{hostname}/.well-known/cry-challenge.txt",
            f"http://{hostname}/.well-known/cry-challenge.txt",
        ]
    )

    for url in candidates:
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    return resp.text.strip()
        except Exception:
            continue
    return None


def verify_target_control(target: str, port: int | None = None) -> tuple[bool, str]:
    """Verify ownership of target host via DNS TXT or HTTP well-known path.

    Returns (is_verified, status_message).
    """
    clean_target = target.strip().lower()
    record = get_or_create_authorization(clean_target)
    token = record.token

    # 1. Check DNS TXT records for token
    for host_to_check in [clean_target, f"_cry-challenge.{clean_target}"]:
        txt_records = query_dns_txt(host_to_check)
        for record_val in txt_records:
            if token in record_val or f"cry-verification={token}" in record_val:
                record.verified_at = datetime.now(UTC).isoformat()
                record.method = "dns_txt"
                records = load_authorizations()
                records[clean_target] = record
                save_authorizations(records)
                return True, f"Verified via DNS TXT record on {host_to_check}."

    # 2. Check HTTP well-known path
    well_known_content = query_well_known_challenge(clean_target, port=port)
    if well_known_content and token in well_known_content:
        record.verified_at = datetime.now(UTC).isoformat()
        record.method = "well_known"
        records = load_authorizations()
        records[clean_target] = record
        save_authorizations(records)
        target_display = f"{clean_target}:{port}" if port else clean_target
        return True, f"Verified via HTTP /.well-known/cry-challenge.txt on {target_display}."

    return (
        False,
        "Verification failed: Proof token was not found via DNS TXT or HTTP well-known challenge.",
    )


def log_network_scan_audit(
    target: str,
    resolved_ip: str | None,
    checks_run: list[str],
    is_deep: bool,
    auth_status: str,
) -> None:
    """Append an immutable entry to the local network scan audit log."""
    audit_file = get_audit_log_file()
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": target,
        "resolved_ip": resolved_ip,
        "checks_run": checks_run,
        "is_deep": is_deep,
        "authorization_status": auth_status,
        "caller": os.environ.get("USER") or os.environ.get("USERNAME") or "local_developer",
    }
    try:
        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def check_target_permission(
    target: str,
    allow_local: bool = False,
    pre_resolved_ip: str | None = None,
) -> tuple[bool, str, str | None]:
    """Enforce authorization and safety rules prior to any active network probe.

    Returns:
        (is_allowed, reason_or_status, token_if_unauthorized)
    """
    clean_target = target.strip().lower()
    # Strip protocol if present
    if "://" in clean_target:
        clean_target = re.sub(r"^[a-zA-Z0-9]+://", "", clean_target)
    clean_target = clean_target.split("/")[0]

    # Handle port stripping:
    if clean_target.startswith("[") and "]" in clean_target:
        clean_target = clean_target[1:].split("]")[0]
    elif clean_target.count(":") == 1:
        clean_target = clean_target.split(":")[0]

    norm = normalize_ip(clean_target)
    eval_target = norm or pre_resolved_ip or clean_target

    # 1. Cloud metadata check: NEVER allowed under any circumstances
    if is_cloud_metadata(eval_target):
        return (
            False,
            f"PROHIBITED: Target '{clean_target}' resolves to cloud instance metadata ({eval_target}). Active probing of cloud metadata is strictly forbidden.",
            None,
        )

    # 2. Internal / Loopback / RFC-1918 / Link-Local
    if is_internal(eval_target):
        if not allow_local:
            return (
                False,
                f"Blocked: Target '{clean_target}' ({eval_target}) is in private, loopback, or internal scope. Active scanning of local machines requires explicit '--allow-local'.",
                None,
            )
        return (True, "AUTHORIZED_LOCAL", None)

    # 3. Public Host: Requires explicit verified ownership
    if is_target_authorized(clean_target):
        return (True, "AUTHORIZED_PUBLIC", None)

    # Not authorized: provide token and instructions
    record = get_or_create_authorization(clean_target)
    return (
        False,
        f"Target '{clean_target}' is not authorized. You must prove control of public hosts before probing.",
        record.token,
    )
