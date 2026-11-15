"""Vulnerable sample: Unsanitized user input concatenated into system command (CWE-78)."""

import os


def ping_host(user_host: str) -> None:
    # VULNERABLE: Direct string concatenation into os.system enables command injection
    cmd = "ping -c 1 " + user_host
    os.system(cmd)
