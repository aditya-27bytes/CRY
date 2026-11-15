"""Safe sample: Subprocess execution using parameterized arguments without shell=True (CWE-78 Safe Trap)."""

import subprocess


def ping_host_safe(user_host: str) -> None:
    # SAFE: Array arguments with shell=False prevent shell metacharacter interpretation
    clean_host = user_host.strip()
    subprocess.run(["ping", "-c", "1", clean_host], shell=False, check=False)
