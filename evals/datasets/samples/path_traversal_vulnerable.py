"""Vulnerable sample: Path traversal via unvalidated user input in file open (CWE-22)."""

import os

BASE_DIR = "/var/data/uploads"


def read_user_file(req) -> bytes:
    # VULNERABLE: User input from req.query directly passed into open() without containment check
    with open(os.path.join(BASE_DIR, req.query.get("file")), "rb") as f:
        return f.read()
