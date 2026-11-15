"""Safe sample: Path traversal safe trap with strict path containment check (CWE-22 Safe Trap)."""

from pathlib import Path

BASE_DIR = Path("/var/data/uploads").resolve()


def read_user_file_safe(filename: str) -> bytes:
    # SAFE: Verifies canonical resolved path stays strictly within BASE_DIR
    clean_name = Path(filename).name
    target_path = (BASE_DIR / clean_name).resolve()
    if not target_path.is_relative_to(BASE_DIR):
        raise PermissionError("Access denied: path traversal attempt detected.")
    with open(target_path, "rb") as f:
        return f.read()
