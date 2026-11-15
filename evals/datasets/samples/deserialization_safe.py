"""Safe sample: Safe YAML deserialization with yaml.safe_load (CWE-502 Safe Trap)."""

import yaml


def load_user_config_safe(raw_payload: str) -> dict:
    # SAFE: yaml.safe_load restricts parsing to simple types (scalars, lists, dicts)
    return yaml.safe_load(raw_payload)
