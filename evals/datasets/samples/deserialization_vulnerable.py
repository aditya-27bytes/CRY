"""Vulnerable sample: Insecure PyYAML deserialization with unsafe loader (CWE-502)."""

import yaml


def load_user_config(raw_payload: str) -> dict:
    # VULNERABLE: yaml.load with default or standard Loader allows arbitrary Python object instantiation
    return yaml.load(raw_payload, Loader=yaml.Loader)
