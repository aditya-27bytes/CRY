"""Real-app benchmark configuration for CRY accuracy evaluations.

Configures target open-source benchmark applications:
- OWASP NodeGoat (Node.js/Express)
- OWASP Juice Shop (TypeScript/Angular/Express)
- OWASP DVWA (Damn Vulnerable Web Application testing ground)
"""

from dataclasses import dataclass


@dataclass
class RealAppTarget:
    name: str
    repo_url: str
    description: str
    target_cwe: list[str]
    sample_paths: list[str]


REAL_APPS: list[RealAppTarget] = [
    RealAppTarget(
        name="OWASP Juice Shop",
        repo_url="https://github.com/juice-shop/juice-shop",
        description="Vulnerable modern web app (TypeScript/Express) covering OWASP Top 10",
        target_cwe=["CWE-89", "CWE-601", "CWE-798"],
        sample_paths=[
            "evals/datasets/samples/sqli_vulnerable.ts",
            "evals/datasets/samples/open_redirect.ts",
            "evals/datasets/samples/secrets_vulnerable.ts",
        ],
    ),
    RealAppTarget(
        name="OWASP NodeGoat",
        repo_url="https://github.com/OWASP/NodeGoat",
        description="Node.js/Express security benchmarking app",
        target_cwe=["CWE-94", "CWE-78", "CWE-22"],
        sample_paths=[
            "evals/datasets/samples/cmdi_vulnerable.py",
            "evals/datasets/samples/path_traversal_vulnerable.py",
        ],
    ),
    RealAppTarget(
        name="OWASP DVWA",
        repo_url="https://github.com/digininja/DVWA",
        description="Damn Vulnerable Web Application testing ground",
        target_cwe=["CWE-78", "CWE-22", "CWE-502", "CWE-918"],
        sample_paths=[
            "evals/datasets/samples/deserialization_vulnerable.py",
            "evals/datasets/samples/ssrf_vulnerable.py",
        ],
    ),
]
