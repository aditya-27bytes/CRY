# ==============================================================================
# CRY SYNTHETIC TEST FIXTURE — STRICTLY FOR AUTOMATED TESTING & BENCHMARKS
# ==============================================================================
# ⚠️ DO NOT USE IN PRODUCTION — THIS FILE CONTAINS INTENTIONALLY INSECURE CODE.
#
# IMPORTANT NOTICE REGARDING CREDENTIALS & SECRETS:
# • NONE of the secret keys, tokens, or credentials below are genuine or active.
# • All credential strings are standard public synthetic examples from official
#   documentation (e.g. AWS documentation sample AKIA key format and
#   official Stripe documentation test key formats).
# • PRODUCTION SECURITY RULE: In real applications, secrets and credentials must
#   NEVER be hardcoded in source files. Always store genuine secrets in a
#   gitignored '.env' file or a cloud secret manager (AWS Secrets Manager,
#   GCP Secret Manager, HashiCorp Vault).
# ==============================================================================

import os
import pickle
import subprocess

# ── Secret Exposure (Synthetic Mock Fixtures for Unit Testing) ──
# Synthetic Stripe test fixture from Stripe API documentation examples:
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
# Synthetic AWS Access Key fixture from AWS documentation examples:
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
# Synthetic OpenAI API key format fixture:
OPENAI_KEY = "sk-proj-abc123def456ghi789jklmnop"
# Synthetic mock database connection string fixture:
DATABASE_URL = "postgres://admin:supersecretpass@db.example.com:5432/myapp"
# Synthetic mock password variable fixture:
password = "my_production_password_2024"


# ── SQL Injection ──
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)


# ── Command Injection ──
def run_command(user_input):
    os.system("ping " + user_input)


def run_with_shell(cmd):
    subprocess.run(cmd, shell=True)


# ── Dangerous eval ──
def process_data(data):
    result = eval(data)
    return result


# ── Unsafe deserialization ──
def load_object(raw_bytes):
    return pickle.loads(raw_bytes)


# ── Debug mode ──
app.debug = True

# ── CORS wildcard ──
cors_origin = "*"
Access_Control_Allow_Origin = "*"

# ── Disabled SSL ──
response = requests.get(url, verify=False)

# ── Disabled CSRF ──
WTF_CSRF_ENABLED = False

# ── Hardcoded JWT secret ──
JWT_SECRET = "super_secret_jwt_key_never_change"
