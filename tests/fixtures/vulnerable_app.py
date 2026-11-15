# Intentionally vulnerable Python file for testing CRY scanners
# DO NOT use this in production — it exists solely as a test fixture.

import os
import pickle
import subprocess

# ── Secret Exposure ──
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
OPENAI_KEY = "sk-proj-abc123def456ghi789jklmnop"
DATABASE_URL = "postgres://admin:supersecretpass@db.example.com:5432/myapp"
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
