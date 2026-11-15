# Safe Python file — should produce zero or very few findings
# This file uses correct security practices throughout.

import json
import os

from flask import Flask

app = Flask(__name__)

# Secrets loaded from environment variables (correct practice)
DATABASE_URL = os.environ.get("DATABASE_URL", "")
API_KEY = os.environ["API_KEY"]
JWT_SECRET = os.environ.get("JWT_SECRET")


# Parameterized query (safe)
def get_user(user_id: str) -> dict:
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()


# Safe subprocess usage (no shell=True, list args)
def ping_host(hostname: str) -> str:
    import subprocess

    result = subprocess.run(["ping", "-c", "1", hostname], capture_output=True, text=True)
    return result.stdout


# Safe JSON parsing (not eval/pickle)
def parse_data(raw: str) -> dict:
    return json.loads(raw)


# Debug mode off
app.debug = False

# CORS restricted to specific origin
CORS_ORIGIN = "https://myapp.example.com"
