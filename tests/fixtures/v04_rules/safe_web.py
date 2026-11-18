# Tests fixture: safe web and framework patterns for v0.4 rules

import jwt
from flask import render_template_string, request


def ssti_safe():
    name = request.args.get("name")
    # Safe: static template string with keyword variable arguments
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


def jwt_verification_safe(token, secret_key):
    # Safe: signature verified with strict algorithms list
    claims = jwt.decode(token, secret_key, algorithms=["HS256"])
    return claims


def cors_allowlist_safe(response):
    # Safe: strict origin whitelist
    allowed = {"https://trusted.app.com"}
    origin = request.headers.get("origin")
    if origin in allowed:
        response.headers["Access-Control-Allow-Origin"] = origin
    return response
