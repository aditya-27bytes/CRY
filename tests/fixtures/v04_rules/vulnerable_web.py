# Tests fixture: vulnerable web and framework patterns for v0.4 rules

import jwt
from flask import render_template_string, request


def ssti_vulnerable():
    name = request.args.get("name")
    # Vulnerable: render_template_string with f-string interpolation
    return render_template_string(f"<h1>Hello {name}</h1>")


def jwt_verification_disabled_vulnerable(token):
    # Vulnerable: verify=False allows arbitrary unverified JWT claims
    claims = jwt.decode(token, verify=False)
    return claims


def cors_reflection_vulnerable(response):
    origin = request.headers.get("origin")
    # Vulnerable: reflects origin while allowing credentials
    response.set_header("Access-Control-Allow-Origin", request.headers.get("origin"))
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
