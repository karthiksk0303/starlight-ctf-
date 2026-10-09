
import base64
import json
import os

from flask import Flask, jsonify, render_template, request

app = Flask(
    __name__,
    static_folder="public",
    static_url_path="/static",
)

FLAG = "ROOT@KNU11{STRXX_L1GHtt_P4Y4LuG4}"


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data):
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def create_token(callsign):
    """Issue a demo JWT-shaped token for the CTF."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": callsign,
        "role": "cadet",
        "iss": "STARLIGHT",
    }

    # Intentionally fake signature: this is a CTF, not real authentication.
    return (
        f"{b64url_encode(json.dumps(header, separators=(',', ':')))}."
        f"{b64url_encode(json.dumps(payload, separators=(',', ':')))}."
        "demo-signature"
    )


def read_unverified_claims(token):
    """
    INTENTIONAL CTF VULNERABILITY:
    The server decodes the JWT payload without validating its signature.
    Never use this function for production authentication.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed token")

    payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Invalid token payload")

    return payload


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/internal-docs")
def internal_docs():
    return render_template("docs.html")


@app.get("/robots.txt")
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /internal-docs\n"
        "Disallow: /api/archive\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.post("/api/session")
def create_session():
    data = request.get_json(silent=True) or {}
    callsign = str(data.get("callsign", "cadet")).strip()[:40] or "cadet"

    token = create_token(callsign)
    return jsonify({
        "status": "SESSION ESTABLISHED",
        "callsign": callsign,
        "token": token,
        "message": "Inspect the token and the access protocol.",
    })


@app.post("/api/profile")
def profile():
    data = request.get_json(silent=True) or {}
    token = str(data.get("token", "")).strip()

    try:
        claims = read_unverified_claims(token)
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError):
        return jsonify({
            "ok": False,
            "error": "Invalid token format.",
        }), 400
    except Exception:
        return jsonify({
            "ok": False,
            "error": "Could not read token.",
        }), 400

    return jsonify({
        "ok": True,
        "callsign": claims.get("sub", "unknown"),
        "role": claims.get("role", "unknown"),
        "issuer": claims.get("iss", "unknown"),
        "notice": "Claims decoded. This endpoint does not verify the signature.",
    })


@app.get("/api/archive")
def archive():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()

    if not token:
        data = request.get_json(silent=True) or {}
        token = str(data.get("token", "")).strip()

    try:
        claims = read_unverified_claims(token)
    except Exception:
        return jsonify({
            "ok": False,
            "error": "A validly formatted access token is required.",
        }), 401

    # INTENTIONAL FLAW: role is trusted without cryptographic verification.
    if claims.get("role") != "admin":
        return jsonify({
            "ok": False,
            "error": "Restricted archive. Admin clearance required.",
            "current_role": claims.get("role", "unknown"),
        }), 403

    return jsonify({
        "ok": True,
        "archive": "STARLIGHT // RESTRICTED TRANSMISSION",
        "flag": FLAG,
    })


@app.get("/health")
def health():
    return jsonify({"status": "online", "service": "STARLIGHT"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
