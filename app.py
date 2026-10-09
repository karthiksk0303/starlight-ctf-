
import base64
import json
import os
from flask import Flask, jsonify, redirect, render_template, request

app = Flask(__name__)


# STARLIGHT CTF configuration
FLAG = os.environ.get(
    "STARLIGHT_FLAG",
    "ROOT@KNU11{STRXX_L1GHtt_P4Y4LuG4}"
)


def encode_payload(data):
    """Encode JSON as URL-safe Base64 without padding."""
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_payload(token):
    """Decode the challenge token payload."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        payload = parts[1]
        payload += "=" * (-len(payload) % 4)

        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded.decode())

        if isinstance(data, dict):
            return data

    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/internal-docs")
def internal_docs():
    return render_template("docs.html")


@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /internal-docs\n"
        "Disallow: /api/archive\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.route("/api/session", methods=["GET", "POST"])
def session():
    if request.method == "GET":
        return jsonify({
            "service": "STARLIGHT Identity Service",
            "status": "online",
            "message": "Submit credentials to obtain a session.",
        })

    body = request.get_json(silent=True) or request.form

    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    if username == "operator" and password == "starlight2026":
        token = encode_payload({
            "sub": "operator",
            "role": "user",
        })

        # This is a deliberately vulnerable CTF token.
        return jsonify({
            "success": True,
            "token": f"header.{token}.signature",
            "message": "Session created.",
        })

    return jsonify({
        "success": False,
        "message": "Invalid username or password.",
    }), 401


@app.route("/api/profile")
def profile():
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()

    payload = decode_payload(token) if token else None

    if not payload:
        return jsonify({
            "error": "Missing or invalid session token.",
        }), 401

    return jsonify({
        "username": payload.get("sub", "unknown"),
        "role": payload.get("role", "user"),
        "message": "Profile retrieved successfully.",
    })


@app.route("/api/archive")
def archive():
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()

    payload = decode_payload(token) if token else None

    if not payload:
        return jsonify({
            "error": "Missing or invalid session token.",
        }), 401

    # INTENTIONAL VULNERABILITY:
    # The challenge decodes the payload without verifying the signature.
    if payload.get("role") == "admin":
        return jsonify({
            "success": True,
            "archive": "CLASSIFIED",
            "flag": FLAG,
        })

    return jsonify({
        "error": "Forbidden. Administrator role required.",
        "role": payload.get("role", "user"),
    }), 403


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "STARLIGHT",
    })


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Endpoint not found."}), 404

    return "Not Found", 404


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
