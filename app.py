from flask import Flask, render_template, request, jsonify
import jwt
import os
from datetime import datetime, timedelta, timezone

app = Flask(__name__, static_folder="public", static_url_path="/public")

# CTF ONLY: deliberately weak demo secret. Never use this pattern in production.
DEMO_SECRET = os.environ.get("STARLIGHT_DEMO_SECRET", "starlight-demo-key-change-me")
FLAG = "ROOT@KNU11{STRXX_L1GHtt_P4Y4LuG4}"


def issue_token(username: str, role: str = "cadet") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=2),
        "iss": "starlight-auth"
    }
    return jwt.encode(payload, DEMO_SECRET, algorithm="HS256")


def decode_token(token: str):
    """INTENTIONAL CTF VULNERABILITY: signature verification is disabled."""
    try:
        # The challenge is to notice that the server trusts editable token claims.
        return jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False, "verify_iss": False},
            algorithms=["HS256"]
        )
    except Exception:
        return None


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /internal-docs\nDisallow: /api/archive\n", 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.get("/internal-docs")
def internal_docs():
    return render_template("docs.html")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "cadet")).strip()[:40] or "cadet"
    # Demo login is intentionally open; authorization is the actual challenge.
    return jsonify({"message": "Identity token issued", "token": issue_token(username), "role": "cadet"})


@app.get("/api/profile")
def profile():
    token = _bearer_token()
    if not token:
        return jsonify({"error": "Missing bearer token", "hint": "Authorization: Bearer <token>"}), 401
    claims = decode_token(token)
    if not claims:
        return jsonify({"error": "Unreadable token"}), 401
    return jsonify({"username": claims.get("sub", "unknown"), "role": claims.get("role", "unknown"), "issuer": claims.get("iss", "unspecified")})


@app.get("/api/archive")
def archive():
    token = _bearer_token()
    if not token:
        return jsonify({"error": "Missing bearer token"}), 401
    claims = decode_token(token)
    if not claims:
        return jsonify({"error": "Unreadable token"}), 401
    if claims.get("role") != "admin":
        return jsonify({"error": "Clearance denied", "message": "Admin clearance required."}), 403
    return jsonify({"status": "ACCESS GRANTED", "archive": "STARLIGHT / RESTRICTED", "flag": FLAG})


def _bearer_token():
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.args.get("token", "").strip() or None


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
