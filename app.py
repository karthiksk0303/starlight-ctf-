```python
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
)
import base64
import json
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "starlight-ctf-dev-key")


# Serve CSS
@app.route("/style.css")
def stylesheet():
    return send_from_directory(
        app.root_path,
        "style.css",
        mimetype="text/css",
    )


# Homepage
@app.route("/")
def index():
    return render_template("index.html")


# Challenge documentation
@app.route("/docs")
@app.route("/docs.html")
def docs():
    return render_template("docs.html")


# Login - intentionally vulnerable for the CTF
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return redirect("/")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if username and password:
        session["username"] = username
        return redirect("/profile")

    return jsonify({
        "status": "error",
        "message": "Enter a username and password.",
    }), 400


# Profile
@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/")

    return jsonify({
        "status": "success",
        "username": session["username"],
        "message": "Welcome to STARLIGHT.",
    })


# Deliberately vulnerable JWT payload decoder for the CTF.
# It decodes the payload but does not verify the signature.
@app.route("/api/token", methods=["GET", "POST"])
def token():
    token_value = request.values.get("token", "")

    if not token_value:
        return jsonify({
            "error": "Provide a token parameter.",
        }), 400

    try:
        parts = token_value.split(".")

        if len(parts) != 3:
            raise ValueError("Invalid token format")

        payload = parts[1]
        payload += "=" * (-len(payload) % 4)

        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded.decode("utf-8"))

        return jsonify({
            "decoded": data,
            "signature_verified": False,
            "warning": "Payload decoded without signature verification.",
        })

    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({
            "error": "Could not decode token.",
        }), 400


# Archive
@app.route("/archive")
def archive():
    if "username" not in session:
        return redirect("/")

    return jsonify({
        "message": "STARLIGHT archive",
        "access": "authenticated",
    })


# Health check
@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "challenge": "STARLIGHT",
    })


# Robots.txt
@app.route("/robots.txt")
def robots():
    content = (
        "User-agent: *\n"
        "Disallow: /archive\n"
        "Disallow: /api/token\n"
    )

    return content, 200, {
        "Content-Type": "text/plain; charset=utf-8"
    }


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )
```
