import os
import json
import secrets
from urllib.parse import urlencode
from flask import Flask, redirect, request, session, render_template, url_for, abort
import requests
import base64
from werkzeug.middleware.proxy_fix import ProxyFix

"""
Minimal ID.me OAuth/OIDC example for the Retail vertical (Customer: Walmart)
- Shows a "Verify with ID.me" button
- Redirects user to ID.me to authenticate
- Handles callback, exchanges code for tokens
- Fetches user payload (userinfo) and displays first name, last name, email, and full payload

References:
- Sample code: https://github.com/IDme/python-sample-code/blob/master/server.py
- Docs: https://developer.id.me/documentation/federated-protocols/oauth
- OIDC discovery: https://api.id.me/oidc/.well-known/openid-configuration

Test credentials from provided assignment PDF:
- Client ID: 28bf5c72de76f94a5fb1d9454e347d4e
- Client Secret: 3e9f2e9716dba6ec74a2e42e90974828
- Scope: login
- Redirect URI: For this exercise, you can use any redirect_uri (we use http://localhost:5000/callback by default)
"""

app = Flask(__name__, template_folder="templates")
# Honor reverse proxy headers (X-Forwarded-Proto, X-Forwarded-Host, etc.) so url_for builds https when appropriate
if os.getenv("TRUST_PROXY", "1") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

# Optional: force https scheme and secure cookies (enable by setting FORCE_HTTPS=1)
if os.getenv("FORCE_HTTPS", "0") == "1":
    app.config["PREFERRED_URL_SCHEME"] = "https"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Use a persistent secret in env for session protection; fallback for demo purposes only
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

# Config via environment variables with sensible defaults for the exercise
IDME_DISCOVERY_URL = os.getenv("IDME_DISCOVERY_URL", "https://api.id.me/oidc/.well-known/openid-configuration")
IDME_CLIENT_ID = os.getenv("IDME_CLIENT_ID", "28bf5c72de76f94a5fb1d9454e347d4e")
IDME_CLIENT_SECRET = os.getenv("IDME_CLIENT_SECRET", "3e9f2e9716dba6ec74a2e42e90974828")
IDME_SCOPE = os.getenv("IDME_SCOPE", "login")
# Optional OIDC request parameters
IDME_PROMPT = os.getenv("IDME_PROMPT")  # e.g., "login", "consent", or leave unset
IDME_MAX_AGE = os.getenv("IDME_MAX_AGE")  # seconds, e.g., "3600"
IDME_ACR_VALUES = os.getenv("IDME_ACR_VALUES")  # e.g., "urn:mace:incommon:iap:silver"
# If running on a different host/port, set IDME_REDIRECT_URI accordingly (must match the Flask callback URL)
DEFAULT_REDIRECT_URI = "http://localhost:5000/callback"
IDME_REDIRECT_URI = os.getenv("IDME_REDIRECT_URI", DEFAULT_REDIRECT_URI)


def effective_redirect_uri():
    """
    Determine the redirect_uri to use:
    - If IDME_REDIRECT_URI env var is set, honor it.
    - Otherwise, build from the current request host to avoid host/cookie mismatches.
    - If FORCE_HTTPS=1, enforce https scheme for the redirect_uri.
    """
    override = os.getenv("IDME_REDIRECT_URI")
    if override:
        uri = override
    else:
        # Build absolute URL from current request context
        uri = url_for("callback", _external=True)

    # If enforcing HTTPS, normalize the scheme to https
    if os.getenv("FORCE_HTTPS", "0") == "1" and uri.startswith("http://"):
        uri = "https://" + uri[len("http://"):]

    return uri


def decode_jwt_unverified(token: str):
    """
    Decode a JWT without verifying the signature (for demo/inspection only).
    Returns the payload dict if successful, otherwise None.
    """
    if not token or not isinstance(token, str):
        return None
    try:
        parts = token.split(".", 2)
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        # Add padding for base64url
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None


def get_provider_config():
    """
    Retrieve and cache the OIDC provider configuration from the well-known endpoint.
    """
    if "idme_provider_config" not in app.config:
        resp = requests.get(IDME_DISCOVERY_URL, timeout=10)
        resp.raise_for_status()
        app.config["idme_provider_config"] = resp.json()
    return app.config["idme_provider_config"]


@app.route("/")
def index():
    """
    Simple landing page with Walmart branding and a Verify with ID.me button.
    """
    return render_template("index.html")


@app.route("/login")
def login():
    """
    Start the OAuth 2.0 Authorization Code flow.
    Build the authorization URL from the discovery doc and redirect the user.
    """
    cfg = get_provider_config()
    authorization_endpoint = cfg["authorization_endpoint"]

    # Protect against CSRF with 'state' and include a 'nonce' for OIDC (best practice).
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    session["oauth_nonce"] = nonce

    # Compute redirect_uri to match the current host (avoids session cookie/host mismatch issues)
    redirect_uri = effective_redirect_uri()
    print(f"OAuth login: redirect_uri={redirect_uri} host={request.host}")

    # Build authorization request
    params = {
        "client_id": IDME_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": IDME_SCOPE,  # per assignment: "login"
        "state": state,
        "nonce": nonce,
    }
    # Optional OIDC parameters (configurable via env)
    if IDME_PROMPT:
        params["prompt"] = IDME_PROMPT
    if IDME_MAX_AGE and str(IDME_MAX_AGE).isdigit():
        params["max_age"] = IDME_MAX_AGE
    if IDME_ACR_VALUES:
        params["acr_values"] = IDME_ACR_VALUES

    auth_url = f"{authorization_endpoint}?{urlencode(params)}"
    return redirect(auth_url)


@app.route("/callback")
def callback():
    """
    Handle the redirect back from ID.me, verify state, exchange code for tokens,
    fetch userinfo payload, and display it.
    """
    error = request.args.get("error")
    if error:
        description = request.args.get("error_description", "")
        return render_template("error.html", error=error, description=description), 400

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        return render_template("error.html", error="invalid_request", description="Missing authorization code or state"), 400

    # Verify state to mitigate CSRF
    expected_state = session.pop("oauth_state", None)
    if not expected_state or state != expected_state:
        return render_template("error.html", error="invalid_state", description="State mismatch"), 400

    cfg = get_provider_config()
    token_endpoint = cfg["token_endpoint"]
    userinfo_endpoint = cfg.get("userinfo_endpoint")

    # Compute redirect_uri to match the current host (must match what was used in /login)
    redirect_uri = effective_redirect_uri()
    print(f"OAuth callback: redirect_uri={redirect_uri} host={request.host}")

    # Exchange authorization code for tokens
    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": IDME_CLIENT_ID,
        "client_secret": IDME_CLIENT_SECRET,
    }

    token_resp = requests.post(token_endpoint, data=token_payload, timeout=10)
    if token_resp.status_code != 200:
        return render_template(
            "error.html",
            error="token_exchange_failed",
            description=f"Token endpoint returned {token_resp.status_code}: {token_resp.text}",
        ), 400

    tokens = token_resp.json()
    access_token = tokens.get("access_token")
    id_token = tokens.get("id_token")
    id_claims = decode_jwt_unverified(id_token) if id_token else None

    # Fetch user info (payload) using the access token
    userinfo = None
    if access_token and userinfo_endpoint:
        ui_resp = requests.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}, timeout=10)
        if ui_resp.status_code == 200:
            userinfo = ui_resp.json()
        else:
            # Keep going and show tokens even if userinfo failed
            userinfo = {"error": f"userinfo_endpoint returned {ui_resp.status_code}", "body": ui_resp.text}

    # Normalize userinfo into claims dict
    userinfo_claims = None
    if isinstance(userinfo, str):
        userinfo_claims = decode_jwt_unverified(userinfo)
    elif isinstance(userinfo, dict):
        userinfo_claims = userinfo

    # Extract a few common fields from userinfo or id_token as fallback
    first_name = None
    last_name = None
    email = None
    if isinstance(userinfo_claims, dict):
        first_name = userinfo_claims.get("given_name") or userinfo_claims.get("first_name") or userinfo_claims.get("fname")
        last_name = userinfo_claims.get("family_name") or userinfo_claims.get("last_name") or userinfo_claims.get("lname")
        email = userinfo_claims.get("email")
    if not first_name and isinstance(id_claims, dict):
        first_name = id_claims.get("given_name") or id_claims.get("first_name") or id_claims.get("fname")
    if not last_name and isinstance(id_claims, dict):
        last_name = id_claims.get("family_name") or id_claims.get("last_name") or id_claims.get("lname")
    if not email and isinstance(id_claims, dict):
        email = id_claims.get("email")

    # Store for display (do not store secrets in prod)
    session["idme_tokens"] = tokens
    session["idme_userinfo"] = userinfo
    session["idme_userinfo_claims"] = userinfo_claims
    session["idme_id_token_claims"] = id_claims
    session["idme_profile"] = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
    }

    return redirect(url_for("profile"))


@app.route("/profile")
def profile():
    """
    Display the user's first, last, email (if available) and the full payload JSON.
    """
    tokens = session.get("idme_tokens")
    userinfo = session.get("idme_userinfo")
    profile = session.get("idme_profile")

    if not tokens and not userinfo:
        # No session data, ask user to start over
        return redirect(url_for("index"))

    # Pretty-print JSON payload for display
    payload_str = json.dumps(
        {
            "tokens": tokens,
            "id_token_claims": session.get("idme_id_token_claims"),
            "userinfo_raw": userinfo,
            "userinfo_claims": session.get("idme_userinfo_claims"),
        },
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )

    return render_template(
        "profile.html",
        profile=profile or {},
        payload_str=payload_str,
    )


@app.route("/logout")
def logout():
    """
    Clear session (local logout for demo).
    """
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Run Flask app
    # Ensure the redirect URI matches http://localhost:5000/callback (default) or set IDME_REDIRECT_URI to your callback
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
