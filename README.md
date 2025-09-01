# Walmart Retail — Verify with ID.me (Option 1: OIDC/OAuth)

A minimal Flask app demonstrating an ID.me OAuth 2.0 / OpenID Connect Authorization Code flow for the Retail vertical (Customer: Walmart). The app:
- Shows a "Verify with ID.me" button
- Redirects to ID.me for login
- Handles the callback and exchanges the authorization code for tokens
- Fetches the user payload (userinfo) and displays first name, last name, email, and the full payload on the page

References:
- Sample code: https://github.com/IDme/python-sample-code/blob/master/server.py
- OAuth/OIDC Docs: https://developer.id.me/documentation/federated-protocols/oauth
- OIDC Discovery: https://api.id.me/oidc/.well-known/openid-configuration

Test credentials (from the assignment PDF):
- Client ID: `28bf5c72de76f94a5fb1d9454e347d4e`
- Client secret: `3e9f2e9716dba6ec74a2e42e90974828`
- Scope: `login`
- Redirect URI: For this exercise, you can use any redirect_uri (this demo uses `http://localhost:5000/callback` by default)
- Test user: `partner+se-test-mil-200603-f4b4b8@id.me`
- Test user password: `5uxgqZdg8By7Lz22`

Note: With scope `login`, the userinfo payload may be minimal. This demo extracts first, last, and email if present.

## Project Structure

```
idme/
  app.py
  requirements.txt
  templates/
    index.html
    profile.html
    error.html
```

## Quick Start

Prereqs: Python 3.10+, pip

1) Create and activate a virtual environment (recommended)
- macOS/Linux:
  ```
  python3 -m venv .venv
  source .venv/bin/activate
  ```
- Windows (PowerShell):
  ```
  py -3 -m venv .venv
  .venv\Scripts\Activate.ps1
  ```

2) Install dependencies
```
pip install -r idme/requirements.txt
```

3) (Optional but recommended) Set environment variables
```
export FLASK_SECRET_KEY="change-me"                 # required for session protection
export IDME_CLIENT_ID="28bf5c72de76f94a5fb1d9454e347d4e"
export IDME_CLIENT_SECRET="3e9f2e9716dba6ec74a2e42e90974828"
export IDME_SCOPE="login"
export IDME_REDIRECT_URI="http://localhost:5000/callback"
# Optionally override discovery if needed:
# export IDME_DISCOVERY_URL="https://api.id.me/oidc/.well-known/openid-configuration"
```

4) Run the app
```
python idme/app.py
```

5) Open your browser at
```
http://localhost:5000
```

6) Click "Verify with ID.me", complete login with the provided test account, and upon redirect the app will display:
- First name, last name, email (if provided)
- The full payload (tokens + userinfo) pretty-printed

## How It Works

- `GET /` renders a Walmart-branded page with a "Verify with ID.me" button.
- `GET /login`:
  - Loads the OIDC provider config from the well-known discovery endpoint
  - Generates `state` and `nonce` to mitigate CSRF and replay attacks
  - Redirects the user to ID.me's authorization endpoint with:
    - `client_id`, `redirect_uri`, `response_type=code`, `scope=login`, `state`, `nonce`
- `GET /callback`:
  - Validates the returned `state`
  - Exchanges the `code` for tokens at the `token_endpoint` (from discovery)
  - Calls the `userinfo_endpoint` with the `access_token`
  - Extracts `first_name`/`given_name`, `last_name`/`family_name`, and `email` if present
  - Stores tokens + payload in the session and redirects to `/profile`
- `GET /profile` displays basic fields and the full payload JSON
- `GET /logout` clears the session (local logout only)

## Retail Vertical Context

This demo targets the Retail vertical (customer: Walmart) with Walmart-themed UI. It leverages ID.me's OIDC discovery on `api.id.me`, which covers retail sign-in. If your implementation requires additional vertical-specific parameters (e.g., special `acr_values`), you can add them to the auth request in `/login`. The assignment's scope of `login` is used here for simplicity.

## Security Notes (Demo)

- Secrets are configurable via environment variables; do not hardcode in production.
- This demo includes `state` and `nonce`. For production, store and validate them securely.
- Logout here only clears local session; add ID.me logout and RP-initiated logout as needed.

## Troubleshooting

- Redirect URI mismatch:
  - Ensure `IDME_REDIRECT_URI` matches the Callback URL your app is listening on (`http://localhost:5000/callback` by default).
- State mismatch:
  - Clear browser cookies for the app or click "Logout" and retry.
- Userinfo fields missing (e.g., email):
  - The `login` scope may not include all profile claims; consult ID.me docs for required scopes and claims for your use case.
- Network issues:
  - Verify you can reach `https://api.id.me/oidc/.well-known/openid-configuration` from your environment.

### MFA failures (e.g., MFAL01 on ID.me 2FA page)
This error is shown on an ID.me-hosted page and typically indicates the MFA code couldn’t be delivered (e.g., SMS delivery issue) before redirecting back to your app. Integration is usually not the cause. Try:
- Retry once or twice; avoid rapid re-requests to prevent carrier throttling.
- Try another factor if available (Authenticator app/TOTP, phone call instead of SMS).
- Verify the phone number/carrier can receive short-code SMS and is not blocking ID.me messages.
- If using an authenticator app, ensure device time is set automatically and in sync (required for TOTP).
- Use a fresh private/incognito window to eliminate stuck sessions.
- Confirm the login request is using HTTPS redirect_uri (see “HTTPS and Reverse Proxy” section).
- If the issue persists, check ID.me status/support and provide the specific error code (e.g., MFAL01).

If you do receive an OAuth redirect back to `/callback` with an `error` parameter, the app will display it on `/error`. If the browser remains on an ID.me URL, the failure occurred upstream at the provider and is not an app-side error.

## Code Pointers

- Discovery and endpoints: `get_provider_config()` in `app.py`
- Auth URL build + redirect: `/login`
- Token exchange + userinfo retrieval: `/callback`
- Payload rendering: `/profile`

## Optional OIDC parameters

These environment variables allow you to fine-tune the authorization request. They’re optional and unset by default:
- IDME_PROMPT — set to `login`, `consent`, or `select_account` if needed. Leaving it unset avoids forcing re-auth on every attempt, which can reduce unnecessary MFA prompts.
- IDME_MAX_AGE — maximum acceptable age (in seconds) of the user’s authentication. Example: `3600`.
- IDME_ACR_VALUES — provider-specific assurance requirements. Leave unset unless ID.me documentation for your use case specifies a value.

Examples:
```
export IDME_PROMPT="select_account"
export IDME_MAX_AGE="3600"
# Only set ACR values if instructed by ID.me documentation for your vertical:
# export IDME_ACR_VALUES="your-required-acr"
```

Note: MFA enrollment/prompting is largely controlled by the provider and/or user account settings. These parameters cannot disable MFA enforced by ID.me.

## Screens

- `index.html`: "Verify with ID.me" button (Walmart branding)
- `profile.html`: Basic profile + full payload
- `error.html`: Minimal error page

## HTTPS and Reverse Proxy (e.g., https://idme.izzytchai.com)

When running behind a reverse proxy with TLS termination, ensure Flask knows the original scheme/host so the OAuth redirect_uri is HTTPS. This repo is configured to support that.

Environment variables:
- TRUST_PROXY=1 (default) — enables ProxyFix to honor X-Forwarded-* headers
- FORCE_HTTPS=1 — forces https scheme in generated URLs and sets secure cookie flags
- FLASK_SECRET_KEY=your-strong-secret
- IDME_REDIRECT_URI=https://idme.izzytchai.com/callback — strongly recommended to set explicitly so it matches your provider allowlist

Sample Nginx config:
```
server {
  listen 443 ssl http2;
  server_name idme.izzytchai.com;

  ssl_certificate     /etc/letsencrypt/live/idme.izzytchai.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/idme.izzytchai.com/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_redirect off;
  }
}
```

ID.me application configuration:
- Add https://idme.izzytchai.com/callback to the allowed Redirect URIs for your app.

If you see an "insecure redirect" warning:
1) Verify the app logs print an HTTPS redirect URI (look for: "OAuth login: redirect_uri=...").
2) Ensure FORCE_HTTPS=1 is set in the environment.
3) Ensure your proxy sets X-Forwarded-Proto=https (see sample config).
4) If you set IDME_REDIRECT_URI, make sure it uses https://, not http://.
5) Confirm the exact https callback URL is allowlisted in the ID.me dashboard.

Testing checklist:
- export TRUST_PROXY=1 FORCE_HTTPS=1 FLASK_SECRET_KEY="change-me" IDME_REDIRECT_URI="https://idme.izzytchai.com/callback"
- Restart the Flask app
- Browse to https://idme.izzytchai.com/
- Click "Verify with ID.me" and complete login
- You should land on /profile without any "insecure redirect" message
- In server logs, confirm both the login and callback lines show an https redirect_uri

## Containerized deployment

Option A — docker run:
1) Build the image
```
docker build -t idme-app:latest .
```
2) Run the container (bind to loopback; your reverse proxy should forward HTTPS traffic to 127.0.0.1:5000)
```
docker run -d --name idme-app --restart unless-stopped \
  -p 127.0.0.1:5000:5000 \
  -e TRUST_PROXY=1 \
  -e FORCE_HTTPS=1 \
  -e FLASK_SECRET_KEY="change-me" \
  -e IDME_CLIENT_ID="28bf5c72de76f94a5fb1d9454e347d4e" \
  -e IDME_CLIENT_SECRET="3e9f2e9716dba6ec74a2e42e90974828" \
  -e IDME_SCOPE="login" \
  -e IDME_REDIRECT_URI="https://idme.izzytchai.com/callback" \
  idme-app:latest
```
3) Configure your HTTPS reverse proxy to forward to http://127.0.0.1:5000 and set:
   - Host and X-Forwarded-Host to your domain
   - X-Forwarded-Proto=https
   See the “HTTPS and Reverse Proxy” section above for a sample Nginx config.

Option B — docker compose:
1) Create a .env file next to docker-compose.yml:
```
FLASK_SECRET_KEY=change-me
IDME_CLIENT_ID=28bf5c72de76f94a5fb1d9454e347d4e
IDME_CLIENT_SECRET=3e9f2e9716dba6ec74a2e42e90974828
IDME_SCOPE=login
IDME_REDIRECT_URI=https://idme.izzytchai.com/callback
# Optional:
# IDME_DISCOVERY_URL=https://api.id.me/oidc/.well-known/openid-configuration
# IDME_PROMPT=
# IDME_MAX_AGE=3600
# IDME_ACR_VALUES=
```
2) Start the service
```
docker compose up -d
```
3) Point your HTTPS reverse proxy at http://127.0.0.1:5000 with the required X-Forwarded-* headers.

Notes:
- The image runs Gunicorn binding 0.0.0.0:5000 and honors TRUST_PROXY/FORCE_HTTPS so generated URLs and cookies are correct behind TLS.
- Ensure https://idme.izzytchai.com/callback is allowlisted in your ID.me app.
- If you don’t run behind a reverse proxy, you can still expose port 5000 publicly, but use proper TLS termination in front of it for production.

## AWS Integration

# 1) Get login and account info and confirm it.
aws sso login --profile bond-admin --no-browser

aws sts get-caller-identity

# 2) Ensure region is set (adjust if needed)
export AWS_REGION=us-west-2
export ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
export REGISTRY="${ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com"
echo "ACCOUNT=$ACCOUNT | AWS_REGION=$AWS_REGION | REGISTRY=$REGISTRY"

# 3) Authenticate Docker to ECR (note the pipe between the two commands)
aws ecr get-login-password --region "$AWS_REGION" \
| docker login --username AWS --password-stdin "$REGISTRY"

# 4) Build new image and push to ECR
docker compose build --no-cache

# 5) Push container to ECR
docker compose push