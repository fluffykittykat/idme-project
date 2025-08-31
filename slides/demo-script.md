# ID.me + Retail (Walmart-style) Demo Script and Run-of-Show

Audience: Retail e‑commerce stakeholders (Solution Consulting, Product, Security)
Goal: Show how ID.me provides trusted authentication and educator eligibility to unlock segmented pricing with minimal code changes in a Walmart-style storefront.
Duration: 30 minutes total (recommended: 22–25 min content + 5–8 min Q&A)

Agenda (timeboxed)
- 0:00–1:30 — Introductions and objectives
- 1:30–6:00 — How the solution works + value of ID.me (slides)
- 6:00–12:00 — Integration with current system (slides + quick code peek)
- 12:00–18:00 — OIDC Auth Code walkthrough (slides + code)
- 18:00–24:00 — Live demo
- 24:00–30:00 — Q&A and close

Pre‑requisites (local run)
- Python 3.10+
- pip install -r requirements.txt
- Set environment variables (for demo):
  - export FLASK_SECRET_KEY="change-me"
  - Optional: export IDME_CLIENT_ID, IDME_CLIENT_SECRET, IDME_REDIRECT_URI (defaults in app.py work for the assignment)
  - Optional: export FORCE_HTTPS=1 when behind TLS; TRUST_PROXY=1 is on by default (ProxyFix)
  - DEMO_FORCE_TEACHER=1 (default) keeps educator example predictable for demo
- Start: python app.py
- Open: http://localhost:5000

Talk track highlights by section
1) How the solution works (Slides)
- ID.me verifies identity/eligibility (e.g., Teacher) and returns signed claims.
- The retailer trusts those claims to grant benefits (discounts, features).
- Portability: users reuse verification across participating merchants.
- Business value: higher conversion, margin protection, lower abuse rate.

2) Integration with current system (Slides + Code)
- Minimal changes: add /login, /callback; map claims → is_teacher; update pricing templates.
- app.py: 
  - get_provider_config() — OIDC discovery via well-known URL.
  - login() — builds auth URL with state and nonce; redirects to ID.me.
  - callback() — exchanges code for tokens, fetches /userinfo, normalizes claims, sets session.
  - is_teacher_from_claims() — robust detection across common claim shapes.
  - effective_redirect_uri() — avoids host/cookie mismatches; supports FORCE_HTTPS.
- Templates show how session-derived flags drive UX/pricing.

3) OIDC walkthrough (Slides + Code)
- Discovery: /.well-known/openid-configuration → endpoints.
- Auth request: response_type=code, scope="login", state+nonce.
- Callback validates state; token exchange (code→tokens).
- Fetch userinfo; derive eligibility; set session profile.
- Production notes:
  - Verify ID token signature via JWKS.
  - Consider PKCE (best practice), short-lived sessions, refresh.
  - Secure cookies, SameSite, HTTPS, proxy headers.

4) Live demo (6 minutes)
A) Baseline
- Navigate to http://localhost:5000. Point out:
  - "Verify with ID.me" CTA
  - Logged-out pricing vs. educator experience
B) Verify flow
- Click "Verify with ID.me" (triggers /login).
  - Explain state/nonce protection and redirect to ID.me.
  - If live ID.me auth is possible, complete login and consent.
  - If not available, describe the redirect/callback and proceed with the demo using DEMO_FORCE_TEACHER.
C) Post-auth experience
- After callback, storefront shows:
  - Educator badge (teacher discount active)
  - Discounted pricing on cards
- Open a product page to show:
  - Savings line, educator price
- Open Profile:
  - Show payload (tokens + userinfo) for demo transparency
  - Reiterate that production systems avoid storing unnecessary PII
D) Logout
- Click Sign out; show session clears and pricing reverts

Contingencies and offline mode
- If ID.me login cannot be completed (network/policy):
  - Keep DEMO_FORCE_TEACHER=1 (default) to illustrate pricing behavior.
  - Still walk through login() and callback() code and the slides’ sequence diagram.
- If callback shows error:
  - Show templates/error.html handling and explain state mismatch/invalid_request scenarios.

Security and compliance callouts
- ProxyFix and FORCE_HTTPS guard correct scheme/host in URLs.
- Secure cookies and SameSite suggested in FORCE_HTTPS mode.
- Validate state and use nonce; in production, verify JWT signature and claims (aud, iss, exp).
- Principle of least privilege: don’t persist raw tokens; prefer session flags/role mapping.

Close (30–60 seconds)
- Recap: trusted identity → targeted offers with minimal integration.
- Next steps: enable test app in ID.me console, configure client/redirects, implement prod token verification, add PKCE.
- Hand-off to Q&A.

Appendix: Useful commands
- Run app: python app.py
- Open slides: file://<repo>/slides/retail-idme-deck.html (or xdg-open slides/retail-idme-deck.html on Linux)
- Env examples:
  - export IDME_DISCOVERY_URL="https://api.id.me/oidc/.well-known/openid-configuration"
  - export IDME_SCOPE="login"
  - export IDME_REDIRECT_URI="http://localhost:5000/callback"

Links (for reference)
- OIDC discovery: https://api.id.me/oidc/.well-known/openid-configuration
- Docs: https://developer.id.me/documentation/federated-protocols/oauth
