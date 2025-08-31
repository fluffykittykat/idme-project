# ID.me + Retail Q&A Reference (Walmart-style)

Use these concise answers during stakeholder Q&A. References to sample app components are in parentheses.

Core questions from the rubric
1) How does ID.me give trust to the users coming to our system?
- Verified identity and eligibility: ID.me performs identity proofing and community eligibility checks (e.g., Teacher). Your app receives cryptographically signed tokens with claims (OIDC). (login(), callback(), get_provider_config())
- Protocol security: OIDC Authorization Code flow with state/nonce, TLS, and signed ID tokens; optional PKCE for public clients.
- Network effect: Users verified once can port eligibility across merchants, reducing fraud/abuse on segmented offers.

2) Do users need to verify each time they visit?
- No. Verification persists at ID.me; user sessions and refresh keep friction low.
- You can enforce re-auth or step-up with policy and OIDC parameters:
  - max_age (forces re-auth after N seconds),
  - acr_values (assurance requirements),
  - prompt (e.g., login, consent).
- Your local session controls UX; you don’t need to re-verify unless your policy requires it. (effective_redirect_uri(), session usage in templates)

3) Does the customer need to provide Tier 1 support?
- ID.me handles Tier 1 for identity proofing and verification issues.
- Your support focuses on commerce/account matters (orders, shipping).
- Establish a clear escalation path to ID.me for verification concerns.

4) How should user access be granted?
- Claims → roles/feature flags. Use eligibility claims to set an internal flag (e.g., is_teacher) and drive pricing/entitlements. (is_teacher_from_claims(), session["idme_profile"])
- Minimize PII. Avoid storing raw tokens or unnecessary attributes; prefer short-lived sessions with flags.
- Optional: Persist an eligibility snapshot with TTL if audit/compliance needs exist.

5) User experience walkthrough
- Logged out: CTA “Verify with ID.me.”
- Click → redirect to ID.me for login/consent (state/nonce pinned). (login())
- Callback with code → token exchange → userinfo → set session profile and eligibility. (callback())
- Storefront shows educator badge and discounted pricing; product page shows savings; profile shows payload for demo. (index.html, product.html, profile.html)

6) Technical walkthrough of the integration
- Discovery: Retrieve endpoints from /.well-known/openid-configuration once and cache. (get_provider_config())
- Auth request: Build URL with client_id, redirect_uri, scope=login, state, nonce. (login())
- Token exchange: code → tokens; then call /userinfo. Normalize claims. (callback())
- Claims mapping: derive is_teacher via flexible parsing; set session; templates render pricing. (is_teacher_from_claims(), templates)
- Production hardening: verify ID token signature (JWKS), use PKCE, secure cookies, HTTPS, rotate secrets, short sessions.

Deeper technical questions (prepared responses)
Token verification (production)
- Validate ID token signature using JWKS (cfg["jwks_uri"]), check iss/aud/exp/nonce. Example (PyJWT concept):
  - jwks = requests.get(cfg["jwks_uri"]).json()
  - key = select by kid; jwt.decode(id_token, key, algorithms=["RS256"], audience=IDME_CLIENT_ID, issuer=cfg["issuer"])
- In demo, we decode unverified for display only. Production must verify.

PKCE (recommended)
- Public clients and native/mobile apps should use PKCE:
  - code_verifier = base64url(random 32–64 bytes)
  - code_challenge = base64url(SHA256(verifier))
  - Send code_challenge & method=S256 in auth request; include code_verifier in token exchange.

Logout flows
- Local logout clears session (demo). For full RP-initiated logout, call ID.me’s end-session endpoint if available; consider front-/back-channel logout for SSO.

Data minimization/PII
- Store only what you need to render UX/eligibility flags.
- Prefer ephemeral sessions; avoid writing raw tokens to persistent storage.
- Honor data retention policies; document lawful basis and TTLs.

Reliability and performance
- Cache discovery doc (get_provider_config() already memoizes).
- Timeouts and retries (requests timeout=10 is set); implement backoff for robustness.
- Graceful error handling: state mismatch, token exchange failure, userinfo failure bubble to templates/error.html.

Fraud/abuse mitigation for segmented offers
- Enforce eligibility via signed claims, not client-side signals.
- Time-bound snapshots; re-check eligibility on sensitive events (checkout).
- Monitor anomalies (excessive returns/benefit use); limit sharing by binding to account.

Mobile/native integration
- Use OIDC with PKCE and app schemes/universal links.
- Store session/flags in app storage; rely on ID.me SSO where possible.

Multi-tenant and environment separation
- Separate client IDs/secrets and redirect URIs per environment (dev/stage/prod).
- Rotate secrets; store in a secrets manager.

SLA/outage planning
- Use sandbox for integration; monitor production endpoints.
- Implement fallback UX (e.g., remove discount CTA if IDP outage) while preserving checkout integrity.

Metrics and experimentation
- Track CTR on “Verify with ID.me,” verification success rate, conversion lift, AOV, margin impact.
- A/B test placement and messaging to optimize uptake.

Security settings used in the sample
- ProxyFix to honor reverse proxy headers (scheme/host), opt-in forced HTTPS, SameSite/Secure cookies (when FORCE_HTTPS=1).
- state and nonce in auth request; demo-only unverified ID token decode (replace with proper verification in prod).

Callouts to code in this repo (for demo)
- OIDC discovery: get_provider_config()
- Auth request: login() (state/nonce, optional prompt/max_age/acr_values)
- Token exchange + userinfo: callback()
- Eligibility mapping: is_teacher_from_claims()
- UX/pricing: templates/index.html and templates/product.html (check is_teacher)
- Payload display (demo): templates/profile.html

Appendix: Example policy knobs
- Re-auth policy: max_age=3600 for sensitive actions; none for browse.
- Step-up: acr_values for higher assurance flows where needed.
- Session TTLs: 30–60 min idle with rolling refresh; avoid excessive duration.
