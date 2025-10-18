# Week 06 — **Authentication Deep-Dive: OAuth2/OIDC (Auth Code + PKCE), Sessions vs JWT** (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Build a production-grade login system end-to-end using **OIDC Authorization Code + PKCE** with an IdP (Keycloak/Auth0). Implement **secure session cookies** *and* an **access/refresh token** path (rotation + reuse detection), add **step‑up MFA**, instrument detections, and validate with **Burp** macros + negative tests. Map everything to OWASP A07 (Identification & Authentication), A05 (Misconfiguration), API2 (Broken Auth), and API6 (Business Flow).

---

## Outcomes
- Stand up an IdP (Keycloak) with a public client using **Auth Code + PKCE**; register redirect/logout URIs and scopes.
- Implement **server-side sessions** (HttpOnly, Secure, SameSite=Lax/Strict) and compare against a **short‑lived JWT** approach.
- Add **refresh token rotation** with reuse detection; on reuse, revoke session family and require re‑auth.
- Implement **MFA step‑up** (TOTP) for sensitive routes using `acr_values`/`max_age` semantics.
- Defend against **CSRF**, **session fixation**, **token replay**, and **state/nonce** tampering.
- Instrument logs/metrics and dashboards: login success/fail, refresh/reuse, logout, step‑ups, new device.
- Ship `week06-authn-authz-baseline` with tests, Burp project file, and a mini-report.

## Repository layout (this week)

```
/week06-authn-authz-baseline
  ├─ app/
  │  ├─ src/
  │  │  ├─ server.ts|js
  │  │  ├─ auth/
  │  │  │  ├─ oidcClient.ts
  │  │  │  ├─ sessionStore.ts
  │  │  │  ├─ routes.ts          # /login /callback /logout /refresh
  │  │  │  ├─ mfa.ts             # step-up helpers
  │  │  │  └─ tokens.ts          # rotate/revoke/reuse-detect
  │  │  ├─ middleware/
  │  │  │  ├─ csrf.ts
  │  │  │  ├─ requireAuth.ts
  │  │  │  └─ secureHeaders.ts
  │  │  └─ lib/
  │  ├─ test/
  │  │  ├─ integration/
  │  │  │  ├─ login.spec.ts
  │  │  │  ├─ refresh.spec.ts
  │  │  │  ├─ csrf.spec.ts
  │  │  │  ├─ fixation.spec.ts
  │  │  │  └─ stepup.spec.ts
  │  ├─ openapi.yaml              # auth endpoints & error schemas
  │  ├─ package.json
  │  └─ .semgrep.yml
  ├─ idp/
  │  ├─ docker-compose.yaml       # Keycloak + DB
  │  └─ realm-export.json         # client config (sanitized)
  ├─ burp/
  │  └─ week06-login.burp         # macros/session rules
  ├─ dashboards/
  │  └─ auth-panels.json          # login/refresh/reuse
  ├─ docs/
  │  ├─ flows.md                  # sequence diagrams & cookies
  │  ├─ threats.md                # CSRF/fixation/replay/…
  │  └─ report-week06.md
  └─ README.md
```

---

# Day 1 — **Identity Provider (IdP) + PKCE Client**

### Morning (Build, ~4h)
- Bring up **Keycloak** via docker-compose; create a realm and a **public client** with `authorization code` flow and `PKCE (S256)`.
- Register **redirect URIs** (`http://localhost:3000/callback`) and **post-logout redirect**; set **Allowed CORS origins** if SPA used for demo only.
- Export sanitized **realm JSON** to `idp/realm-export.json` for reproducibility.

### Midday (Learn/Labs, ~3h)
- Read **RFC 6749 (OAuth2)**, **RFC 7636 (PKCE)** basics, and **OIDC Core** sections on `authorization_code`, `nonce`, `state`.
- Sketch **sequence diagrams** (Mermaid) for: (1) Login with PKCE, (2) Logout (RP-initiated), (3) Refresh rotation.

### Afternoon (Drill/Test, ~3h)
- CLI sanity: call IdP discovery `/.well-known/openid-configuration`; fetch JWKS.
- Configure **openid-client** (Node) with discovery URL; build `/login` and `/callback` routes; verify you can read the user’s `sub`, `email`, `groups`.

### Evening (Document/Share, ~2h)
- Commit `idp/docker-compose.yaml` and `realm-export.json` (no secrets).
- Add `docs/flows.md` with your sequence diagrams.

### Why?
Without a real IdP, you can’t test PKCE, nonce/state, or RP-initiated logout correctly. Sequence diagrams lock in shared understanding.

### Real‑world mapping
- SaaS enterprises commonly use Keycloak/Auth0/Okta; PKCE is mandatory for public/mobile/Spa clients.
- Auditors will ask for redirect URI allowlists and flow diagrams.

### Acceptance criteria
- Keycloak up; client registered; `/login` → IdP → `/callback` returns a session with claims.
- Realm export and diagrams are committed.

---

# Day 2 — **Secure Sessions vs JWTs**

### Morning (Build, ~4h)
- Implement **server-side sessions**: `express-session` with Redis store; cookie `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict` if UX allows), `Domain` scoped narrowly.
- Alternate path: **short‑lived JWT access token** stored in **memory** (not localStorage) and session cookie only for refresh (server side).

```js
// app/src/server.ts (cookie + session basics)
import session from "express-session";
import connectRedis from "connect-redis";
import Redis from "ioredis";

const RedisStore = connectRedis(session);
const redis = new Redis(process.env.REDIS_URL);

app.use(session({
  store: new RedisStore({ client: redis }),
  name: "sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,            // true behind TLS
    sameSite: "lax",
    maxAge: 1000 * 60 * 15   // 15 min rolling
  }
}));
```
### Midday (Learn/Labs, ~3h)
- Compare **session fixation** risks vs stateless JWTs; understand why **rotating session IDs** on login is essential.
- Review **SameSite** modes and CSRF risks; plan a **double-submit cookie** or state token for UI POSTs.

### Afternoon (Drill/Test, ~3h)
- Add `requireAuth` middleware; rotate session ID on successful login (`req.session.regenerate`).
- Write tests: session cookie cannot be used from other origin; fixate attempt fails; unauthorized access 302/401 as expected.

### Evening (Document/Share, ~2h)
- Document trade-offs in README: **server sessions** vs **access JWT**; when to use which.
- Add cookie header examples and security rationale.

### Acceptance criteria
- Session store running; session ID rotation implemented on login.
- Tests cover SameSite behavior and fixation denial.

---

# Day 3 — **Refresh Tokens: Rotation & Reuse Detection**

### Morning (Build, ~4h)
- Implement `/refresh` route using **openid-client** token endpoint; **store refresh tokens server‑side** keyed by session and **rotate** on each use.
- Track **token family** (current token hash, previous hash, last use ts, device fingerprint). Mark a family **compromised** on reuse.

```ts
// app/src/auth/tokens.ts (sketch)
export async function rotateRefresh(sessionId, oldToken) {
  const rec = await db.getFamily(sessionId);
  if (!rec || hash(oldToken) != rec.currentHash) {
    // reuse detected
    await db.markCompromised(sessionId);
    await revokeFamily(sessionId);
    throw new Error("refresh_reuse_detected");
  }
  const newTokens = await oidcClient.refresh(oldToken);
  await db.updateFamily(sessionId, {
    currentHash: hash(newTokens.refresh_token),
    prevHash: hash(oldToken),
    lastRotatedAt: new Date()
  });
  return newTokens;
}
```
### Midday (Learn/Labs, ~3h)
- Study **refresh token rotation** (Auth0 docs pattern) and **reuse detection** rationale; understand `invalid_grant` and why to revoke the family.
- Consider **device binding** heuristics (UA/IP) and limitations.

### Afternoon (Drill/Test, ~3h)
- Write tests: use refresh token twice (second should trigger family revoke).
- Attempt **replay after logout**: should fail; log events must show revocation.

### Evening (Document/Share, ~2h)
- Add dashboards: refresh success/fail, reuse detections, revocations over time.
- Document incident flow for reuse detection (for Week 10 monitoring).

### Acceptance criteria
- Rotation works; family reuse triggers revoke and requires re‑auth.
- Dashboards show refresh usage and anomalies.

---

# Day 4 — **CSRF, State/Nonce, and OIDC Logout**

### Morning (Build, ~4h)
- Add **CSRF protection** for form POSTs: double‑submit cookie or library middleware; exempt pure API with SameSite+token headers.
- Ensure **`state`** and **`nonce`** are per‑request, unpredictable, and validated on callback; store in session.

```ts
// app/src/middleware/csrf.ts (double-submit sketch)
export function csrf(req, res, next){
  if (req.method === "GET") return next();
  const csrfHeader = req.get("X-CSRF-Token");
  const csrfCookie = req.cookies["csrf"];
  if (!csrfHeader || !csrfCookie || csrfHeader !== csrfCookie) {
    return res.status(403).json({ error: "csrf_violation" });
  }
  next();
}
```
### Midday (Learn/Labs, ~3h)
- Review **RP-Initiated Logout** in OIDC; when to clear app session and call IdP end-session endpoint.
- Study **SameSite** + CORS interactions for cross-site POSTs.

### Afternoon (Drill/Test, ~3h)
- Tests: missing/invalid CSRF token blocked; `state`/`nonce` mismatch in callback → 401; logout clears cookie and invalidates session server‑side.
- Add Burp passive checks: headers present; verify `Set-Cookie` flags.

### Evening (Document/Share, ~2h)
- Update `docs/threats.md` with CSRF, fixation, and state/nonce attacks and your mitigations.
- Add **Burp project** under `/burp/week06-login.burp` capturing the login/logout baseline.

### Acceptance criteria
- CSRF protections enforced; tests green; Burp shows cookies with HttpOnly/Secure/SameSite.
- Logout works: app session cleared, IdP logout invoked.

---

# Day 5 — **MFA Step‑Up & ACR/Max_Age**

### Morning (Build, ~4h)
- Enable **TOTP** for user in IdP. Implement a **step‑up** route that redirects to IdP with `acr_values` or `max_age=0` (force re‑auth/MFA).
- Mark sensitive endpoints (`/transfer`, `/delete-account`) with middleware that checks recent MFA claim in session (e.g., `amr` or `acr`).

```ts
// app/src/auth/mfa.ts (sketch)
export function requireRecentMFA(windowSecs=300){
  return (req,res,next)=>{
    const mfaAt = req.session?.mfaAt;
    if (!mfaAt || (Date.now()-mfaAt) > windowSecs*1000){
      return res.status(401).json({ stepUpRequired: true });
    }
    next();
  }
}
```
### Midday (Learn/Labs, ~3h)
- Read IdP docs for **ACR** values and **AMR** claims; understand how to store proof of MFA in session claims.
- Decide UX: how to prompt for step‑up and persist the timestamp securely.

### Afternoon (Drill/Test, ~3h)
- Tests: calling sensitive route without step‑up returns 401 with `stepUpRequired`; after step‑up, call succeeds within window then expires.
- Negative test: replaying an old step‑up outside window fails.

### Evening (Document/Share, ~2h)
- Update dashboards: count of step‑ups, failures, and window expiries; unusual patterns alerting placeholder.
- Document recovery paths if users lose MFA devices (admin-only flow).

### Acceptance criteria
- SStep‑up enforced on sensitive actions; tests simulate full flow.
- Metrics show step‑ups over time; logs include `acr`/`amr` evidence.

---

# Day 6 — **Burp Macros, Session Rules & Abuse Tests**

### Morning (Build, ~4h)
- Record a **Burp Macro** to perform login (follow redirects, capture anti-CSRF if present).
- Create **Session Handling Rules** so Repeater requests stay authenticated and refresh when tokens expire.

### Midday (Learn/Labs, ~3h)
- Review PortSwigger docs: macros, handling post-auth flows, cookie jar usage.
- Plan **negative tests** in Burp: reuse refresh token after rotation; use cookie after logout; cross-site POST without CSRF.

### Afternoon (Drill/Test, ~3h)
- Run negative tests and capture evidence with **Comparer** (before/after).
- Export the Burp project `.burp` file and check into `/burp`.

### Evening (Document/Share, ~2h)
- Add `docs/report-week06.md` summarizing abuses, results, and fixes with screenshots.
- Link Burp file and test scripts in README.

### Acceptance criteria
- Burp macro works; session rules keep Repeater authenticated.
- Replay attempts (cookie post-logout / old refresh token) fail with clear 401/403 and logs.

---

# Day 7 — **Mini‑Project & Release: Auth Baseline**

### Morning (Build, ~4h)
- Polish: secure headers, error format, OpenAPI auth sections (`securitySchemes`, per‑route `security`).
- Add **idempotency key** requirement to all mutating endpoints (ties to Week 8).

### Midday (Learn/Labs, ~3h)
- Run a clean install; re-execute all tests; simulate refresh reuse and step‑up again.
- Verify logs and dashboards are populated; export Grafana panels JSON.

### Afternoon (Drill/Test, ~3h)
- Create a **CHANGELOG**; tag **v0.6.0** release; attach Burp project and screenshots.
- Optional deploy to a free platform via reverse proxy; keep IdP local.

### Evening (Document/Share, ~2h)
- Publish a 2–3 page **auth report** mapping controls to OWASP/API items and evidence of tests/detections.
- Open follow-up issues for DPoP/MTLS sender-constrained tokens (future work).

### Acceptance criteria
- Release includes Burp file, tests, dashboards, and docs; all checks green.
- Auth flows are reproducible with scripts and diagrams.


---

## How this week advances your cybersecurity path
- **API & AppSec:** You can build/assess modern auth stacks, detect common flaws, and write failing tests first.
- **Purple‑team:** You can script valid abuse (replay, reuse, CSRF) and prove non‑repro after fixes.
- **SecOps:** You’ve defined log fields and panels that real teams depend on (login/refresh/step‑up telemetry).


---

## References / Study Hubs
- [RFC 6749 – OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 – PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [JWT (RFC 7519)](https://datatracker.ietf.org/doc/html/rfc7519)
- [MDN: Cookies, SameSite, HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies)
- [Keycloak Docs](https://www.keycloak.org/documentation)
- [openid-client (Node)](https://github.com/panva/node-openid-client)
- [Auth0: Refresh token rotation & reuse detection](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)
- [PortSwigger: Macros & Session Handling](https://portswigger.net/burp/documentation/desktop/settings/sessions)

## Similar GitHub repos / inspiration
- [panva/node-openid-client examples](https://github.com/panva/node-openid-client/tree/main/docs)
- [keycloak/keycloak-quickstarts](https://github.com/keycloak/keycloak-quickstarts)
- [oauth2-proxy/oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) (reverse-proxy pattern)
- [expressjs/session](https://github.com/expressjs/session)
- [redis/ioredis](https://github.com/redis/ioredis)

## Rubric (Week 6)
- **Flows**: PKCE login works; logout clears app & IdP; state/nonce verified.
- **Sessions**: HttpOnly+Secure+SameSite cookies; rotation on login; fixation test present.
- **Tokens**: refresh rotation + reuse detection; family revoke on reuse; replay after logout blocked.
- **MFA**: step‑up enforced for sensitive actions; `acr/amr` proof present; time window enforced.
- **Evidence**: Burp macro/session rules; negative tests; dashboards; mini report; v0.6.0 release.

