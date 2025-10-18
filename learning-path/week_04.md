# Week 04 — **Web/AppSec Foundations + OWASP Mapping** (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Cement secure‑by‑default web/API patterns and map them to OWASP Top 10 (Web 2021 + API 2023). You will design, build, break, detect, and automate a hardened baseline for an Express/Node API (or your preferred stack) with clear threat models, abuse‑case tests, and CI gates (ZAP baseline + Semgrep). Burp is used for passive/targeted manual verification this week; full Burp mastery weeks follow later.

---

## Outcomes
- Threat model your API (dataflows, trust boundaries, abuse stories) and convert risks into backlog issues.
- Ship a **secure baseline**: headers (CSP/HSTS), error handling, structured logging with correlation IDs, rate limiting, request size limits, schema validation at the edge.
- Build **negative tests** for common classes (type confusion, boundary, object access, idempotency) mapped to OWASP items.
- Stand up **ZAP Baseline** in CI and **Semgrep** rules to enforce authZ checks and dangerous‑sink bans.
- Document how each control mitigates OWASP risks and add detection hooks (logs/metrics) to verify in practice.
- Publish `week04-secure-app-baseline` with working app, tests, ZAP/semgrep configs, and a mini report.

## Repository layout (this week)

```
/week04-secure-app-baseline
  ├─ app/
  │  ├─ src/
  │  │  ├─ index.ts|js
  │  │  ├─ routes/
  │  │  ├─ middleware/
  │  │  └─ lib/
  │  ├─ test/
  │  │  ├─ unit/
  │  │  └─ negative/
  │  ├─ openapi.yaml
  │  ├─ package.json
  │  └─ .semgrep.yml
  ├─ ci/
  │  ├─ zap-baseline.yaml
  │  └─ github-actions.yml
  ├─ docs/
  │  ├─ threat-model.md
  │  ├─ abuse-cases.md
  │  └─ controls-matrix.md  # OWASP -> Control -> Test -> Log
  ├─ dashboards/
  │  └─ panels.json         # status codes, errors, rate limit hits
  └─ README.md
```

---

# Day 1 — **Threat Modeling & Controls Matrix**

### Morning (Build, ~4h)
- Draw a **Mermaid** dataflow diagram (DFD) with trust boundaries: Client ↔ Reverse Proxy ↔ API ↔ DB ↔ IdP (OIDC). Mark sensitive stores (PII, tokens).
- Create `docs/threat-model.md` with sections: *Assets*, *Actors*, *Entry Points*, *Dataflows*, *Abuse Stories*, *Existing Controls*, *Gaps*.
- Seed `docs/controls-matrix.md`: a table mapping **OWASP items** to **preventive** and **detective** controls + **tests** + **logs**.

### Midday (Learn/Labs, ~3h)
- Read **OWASP Top 10 (Web 2021)** summaries (A01–A10) and **OWASP API Top 10 (2023)** (API1–API10). Write 1–2 sentence *risk‑in‑your‑context* blurbs.
- Pick 2 PortSwigger Academy labs you will replicate conceptually in your code this week (e.g., Broken Access Control scenario, basic SQLi).

### Afternoon (Drill/Test, ~3h)
- Convert abuse stories into **falsifiable tests**: list 6 negative checks you will implement (IDOR, over‑posting, boundary overflow, rate abuse, replay, SSRF).
- Create GitHub issues labeled `abuse-case` with acceptance criteria and links to tests you will add.

### Evening (Document/Share, ~2h)
- Commit diagrams, docs, and issues. Add a *How to read the matrix* section explaining your evidence columns (test/log).
- Record a short walkthrough of the model and controls matrix.

### Why are we doing this?
Threat modeling prevents **cargo‑cult controls**. The matrix ensures every control has a **test** and a **signal** so you can detect failures and regressions.

### Real‑world mapping
- AppSec program backlogs and architecture reviews.
- Audit/compliance evidence for design‑level controls.

### Acceptance criteria
- `threat-model.md` with DFD and at least 10 abuse stories.
- `controls-matrix.md` with 10 rows mapping OWASP items to tests and logs.

---

# Day 2 — **Security Headers, Error Handling, and Logging**

### Morning (Build, ~4h)
- Add **Helmet** (or equivalent) for basic headers; implement **CSP** (script/style allowlists, `frame-ancestors 'none'`).
- Enable **HSTS** with preload (lab) and secure cookies (if any).
- Add centralized **error handler** that returns sanitized JSON while logging stack traces to stderr (never to clients).
- Implement **correlation IDs** (per‑request UUID in header + context); propagate to logs.

```js
// app/src/middleware/security.js (Express example)
import helmet from "helmet";
import { v4 as uuidv4 } from "uuid";

export function correlation(req, res, next) {
  const cid = req.header("X-Request-ID") || uuidv4();
  res.setHeader("X-Request-ID", cid);
  req.correlationId = cid;
  next();
}

export const securityHeaders = [
  helmet(), // sensible defaults
  helmet.hsts({ maxAge: 15552000, preload: true }),
  helmet.frameguard({ action: "deny" }),
  helmet.referrerPolicy({ policy: "no-referrer" })
];

export function errorHandler(err, req, res, next) {
  console.error(JSON.stringify({ level: "error", cid: req.correlationId, err: err.message }));
  res.status(500).json({ error: "Internal error", cid: req.correlationId });
}
```
### Midday (Learn/Labs, ~3h)
- Study **CSP** report‑only vs enforce; craft a minimal policy for your routes.
- Review **HSTS** implications in dev vs prod; learn how to avoid locking yourself out.

### Afternoon (Drill/Test, ~3h)
- Add tests asserting presence of headers and **no stack traces** in responses.
- Make requests with and without `X-Request-ID`; verify correlation ID propagation in logs.

### Evening (Document/Share, ~2h)
- Update `controls-matrix.md`: A05 (Misconfig) mitigated by headers, A09 by structured logs/correlation IDs.
- Before/after header screenshots; sample sanitized error log in `examples/`.

### Acceptance criteria
- Headers present on all routes; CSP enforced on main pages/APIs.
- Errors are sanitized to clients; detailed stack traces only in server logs with CID.

---

# Day 3 — **Schema Validation, Limits, and Input Normalization**

### Morning (Build, ~4h)
- Validate **every request** at the edge using Zod/Joi/express‑openapi‑validator mapped to `openapi.yaml`.
- Set **request size limits** (JSON body size), **timeout**, and **rate limits** per route.
- Implement **idempotency keys** for state‑changing endpoints to prevent replay/race duplication.

```js
// app/src/middleware/limits.js
import rateLimit from "express-rate-limit";
export const limiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true });
export const jsonLimit = { limit: "256kb" };
export function requireIdempotencyKey(req, res, next){
  if(req.method !== "GET" && !req.header("Idempotency-Key")) {
    return res.status(400).json({ error: "Idempotency-Key required" });
  }
  return next();
}
```
### Midday (Learn/Labs, ~3h)
- Deep dive **OpenAPI** schema features: enums, oneOf/anyOf, string formats, parameter styles.
- Read about **deserialization** pitfalls and mass assignment.

### Afternoon (Drill/Test, ~3h)
- Write **negative tests**: wrong types, missing fields, extra unexpected properties; assert 400 not 500.
- Write a **replay test**: send same `Idempotency-Key` twice and assert the second call returns cached/duplicate‑blocked behavior.

### Evening (Document/Share, ~2h)
- Update controls matrix for **API4 (Resource Consumption)** and **A03 (Injection)** defenses via strict schemas and allowlists.
- Include a sample OpenAPI diff showing stricter types.

### Acceptance criteria
- All routes have validators tied to OpenAPI; request/response mismatch fails tests.
- Idempotency required on mutating routes and verified by tests.

---

# Day 4 — **Access Control Basics: Object & Function Level**

### Morning (Build, ~4h)
- Add a simple **role** system (`user`, `admin`) and decorate routes with **function‑level** checks.
- Implement **object‑level** checks by ensuring a `tenant_id`/`owner_id` predicate is applied to all read/write queries.
- Create a **policy helper** `authorize(resource, subject)` used by all handlers (even if Week 7 will add RLS in DB).

```js
// app/src/lib/authz.js
export function authorize({ actor, action, resourceOwnerId }) {
  if(actor.role === 'admin') return true;
  if(action === 'read' || action === 'update') {
    return actor.userId === resourceOwnerId;
  }
  return false;
}
```
### Midday (Learn/Labs, ~3h)
- Read **OWASP API1 (BOLA)** & API5 (Function‑level) examples; note test strategies (ID swaps; role‑based endpoints).
- Review **mass assignment** and **BOPLA** (property‑level) concerns; plan to block unknown/immutable fields.

### Afternoon (Drill/Test, ~3h)
- Add **negative tests**: cross‑tenant ID swaps; normal user hitting admin routes; over‑posting hidden fields (should be ignored or 403).
- Log all **403** with CID and principal details for detection tuning.

### Evening (Document/Share, ~2h)
- Update controls matrix: A01/API1 mapped to explicit checks + tests; reference log queries to spot repeated cross‑tenant attempts.
- Add `docs/abuse-cases.md` section for IDOR test patterns.

### Acceptance criteria
- All protected routes call a single **authorize** helper; Semgrep rule later will enforce presence near handlers.
- Negative tests prove IDOR and function‑level access are blocked.

---

# Day 5 — **Semgrep Rules + ZAP Baseline CI**

### Morning (Build, ~4h)
- Add **Semgrep** with rules: (1) handler must call `authorize`, (2) forbid raw SQL string concatenation, (3) deny `eval`/`child_process.exec` sinks.
- Create **.semgrep.yml** with custom patterns and exclusions; add a Makefile target.

```yaml
# app/.semgrep.yml (snippet)
rules:
- id: route-must-authorize
  patterns:
    - pattern: |
        app.$METHOD("$ROUTE", (req, res) => {
          $BODY
        })
    - pattern-not: |
        app.$METHOD("$ROUTE", (req, res) => {
          ... authorize(...)
        })
  message: "Route handler must call authorize()"
  severity: ERROR
  languages: [javascript, typescript]
```
### Midday (Learn/Labs, ~3h)
- Study **ZAP Baseline** scan; configure it to run against your dev server with **non‑destructive** passive checks.
- Review how to **suppress** known‑good alerts with justification (not blanket ignores).

### Afternoon (Drill/Test, ~3h)
- Add **GitHub Actions**: run Semgrep + ZAP Baseline on PR; fail on High/Critical.
- Introduce a deliberate failure (missing `authorize`) and watch CI fail; fix and re‑run.

### Evening (Document/Share, ~2h)
- Check in ZAP report artifact (HTML) in Releases; link from README.
- Controls matrix: log which findings the ZAP passive rules catch by default.

### Acceptance criteria
- CI blocks merges on missing `authorize` and on High/Critical passive alerts.
- ZAP report attached to workflow artifacts; documented suppression strategy.

---

# Day 6 — **Burp Passive Verification + Abuse‑Case Library**

### Morning (Build, ~4h)
- Run **Burp** in **passive** mode to verify headers, cookies, CSP, and error responses. Annotate Site Map by feature.
- Export a **suite of Repeater tabs** for canonical CRUD requests and save as a Burp project file in `/burp/` (folders by resource).

### Midday (Learn/Labs, ~3h)
- Complete 1–2 **PortSwigger** labs in Broken Access Control or Input Validation; replicate the exploit idea against your vulnerable branch, then prove fix.
- Read Burp docs: Logger and Comparer usage for before/after diffs.

### Afternoon (Drill/Test, ~3h)
- Add 6 **abuse‑case tests** (unit/integration): IDOR, over‑posting, invalid pagination, replay without idempotency key, huge JSON body, unexpected content type.
- Ensure each test logs a **security event** (with CID) on denial.

### Evening (Document/Share, ~2h)
- Publish `docs/abuse-cases.md` with examples, expected status codes, and log fields. Include sanitized Burp screenshots.
- Record a short demo: run tests, show ZAP/CI green, show Burp headers OK.

### Acceptance criteria
- Abuse‑case library contains ≥6 failing‑then‑fixed tests with clear names and evidence.
- Burp passive checks show expected headers/CSP/cookies correctly set.

---

# Day 7 — **Mini‑Project & Release: Secure App Baseline**

### Morning (Build, ~4h)
- Polish README: architecture diagram, getting started, **controls matrix excerpt**, how to read logs, and how to run CI locally.
- Create sample dashboards: status codes by route, 403 spikes, rate‑limit hits, request size rejections.

### Midday (Learn/Labs, ~3h)
- Do a fresh **from‑scratch** setup; run all tests and CI locally; capture timings and flakiness notes.
- Re‑run PortSwigger lab concepts against your app to ensure they fail as intended.

### Afternoon (Drill/Test, ~3h)
- Add a **CHANGELOG.md**; tag **v0.4.0**. Generate ZAP report and attach to the release.
- Optionally deploy to a free host (Render/Railway/Fly.io) with env‑guardrails.

### Evening (Document/Share, ~2h)
- Publish a 2–3 page **mini report** summarizing mitigated OWASP risks and how to test/observe them.
- Open issues for Week 5+ (API testing and fuzzing), Week 6 (OIDC), Week 7 (RLS).

### Acceptance criteria
- Release tagged with artifacts (ZAP report, screenshots, controls matrix, dashboard JSON).
- All tests pass; CI green; Burp passive checks OK.


---

## How this week advances your cybersecurity path
- **AppSec & API**: You now own a secure baseline with proofs (tests + logs).
- **Purple‑team**: You can create a vuln branch, exploit, then prove non‑repro with CI and Burp evidence.
- **SecOps/Monitoring**: Panels and logs are designed for detection engineering, not just dev convenience.


---

## References / Study Hubs
- [OWASP Top 10 (Web 2021)](https://owasp.org/Top10/)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [MDN: CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) & [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [Helmet](https://helmetjs.github.io/) / [express-rate-limit](https://github.com/nfriedly/express-rate-limit)
- [OpenAPI 3.1](https://spec.openapis.org/oas/latest.html) & [express-openapi-validator](https://github.com/cdimascio/express-openapi-validator-example)
- [Semgrep](https://semgrep.dev/) – writing custom rules
- [ZAP Baseline](https://www.zaproxy.org/docs/docker/baseline-scan/) – CI usage
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) – labs to mirror in your app

## Similar GitHub repos / inspiration
- [cdimascio/express-openapi-validator-example](https://github.com/cdimascio/express-openapi-validator-example)
- [helmetjs/helmet](https://github.com/helmetjs/helmet)
- [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy)
- [returntocorp/semgrep-rules](https://github.com/returntocorp/semgrep-rules)
- [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (for ideas later)

## Rubric (Week 4)
- **Design**: threat model with ≥10 abuse stories; controls matrix with tests/logs mapping.
- **Security**: headers (CSP/HSTS) enforced; sanitized errors; correlation IDs in logs; rate/size/time caps; edge validation tied to OpenAPI.
- **AuthZ**: all protected routes call `authorize`; BOLA/BOPLA tests present.
- **Automation**: Semgrep rules + ZAP Baseline block merges on serious issues.
- **Evidence**: ZAP report artifact; screenshots; dashboards; mini report released as v0.4.0.

