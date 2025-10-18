# Week 05 — **API Security I: REST/OpenAPI/Testing & Fuzzing** (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Go **spec‑first** and build an end‑to‑end API testing rig that proves security at the edges: schema validation, negative testing, fuzzing, discovery of hidden surfaces, and auth harnesses for BOLA/BOPLA checks. You’ll ship a mini vulnerable branch to exploit (then fix) and wire everything into CI (Spectral + Schemathesis + ZAP Baseline + oasdiff + Semgrep). Maps to **OWASP Web A03/A05/A09** and **OWASP API API1/API3/API4/API5/API8**.

---

## Outcomes
- Write/own an **OpenAPI 3.1** spec for a small multi‑tenant API (users, items, orders).
- Implement **edge validation** tied to OpenAPI; enforce `additionalProperties: false`; normalize inputs.
- Build **negative tests** and **schema‑based fuzz** (Schemathesis) to catch type confusion, boundary, and content‑type tricks.
- Discover **undocumented** endpoints/params with **ffuf/httpx** and **Param Miner (Burp)** and keep spec in sync.
- Create an **auth harness** with multiple users/tenants to test **BOLA/BOPLA** and function‑level access rules.
- Add **rate limits, size/time caps**, idempotency on mutating routes, and **429/too‑big** tests.
- CI gates: **Spectral** lint, **Schemathesis** (JUnit), **ZAP Baseline** (passive), **oasdiff** (breaking changes), and **Semgrep** (handlers must call `authorize`).
- Publish `week05-api-test-fuzz-lab` with a vuln branch + report.

## Repository layout (this week)

```
/week05-api-test-fuzz-lab
  ├─ app/
  │  ├─ src/
  │  │  ├─ index.ts|js
  │  │  ├─ routes/
  │  │  ├─ middleware/
  │  │  └─ lib/
  │  ├─ openapi.yaml
  │  ├─ package.json
  │  └─ .semgrep.yml
  ├─ tests/
  │  ├─ schemathesis/            # property-based tests from OpenAPI
  │  ├─ dredd/                   # contract tests (optional)
  │  ├─ negative/                # custom negative tests
  │  ├─ discovery/               # ffuf/httpx scripts & findings
  │  └─ auth/                    # multi-user/tenant harness
  ├─ ci/
  │  ├─ spectral.yaml
  │  ├─ zap-baseline.yaml
  │  └─ github-actions.yml
  ├─ wordlists/
  │  ├─ endpoints.txt
  │  └─ params.txt
  ├─ burp/
  │  └─ week05-passive.burp
  ├─ docs/
  │  ├─ threat-map.md
  │  ├─ test-plan.md
  │  ├─ owasp-matrix.md
  │  └─ report-week05.md
  └─ README.md
```

---

# Day 1 — **Spec‑First & Mocking, then Contract Tests**

### Morning (Build, ~4h)
- Design **OpenAPI 3.1** with 6–10 endpoints: `/auth/login`, `/users/{id}`, `/tenants/{id}/items`, `/orders`, `/orders/{id}`, `/admin/metrics` (admin‑only).
- Model **schemas** with strict types, enums, min/max, formats; set `additionalProperties: false` to prevent over‑posting (API3/BOPLA).
- Add **error schema** (problem+json style) for 4xx/5xx with `traceId`/`cid`.

### Midday (Learn/Labs, ~3h)
- Spin up a **mock** (Prism or openapi‑backend) so you can test clients without the app.
- Read OpenAPI features: `oneOf/anyOf`, `nullable`, `pattern`, `style=form|simple`, parameter encoding rules.

### Afternoon (Drill/Test, ~3h)
- Run **Dredd** or **Schemathesis** in `--checks=all` mode against the mock to ensure the **spec is self‑consistent**.
- Commit `docs/test-plan.md` describing success/negative paths per route.

### Evening (Document/Share, ~2h)
- Commit `openapi.yaml` and mock config; include a minimal **changelog** section describing design choices.
- Add a diagram (Mermaid) of resource relationships & tenant boundaries.

### Acceptance criteria
- OpenAPI validates; mock responds; contract checks pass; docs committed.
- `additionalProperties: false` present on all request bodies with allowlists.

---

# Day 2 — **Edge Validation + Schema‑Based Fuzzing (Schemathesis)**

### Morning (Build, ~4h)
- Wire **express-openapi-validator** (or zod/joi adapter) to validate **every request** and **response** against OpenAPI.
- Return 400 on mismatches (never 500), with sanitized problem+json body and correlation ID.

```js
// app/src/index.js (snippet)
import { OpenApiValidator } from 'express-openapi-validator';
import express from 'express';
import bodyParser from 'body-parser';

const app = express();
app.use(bodyParser.json({ limit: '256kb' }));

new OpenApiValidator({
  apiSpec: './openapi.yaml',
  validateRequests: true,
  validateResponses: true
}).install(app);
```
### Midday (Learn/Labs, ~3h)
- Install **Schemathesis**; read about **hypothesis** strategies and custom hooks (headers, auth).
- Plan **custom checks**: unexpected 500s, missing headers, content‑type confusion, huge numbers/strings.

### Afternoon (Drill/Test, ~3h)
- Write `tests/schemathesis/test_api.py`: run against app, seed auth header, set rate limit delays, and record **JUnit** results.
- Add checks for **boundary values** (min/max, pattern violations), enum out‑of‑set, and random extra fields (should be rejected).

```python
# tests/schemathesis/test_api.py (snippet)
import schemathesis as st
schema = st.from_path("app/openapi.yaml")

@schema.parametrize()
def test_api(case):
    case.headers = {"Authorization": "Bearer TESTTOKEN"}
    response = case.call()
    case.validate_response(response)
```
### Evening (Document/Share, ~2h)
- Save JUnit XML + HTML report artifacts; summarize top failures and fixes.
- Update `owasp-matrix.md`: A03/API3 mitigated by strict schema + allowlists.

### Acceptance criteria
- Edge validators enabled for all routes; Schemathesis runs & reports.
- 500s eliminated for malformed inputs; 400s are consistent with error schema.

---

# Day 3 — **Discovery: Hidden Endpoints & Parameters**

### Morning (Build, ~4h)
- Create **ffuf** wordlists for `wordlists/endpoints.txt` & `wordlists/params.txt`; include common admin/debug names.
- Write a small **httpx** (ProjectDiscovery) workflow to crawl your base URL and collect candidate endpoints.

### Midday (Learn/Labs, ~3h)
- Plan scopes: only your lab hosts. Configure ffuf throttle (rate/sleep) to avoid DoS on your dev stack.
- Read **Burp Param Miner** docs to understand how hidden params get discovered.

### Afternoon (Drill/Test, ~3h)
- Run ffuf & httpx against your app; log **404/403/200** findings and create issues for undocumented endpoints.
- Update **OpenAPI** to reflect any legit routes; add **deny** rules for debug paths.

### Evening (Document/Share, ~2h)
- Commit discovery reports to `tests/discovery/` and link in README.
- Add an **API surface inventory** panel (count by status code, by prefix).

### Acceptance criteria
- Discovery yields a **report**; spec updated; debug routes blocked by default.
- Documented **denylist** or auth requirement for any sensitive path.

---

# Day 4 — **Auth Harness & Access Control Tests (BOLA/BOPLA/Function)**

### Morning (Build, ~4h)
- Seed test data: at least **2 tenants**; users `alice` (tenant A), `bob` (tenant B), `admin` (global).
- Create `tests/auth/harness.js` to obtain tokens/cookies for each role; export helpers to attach headers.

```js
// tests/auth/harness.js (sketch)
export async function getUserTokens(role='alice'){ /* login flow here */ }
export function as(role){ return { headers: { Authorization: `Bearer ${getUserTokens(role).access}` } } }
```
### Midday (Learn/Labs, ~3h)
- Review **API1 (BOLA)** and **API3 (BOPLA)** examples; design ID swap and over‑posting tests.
- Mass assignment defense: use allowlist mapping or strip unknown/immutable fields on update.

### Afternoon (Drill/Test, ~3h)
- Write tests: `alice` cannot read/update `bob`’s resource (should be 403/404).
- Write tests: client over‑posts a `role` or `tenantId` field → ignored or 403; assert DB didn’t change restricted fields.

```js
// app/src/routes/items.js (allowlist)
const ALLOWED = ['name','price','description'];
const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => ALLOWED.includes(k)));
```
### Evening (Document/Share, ~2h)
- Add logs for **403** with user/tenant/cid; create a dashboard panel for cross‑tenant attempts.
- Update `owasp-matrix.md` with test names & log queries.

### Acceptance criteria
- BOLA and over‑posting tests exist and pass; function‑level admin route blocked to normal users.
- Unknown/immutable fields never persisted; verified by test & DB query.

---

# Day 5 — **Injection & Content‑Type Confusion (Lab Branch)**

### Morning (Build, ~4h)
- Create a **vulnerable branch** (lab only) that concatenates a query or uses dynamic field names; add a route accepting multiple content types without validation.
- In main branch, ensure **parameterized queries** and enforced `Content-Type: application/json` + `charset` checks.

### Midday (Learn/Labs, ~3h)
- Review **A03 (Injection)** & API8 (Security misconfiguration of parsing); understand JSON vs form vs multipart pitfalls.
- Prepare **payload packs** (boolean/time‑based, NoSQL operators, UTF‑7/odd encodings).

### Afternoon (Drill/Test, ~3h)
- Use **Schemathesis** custom strategies to try special chars and long strings; assert 400 not 500.
- Manual: exploit the vuln branch (sqlmap or crafted payloads) then prove fix in main branch.

### Evening (Document/Share, ~2h)
- Write a short **attack→fix→non‑repro** note with logs (cid) and DB evidence.
- Keep the vuln branch private or clearly marked as lab‑only.

### Acceptance criteria
- Main branch resists payloads; returns structured 400s; logs evidence present.
- Vuln branch demonstrates exploit for learning; fixed branch verified.

---

# Day 6 — **CI Gates: Spectral, Schemathesis, ZAP, oasdiff, Semgrep**

### Morning (Build, ~4h)
- Add **Spectral** rules: require operationId, security on protected routes, 2xx/4xx/5xx response schemas, error schema reference.
- Add **oasdiff** to compare PR spec vs main; **fail on breaking changes** (removed/changed types).

```yaml
# ci/github-actions.yml (snippet)
jobs:
  api-security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Spectral lint
      run: npx @stoplight/spectral-cli lint app/openapi.yaml
    - name: Schemathesis
      run: st run app/openapi.yaml --junit-xml=schemathesis.xml --checks=all --stateful=links
    - name: ZAP Baseline
      run: docker run -t owasp/zap2docker-stable zap-baseline.py -t http://api:3000 -r zap.html
    - name: oasdiff (breaking)
      run: npx oasdiff breaking --fail-on-diff app/openapi.yaml main:app/openapi.yaml
```
### Midday (Learn/Labs, ~3h)
- Study how to **triage** ZAP passive findings; map relevant ones to your controls matrix.
- Tune Spectral to your style; add ignore justifications in YAML.

### Afternoon (Drill/Test, ~3h)
- Introduce a deliberate **breaking change** in spec; confirm CI fails; then fix.
- Introduce a missing `authorize` call and watch **Semgrep** block the PR.

### Evening (Document/Share, ~2h)
- Publish CI artifacts (JUnit, ZAP HTML) with the release; add badge to README.
- Update `test-plan.md` to reflect automated vs manual checks.

### Acceptance criteria
- CI blocks merges on Spectral/ZAP High/Critical/Semgrep violations and breaking spec diffs.
- Artifacts attached; PR template instructs devs on resolving failures.

---

# Day 7 — **Mini‑Project & Release: API Test & Fuzz Lab**

### Morning (Build, ~4h)
- Polish README: how to run mock → app → tests; how to reproduce discovery; how to read reports; how to toggle vuln branch for demos.
- Add dashboards (status codes by route, 400/403 spikes, validation errors, rate limit hits).

### Midday (Learn/Labs, ~3h)
- Final run from scratch; capture timings; fix flakes; ensure deterministic seeds for Schemathesis where useful.
- Optionally deploy to a cheap host; never expose vuln branch.

### Afternoon (Drill/Test, ~3h)
- Generate **release artifacts**: ZAP report, JUnit XML, discovery findings, oasdiff output, screenshots.
- Tag **v0.5.0** and create a GitHub Release.

### Evening (Document/Share, ~2h)
- Publish a 2–3 page **week05 report** mapping tests/detections to OWASP API items (API1/3/4/5/8).
- Open issues for Week 6 (OIDC), Week 7 (RLS), Week 8 (Rate/Idempotency races).

### Acceptance criteria
- Release includes test reports, ZAP HTML, discovery outputs, and docs.
- Spec/tests/CI all pass; vuln branch clearly documented and isolated.


---

## How this week advances your cybersecurity path
- **AppSec**: You can prove your API enforces schemas and limits with tests, not opinions.
- **API Security**: You can detect BOLA/BOPLA & misconfig through harnessed tests and discovery workflows.
- **Purple‑team**: You have a vuln branch to demonstrate exploit → fix → non‑repro with evidence.
- **SecOps**: Dashboards/logs designed for detection – validation failures, 403 spikes, rate limits.


---

## References / Study Hubs
- [OpenAPI 3.1](https://spec.openapis.org/oas/latest.html)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [express-openapi-validator](https://github.com/cdimascio/express-openapi-validator-example)
- [Stoplight Prism (mock)](https://github.com/stoplightio/prism)
- [Schemathesis](https://schemathesis.readthedocs.io/)
- [Dredd](https://dredd.org/en/latest/)
- [Spectral](https://github.com/stoplightio/spectral)
- [oasdiff](https://github.com/Tufin/oasdiff)
- [ZAP Baseline Docker](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [ffuf](https://github.com/ffuf/ffuf) & [httpx](https://github.com/projectdiscovery/httpx)
- [Burp Param Miner](https://github.com/PortSwigger/param-miner)

## Similar GitHub repos / inspiration
- [OWASP crAPI](https://github.com/OWASP/crAPI) (intentionally vulnerable API)
- [cdimascio/express-openapi-validator-example](https://github.com/cdimascio/express-openapi-validator-example)
- [stoplightio/prism](https://github.com/stoplightio/prism)
- [schemathesis/schemathesis](https://github.com/schemathesis/schemathesis)
- [apiaryio/dredd](https://github.com/apiaryio/dredd)
- [returntocorp/semgrep-rules](https://github.com/returntocorp/semgrep-rules)

## Rubric (Week 5)
- **Spec**: OpenAPI complete; strict schemas; deny extra properties; error schema standardized.
- **Tests**: Schemathesis covers all operations; negative tests for type/bounds/content‑type; auth harness for BOLA/BOPLA.
- **Discovery**: ffuf/httpx run book & findings; spec updated; denies in place for debug paths.
- **CI**: Spectral/Schemathesis/ZAP Baseline/oasdiff/Semgrep block risky PRs; artifacts published.
- **Release**: v0.5.0 with reports and documentation; vuln branch clearly labeled and isolated.

