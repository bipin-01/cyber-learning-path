# Week 09 — **Burp Suite Mastery** (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Become deadly effective with **Burp Suite** for real‑world web/API testing. Build a repeatable Burp project and techniques pack: **scoping**, **authenticated workflows (macros + session handling rules)**, **manual exploitation (Repeater, Intruder variants, Turbo Intruder)**, **param discovery (Param Miner)**, **OAST/Collaborator** for SSRF/Out‑of‑band bugs, **JWT/GraphQL** workflows, **WebSockets/HTTP/2** idiosyncrasies, and **evidence‑grade reporting**. Map to **OWASP Web A01/A03/A05/A07/A08/A09** and **API1/3/4/5/8/9**.

> **Ethics:** Only test hosts you own or have explicit written permission to test. Scope tightly. Respect rate limits.

---

## Outcomes
- Create a **Burp project template** with Target scope, Proxy CA, logging (Logger++), and folders by feature/module.
- Master **authenticated testing**: record **macros** for login, use **Session Handling Rules** to refresh tokens/cookies, handle CSRF tokens, and keep Repeater/Intruder authenticated.
- Exploit and verify with **Repeater**, **Intruder** (Sniper/Battering Ram/Pitchfork/Cluster Bomb), **Grep - Match/Extract**, and **Turbo Intruder** for high‑speed, stateful attacks.
- Find hidden surface with **Param Miner**, **Content Discovery**, and **custom wordlists**; triage with Site map & Issue definitions.
- Use **Burp Collaborator** (and Collaborator Everywhere) to detect **SSRF, blind XXE, blind command injection**, and **out‑of‑band** behaviors.
- Test **JWT** & session flows (JWT Editor), **authorization** (Autorize), **GraphQL** (InQL/GraphQL Raider), **WebSockets** and **HTTP/2** nuances.
- Produce **evidence‑grade reports** with Comparer, embedded requests/responses, and PoCs generated from Burp (CSRF PoC, HTML/JS).
- Publish `week09-burp-mastery` with a Burp `.burp` project file, macro/rule exports, wordlists, checklists, and a mini‑report.

## Repository layout (this week)

```
/week09-burp-mastery
  ├─ burp/
  │  ├─ project.burp                 # sanitized demo project
  │  ├─ macros.json                  # exported macros
  │  ├─ session-rules.json           # exported session handling rules
  │  ├─ collaborator-notes.md
  │  └─ reports/
  │     ├─ findings.html
  │     └─ comparer/
  ├─ wordlists/
  │  ├─ endpoints.txt
  │  ├─ params.txt
  │  └─ headers.txt
  ├─ docs/
  │  ├─ setup.md                     # proxy cert, scope, SSL/TLS notes
  │  ├─ auth-workflows.md            # macros + session rules
  │  ├─ param-discovery.md
  │  ├─ oast-playbook.md             # Collaborator usage
  │  ├─ graphql-workflows.md
  │  ├─ websockets-http2.md
  │  └─ report-week09.md
  └─ README.md
```

---

# Day 1 — **Project Template, Scope & Capture Hygiene**

### Morning (Build, ~4h)
- Create a **fresh Burp project** with **Target scope** restricted to your lab host(s) and paths. Disable **out‑of‑scope** logging requests.
- Install extensions: **Logger++**, **Param Miner**, **JWT Editor**, **Autorize**, **Turbo Intruder**, **Burp Bounty** (optional), **GraphQL (InQL or GraphQL Raider)**.
- Configure **Proxy**: import Burp CA in your browser; enable **HTTP/2**; set **SSL pass‑through** exceptions for noisy hosts (CDNs, telemetry).
- Turn on **Target → Live tasks** for passive checks only (Pro), or rely on **Logger++** for traffic capture.

### Midday (Learn/Labs, ~3h)
- Read PortSwigger docs: **Target/Site map**, **Scope**, **Proxy**, **User Options → TLS**.
- Plan **folder structure** in Site map: `/auth`, `/api/users`, `/api/orders`, `/admin`.

### Afternoon (Drill/Test, ~3h)
- Browse through app flows to populate a clean **Site map**; annotate endpoints with **notes/tags** by risk (auth, object, admin).
- Export **project.burp** snapshot and commit to `/burp` (sanitized if needed).

### Evening (Document/Share, ~2h)
- Write `docs/setup.md` with screenshots (scope, CA, TLS) and your intercept workflow.
- Create a **checklist** of pre‑engagement setup items (scope, rate limits, safe hours).

### Why?
A clean project and explicit scope avoid noisy data and legal risk. Good capture hygiene accelerates triage and evidence production.

### Acceptance criteria
- Burp can intercept HTTPS traffic to the lab app; Site map shows organized folders; extensions installed and working.
- project.burp exported; setup documented with screenshots.

---

# Day 2 — **Authenticated Testing: Macros & Session Handling Rules**

### Morning (Build, ~4h)
- Record a **login macro** (Proxy → HTTP history → right‑click → Add to macro). Include CSRF token retrieval if present.
- Create **Session Handling Rules**: automatically run the login macro when a request returns 401/302 to login, or when a cookie is missing/expired.
- Add a **rule to add CSRF tokens** to state‑changing requests (use `Update parameter` from response of previous request).

### Midday (Learn/Labs, ~3h)
- Study **macro parameterization**: which fields vary (username, password, OTP)?
- Plan **account roles** (user/admin) and set up **separate macros** and **separate cookie jars**.

### Afternoon (Drill/Test, ~3h)
- Verify **Repeater** requests stay authenticated with the rule enabled (no manual cookie fixes).
- Create a **refresh token macro** path (if using OIDC): detect 401 on API call → run refresh flow → replay original request.

### Evening (Document/Share, ~2h)
- Export **macros.json** and **session-rules.json**; store under `/burp`.
- Write `docs/auth-workflows.md` with screenshots of the macro editor and rule conditions.

### Why?
Most high‑value tests require stable auth. Macros + rules allow **stateful** testing in Repeater/Intruder without constant re‑login.

### Acceptance criteria
- Repeater/Intruder remain authenticated for protected routes; automatic CSRF token injection works.
- Exported macros/rules committed and documented.

---

# Day 3 — **Surface Discovery: Param Miner, Content Discovery & Diffing**

### Morning (Build, ~4h)
- Run **Param Miner** against key routes to discover hidden parameters, headers (e.g., `X-Original-URL`, `X-HTTP-Method-Override`), and **transfer‑encoding quirks**.
- Use **Content Discovery** (Pro) or **ffuf** externally with the **Burp proxy** to find hidden endpoints; import results into Site map.

### Midday (Learn/Labs, ~3h)
- Customize wordlists to your app (feature names, internal terms).
- Learn **Comparer** for before/after response bodies and headers.

### Afternoon (Drill/Test, ~3h)
- Queue **Grep - Match** patterns (e.g., `admin`, `isAdmin`, `internal`, `debug`) to flag promising responses.
- Capture baseline responses, flip a header/param, and use **Comparer** to spot authZ or deserialization hints.

### Evening (Document/Share, ~2h)
- Write `docs/param-discovery.md` summarizing new params/endpoints with evidence screenshots.
- Open issues in your API repo to either document or deny discovered surfaces.

### Acceptance criteria
- At least 5 previously unknown parameters/endpoints identified or ruled out with evidence.
- Comparer folders show deltas for interesting toggles (header/param/body).

---

# Day 4 — **Manual Exploitation: Repeater, Intruder & Turbo Intruder**

### Morning (Build, ~4h)
- Master **Repeater**: craft minimal requests, toggle **HTTP/2** vs 1.1, experiment with **Transfer‑Encoding** and **Content‑Type** mismatches, and vary **Host**/**X‑Forwarded‑Host** for SSRF/confusion.
- Use **Grep - Extract** to pull CSRF tokens or IDs from prior responses into future attacks.

### Midday (Learn/Labs, ~3h)
- Intruder strategies: **Sniper** (one position), **Battering Ram** (same payload to all), **Pitchfork** (aligned lists), **Cluster Bomb** (cross product).
- Payload types: fuzz strings, numeric ranges, dates, JWTs (tweak claims/alg), wordlists for IDOR/object keys.

### Afternoon (Drill/Test, ~3h)
- Run **Turbo Intruder** scripts (stateful auth) to test high‑volume IDOR or enumeration with client‑side throttling bypass.
- Use **Resource Pool** & **Throttle** to avoid DoS; log status/length anomalies for triage.

### Evening (Document/Share, ~2h)
- Save Intruder/Turbo configs and payload sets; store results & top anomalies under `/burp/reports/`.
- Document your **false‑positive filters** and length/word heuristics.

### Acceptance criteria
- At least one confirmed bug or high‑quality negative result with evidence (status/length/headers).
- Turbo Intruder script stored and reproducible; rate limiting respected.

---

# Day 5 — **OAST/Collaborator, JWT/GraphQL & Authorization Testing**

### Morning (Build, ~4h)
- Enable **Burp Collaborator**; test endpoints likely to do SSRF/DNS/HTTP callbacks (image fetchers, PDF renderers). Document **interaction IDs** and timings.
- Use **Collaborator Everywhere** to seed headers/params; monitor for unexpected callbacks.

### Midday (Learn/Labs, ~3h)
- **JWT Editor**: tamper `alg`, `kid`, `aud`, `iss`; test **none/HS256 with known key** cases (lab only).
- **Autorize**: capture an authenticated baseline and replay as a lower‑priv user to hunt for **BOLA/FLA**.

### Afternoon (Drill/Test, ~3h)
- **GraphQL**: use **InQL/GraphQL Raider** to pull schema (if introspection open) and craft queries; test **batching**, **aliasing**, **deep nesting** for resource abuse (API4).
- **WebSockets** tab: replay messages, modify auth tokens, test **upgrade path** and **CSRF on WS** initiations.

### Evening (Document/Share, ~2h)
- Write `docs/oast-playbook.md` with screenshots of Collaborator interactions and endpoint notes.
- Add `graphql-workflows.md` with queries/mutations tested and mitigations.

### Acceptance criteria
- OAST yields either benign callbacks (expected) or zero; no unexpected outbound calls remain unexplained.
- JWT/Autorize tests produce clear **pass/fail** evidence for authZ integrity.

---

# Day 6 — **Evidence, PoCs & Reporting**

### Morning (Build, ~4h)
- Use **Generate CSRF PoC** (Engagement tools) for any CSRF‑suspect endpoint; validate in a **separate browser profile**.
- Capture **Comparer** diffs for vulnerable vs fixed behavior; include **full request/response** with sensitive data redacted.

### Midday (Learn/Labs, ~3h)
- Study **Issue definitions** (Burp) and **severity/likelihood** frameworks; map to OWASP items and CWE IDs.
- Learn **Report generation**; customize templates to include your screenshots and reproduction steps.

### Afternoon (Drill/Test, ~3h)
- Produce **findings.html** with 2–3 exemplar issues (or well‑argued non‑findings) including reproduction, impact, fix, and evidence.
- Export a **clean, sanitized** `project.burp` for submission.

### Evening (Document/Share, ~2h)
- Update `report-week09.md` summarizing tests, results, mitigations, and links back to prior weeks (schemas, RLS, headers).
- Checklist: handoff pack for engineering (routes, controls, fixes, regression tests).

### Acceptance criteria
- findings.html contains reproducible steps, evidence, and mapping to OWASP/CWE; sanitized project file included.
- PoCs (CSRF/IDOR/JWT) verified in isolated profile; screenshots/Comparer diffs attached.

---

# Day 7 — **Mini‑Project & Release: Burp Techniques Pack**

### Morning (Build, ~4h)
- Package a **techniques pack**: macros, session rules, param miner configs, Turbo Intruder scripts, wordlists, and reporting templates.
- Create a short **video walkthrough** (optional) showing authenticated Repeater flow and a Param Miner find → exploit → fix.

### Midday (Learn/Labs, ~3h)
- Final QA: import the project on a clean workstation; verify macros/rules function; run a quick passive check.
- Tag **v0.9.0**; ensure all exports and docs are present.

### Afternoon (Drill/Test, ~3h)
- Cross‑reference against **OWASP Web/API Top 10**; ensure at least one explicit test path per item relevant to your app.
- Optionally, integrate **Burp → Postman/Insomnia** via exported **.har** for dev reproducibility.

### Evening (Document/Share, ~2h)
- Publish the release with artifacts and `report-week09.md`.
- Open issues to fold proven tests into CI (Semgrep rules, negative tests) from Weeks 4–6.

### Acceptance criteria
- Release includes: `.burp` project, macro/rule exports, wordlists, Param Miner results, Turbo scripts, and findings report.
- Authenticated testing and param discovery reproducible on a clean machine.


---

## How this week advances your cybersecurity path
- **AppSec & Pentest**: You can run full‑fidelity authenticated tests, discover hidden surface, and produce exec‑credible evidence.
- **API Security**: You validate OWASP API1/3/4/5/8/9 via real requests, not assumptions.
- **Purple‑team**: Turbo Intruder + Collaborator give you scale and out‑of‑band reach for tricky bugs.


---

## References / Study Hubs
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Turbo Intruder (GitHub)](https://github.com/PortSwigger/turbo-intruder)
- [Param Miner (BApp)](https://portswigger.net/bappstore/590a2c...)
- [JWT Editor (BApp)](https://portswigger.net/bappstore/cc86c...)
- [Autorize (BApp)](https://github.com/Quitten/Autorize)
- [Logger++ (BApp)](https://portswigger.net/bappstore/...)
- [InQL / GraphQL Raider](https://portswigger.net/bappstore/)

## Similar GitHub repos / inspiration
- [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder)
- [almandin/fuxploider (upload fuzz ideas; use safely)](https://github.com/almandin/fuxploider)
- [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (for inspiration to translate to Burp payloads)

## Rubric (Week 9)
- **Setup**: Tight scope, CA installed, extensions configured; Site map organized.
- **Auth**: Macros + session rules keep Repeater/Intruder authenticated; CSRF token handling automatic.
- **Discovery**: Param Miner & Content Discovery yield new params/paths or well‑documented negatives.
- **Exploitation**: Intruder/Turbo runs with clear anomalies or confirmed bugs; rate/throttle respected.
- **OAST & Advanced**: Collaborator used appropriately; JWT/GraphQL/WS paths tested; **v0.9.0** release with findings.

