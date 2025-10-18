# Week 13 — **Kali Ops & Recon**: Nmap → httpx → ffuf → Burp (Extra‑Deep, Real‑World Examples)

_Generated: October 18, 2025_

> **Theme:** Build a **chainable recon pipeline** that starts with host discovery and ends with authenticated exploitation in Burp. You’ll:
> 1) scan & fingerprint with **Nmap**,
> 2) confirm live HTTP(S) with **httpx**,
> 3) discover content/parameters with **ffuf**, and
> 4) pivot into **Burp** (macros + session rules) for proof‑grade testing. We’ll use **three realistic case studies** to keep it practical.

> **Ethics:** Only test assets you own or have written permission for. Tread lightly (rate limits, off‑hours), log everything, and stop on impact.

---

## Outcomes
- Run **repeatable recon** that produces machine‑readable artifacts (XML/CSV/JSONL) and cleanly feeds Burp.
- Derive **targets** from Nmap (host:port/proto) → URLs with **httpx** and filter by tech stack headers/banners.
- Use **ffuf** for endpoint & parameter discovery with recursion and extensions, and pipe requests into Burp via `-replay-proxy`.
- Operationalize **Burp** for authenticated testing of discovered surfaces (Param Miner, Autorize, Turbo Intruder).
- Prove value with **three case studies**: API spec leakage, backup/file exposure, and multi‑tenant IDOR (BOLA).
- Publish `week13-kali-ops-recon` with scripts, wordlists, Burp project, evidence, and a field report.

## Repository layout (this week)

```
/week13-kali-ops-recon
  ├─ scans/
  │  ├─ nmap/                      # -oA outputs
  │  └─ live/                      # httpx outputs
  ├─ scripts/
  │  ├─ nmap_http_targets.sh       # parse XML → targets list
  │  ├─ httpx_to_urls.sh           # build https/http URL lists
  │  ├─ ffuf_content.sh            # content discovery (recursing)
  │  ├─ ffuf_params.sh             # parameter discovery
  │  └─ enrich_jsonl.py            # merge outputs → JSONL for dashboards
  ├─ wordlists/
  │  ├─ endpoints.txt
  │  ├─ backups.txt
  │  ├─ params.txt
  │  └─ extensions.txt
  ├─ burp/
  │  ├─ week13-recon.burp          # sanitized project with macros
  │  ├─ macros.json
  │  └─ session-rules.json
  ├─ docs/
  │  ├─ opsec.md
  │  ├─ pipeline.md
  │  ├─ case-studies.md
  │  ├─ cheatsheet.md
  │  └─ report-week13.md
  └─ README.md
```

---

# Day 1 — **OPSEC, Baseline & Scan Profiles (Kali)**

### Morning (Build, ~4h)
- Set **Kali workspace**: proxychains (if needed), tmux layouts, output folders. Set **custom UA** and **contact** header for tooling.
- Prepare **Nmap profiles** (from Week 10): fast sweep over your lab CIDR and thorough TCP on findings. Save `-oA scans/nmap/...`.

```bash
# Fast sweep → XML for parsing later
nmap -sn -PE -PA80,443 -PR 10.10.0.0/24 -oA scans/nmap/fast_sweep

# Thorough fingerprint on interesting hosts
nmap -sS -p- -T3 -Pn -sV --version-intensity 7 -sC -oA scans/nmap/host_10_10_0_23 10.10.0.23
```
### Midday (Learn/Labs, ~3h)
- Write **OPSEC** policy: time windows, `--max-rate`, `-T` levels, randomization (`--randomize-hosts`).
- Decide when to use `-Pn` (firewalled), and when to avoid UDP (prod).

### Afternoon (Drill/Test, ~3h)
- Run both profiles on lab. Snapshot `services` (80/443/8080/8443/9000, etc.).
- Export top 10 hosts by open web ports into a targets list.

### Evening (Document/Share, ~2h)
- Create `docs/pipeline.md` diagram: Nmap → httpx → ffuf → Burp, with artifacts and expected volume.
- Commit OPSEC rules (`docs/opsec.md`).

### Acceptance criteria
- Nmap outputs ready (`-oA`); target hosts selected; OPSEC written down.

---

# Day 2 — **Parse Nmap → Build HTTP(S) Target List with httpx**

### Morning (Build, ~4h)
- Script **XML parsing** → `host:port` for services `http, https, http-proxy, ssl/http`.
- Use **httpx** to check liveness, follow redirects, and capture tech headers (server, x-powered-by, title, status, tls info).

```bash
# scripts/nmap_http_targets.sh
xmllint --xpath "//host[ports/port/service[@name='http' or @tunnel='ssl' or contains(@name,'https')]]/address/@addr" scans/nmap/host_*.xml 2>/dev/null | sed -E 's/ addr="/\n/g;s/"//g' | awk 'NF' > scans/live/http_hosts.txt

# scripts/httpx_to_urls.sh
cat scans/live/http_hosts.txt | httpx -silent -title -tech-detect -status-code -follow-redirects -json -ports 80,443,8080,8443,9000,9443   -H 'User-Agent: Week13Recon/1.0' -H 'X-Contact: security@example.test'   > scans/live/httpx.json
jq -r '.url' scans/live/httpx.json > scans/live/urls.txt
```
### Midday (Learn/Labs, ~3h)
- Choose **filters**: keep only `200/301/302/401/403` and tech stacks you care about (e.g., `spring`, `nginx`, `express`).
- Prioritize **admin/login** paths and anything with **/api**, **/graphql**, **/swagger**, **/v3/api-docs**.

### Afternoon (Drill/Test, ~3h)
- Produce **url clusters** by tech for targeted wordlists (e.g., Java vs Node vs PHP extensions).
- Save `urls.txt` and shortlisted `urls_hot.txt` for ffuf.

### Evening (Document/Share, ~2h)
- Add `docs/cheatsheet.md` entries for httpx flags you used and why (redirects, JSON output).

### Acceptance criteria
- httpx outputs live URLs with titles, status, tech; hotlist compiled.

---

# Day 3 — **ffuf Content Discovery (Recursion + Extensions) → Burp**

### Morning (Build, ~4h)
- Curate **wordlists**: `endpoints.txt` (api, admin, health, metrics), `extensions.txt` (json, yaml, bak, zip), `backups.txt` (db.zip, site.tar.gz).
- Run **ffuf recursion** on hot URLs; stream ALL requests through Burp using `-replay-proxy http://127.0.0.1:8080` for capture.

```bash
# scripts/ffuf_content.sh (example run)
ffuf -w wordlists/endpoints.txt:FUZZ -w wordlists/extensions.txt:EXT -u https://target.test/FUZZ.EXT   -recursion -recursion-depth 1 -e .json,.yaml,.yml,.zip,.bak   -mc 200,204,206,301,302,401,403 -fs 0   -H 'User-Agent: Week13Recon/1.0'   -rate 100 -t 50   -replay-proxy http://127.0.0.1:8080   -of csv -o scans/live/ffuf_content.csv
```
### Midday (Learn/Labs, ~3h)
- Use **response length & words** to triage (`-fw`, `-fl`) and avoid 302/403 noise; sample suspicious 403s in Burp (authZ).
- Note **content‑type** mismatches and **CORS** responses for later tests.

### Afternoon (Drill/Test, ~3h)
- In **Burp**, tag imported ffuf traffic; create **site folders** (/api, /admin, /internal).
- Run **Param Miner** on interesting endpoints; enable passive checks.

### Evening (Document/Share, ~2h)
- Commit `ffuf_content.csv`; snapshot Burp project (`burp/week13-recon.burp`).
- Write why certain 403s are **signals** (auth required) rather than dead ends.

### Acceptance criteria
- ffuf results include at least 10 promising endpoints per host; all traffic captured in Burp.
- Burp Site map organized; Param Miner queued on candidates.

---

# Day 4 — **Parameter Discovery & Authenticated Chains (ffuf → Burp)**

### Morning (Build, ~4h)
- Enumerate **GET/POST params** with ffuf on a target route; try `?FUZZ=` and JSON bodies `{ "FUZZ": "X" }`.
- Use `-H 'Content-Type: application/json'` and **POST** mode (`-X POST -d @payload.json`).

```bash
# scripts/ffuf_params.sh (GET param hunt)
ffuf -u 'https://target.test/search?FUZZ=test' -w wordlists/params.txt -mc 200,400,403 -replay-proxy http://127.0.0.1:8080   -o scans/live/ffuf_params_get.csv -of csv

# JSON body param hunt (ensure the app actually parses JSON)
ffuf -u 'https://target.test/api/orders' -X POST -H 'Content-Type: application/json'   -d '{"FUZZ": "test"}' -w wordlists/params.txt -mc 200,400,403   -replay-proxy http://127.0.0.1:8080 -o scans/live/ffuf_params_post.csv -of csv
```
### Midday (Learn/Labs, ~3h)
- Switch to **Burp** for auth flows: import/login macros; set Session Handling Rules to refresh tokens/cookies.
- Configure **Autorize** for role‑swap testing (admin/user/guest).

### Afternoon (Drill/Test, ~3h)
- Validate parameters in **Repeater**; attempt **over‑posting** and **BOLA** ID swaps.
- Capture evidence (Comparer) for behavior diffs (authorized vs unauthorized).

### Evening (Document/Share, ~2h)
- Update `report-week13.md` with param findings and authZ results; map to OWASP API1/API3.
- Save Burp macro & rules exports.

### Acceptance criteria
- Confirmed useful parameters (not just reflected) with clear 4xx/2xx diffs.
- At least one **authZ finding** or strong negative result with evidence.

---

# Day 5 — **Case Studies (Step‑by‑Step, Real‑World)**

### Case Study A — **Leaked API Spec → Fuzz → Fix**
- Discovery: ffuf finds `/v3/api-docs` and `/swagger.yaml` on `orders-api.test`.
- Action: import OpenAPI into Postman/Burp; run **Schemathesis** (Week 5) to fuzz; found **over‑posting** in `PATCH /orders/{id}` (`role` field).
- Burp: confirm by sending body with `role=admin` (should be ignored/403).
- Fix path: enforce **allowlist** in handler; re‑run Schemathesis → non‑repro.

**Commands:**
```bash
schemathesis run https://orders-api.test/swagger.yaml --checks=all --junit-xml=schemathesis.xml
# Burp Repeater: PATCH /orders/123 with extraneous 'role' → expect 403/ignored
```
### Case Study B — **Backup/Artifact Exposure**
- Discovery: ffuf detects `/backup.zip` (403 → but 200 from `/backup_2023-10-01.zip`).
- Action: In Burp, request variations (`/backup/latest.zip`, `/backup.zip?download=1`).
- Result: 200 with ZIP index; mark **HIGH** if contains DB dump; stop, document, and **do not download** sensitive data beyond proof (content length + headers).
- Fix path: add deny rules and require auth; block indexing.

**Commands:**
```bash
ffuf -w wordlists/backups.txt -u https://portal.test/FUZZ -mc 200,301,302,403 -replay-proxy http://127.0.0.1:8080
```
### Case Study C — **Multi‑Tenant IDOR (BOLA)**
- Discovery: ffuf content + Param Miner reveal `/api/tenants/{id}/invoices` and param `userId`.
- Action: in Burp **Autorize**, replay `GET /api/tenants/tenantA/invoices?userId=alice` as `bob` (tenantB).
- Result: improper filtering (200 with Alice’s data). Use Comparer to show diff; capture correlation ID from logs if available (Week 12).
- Fix path: **DB RLS** (Week 7) + application checks + tests.

---

# Day 6 — **Turbo Intruder for Scale (Stateful) & Rate‑Limit Aware Probing**

### Morning (Build, ~4h)
- Adapt **Turbo Intruder** script for stateful auth (use Burp cookie jar) to enumerate IDs/objects carefully.
- Use **resource pools** and **throttling**; detect **length/status** anomalies.

### Midday (Learn/Labs, ~3h)
- Review rate‑limits and your Week 8 **idempotency**; avoid disrupting the service.
- Design **stop conditions** (e.g., 5 consecutive 429s or WAF block).

### Afternoon (Drill/Test, ~3h)
- Run a controlled enumeration on lab endpoints; confirm detections without exhausting limits.
- Capture timelines and error budget consumed.

### Evening (Document/Share, ~2h)
- Save Turbo Intruder script and CSV output; add to Burp findings pack.

### Acceptance criteria
- Script runs with session reuse and throttling; anomalies triaged; no outage in lab.

---

# Day 7 — **Mini‑Project & Release: Recon → Burp Techniques Pack**

### Morning (Build, ~4h)
- Package **scripts**, **wordlists**, **Burp project**, and **CSV/JSONL artifacts**.
- Create a **field report** with the three case studies, evidence (screenshots redacted), and fixes.

### Midday (Learn/Labs, ~3h)
- Re‑run the full chain on a fresh lab; confirm reproducibility and volumes.
- Add a **triage board**: `HIGH (exposure)`, `MEDIUM (suspicious 403)`, `LOW (noise)`.

### Afternoon (Drill/Test, ~3h)
- Generate **release v1.3.0-recon** and attach artifacts.
- Open issues to integrate discovery into CI (safe lists) and to auto‑import into Burp.

### Evening (Document/Share, ~2h)
- Update `docs/case-studies.md` with root causes and **defense tie‑backs**: Week 5 (schema), Week 7 (RLS), Week 8 (limits), Week 12 (monitoring).

### Acceptance criteria
- Release contains scripts, Burp project, wordlists, CSV/JSONL outputs, and report. Repro on clean VM succeeds.


---

## References / Study Hubs
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [httpx (ProjectDiscovery)](https://github.com/projectdiscovery/httpx)
- [ffuf](https://github.com/ffuf/ffuf) (content & param discovery)
- [PortSwigger Academy](https://portswigger.net/web-security) & Burp docs
- [Param Miner](https://portswigger.net/bappstore/590a2c...), [Autorize](https://github.com/Quitten/Autorize), [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)

## Rubric (Week 13)
- **Pipeline**: Nmap → httpx → ffuf → Burp executed with artifacts and filters.
- **Discovery**: ≥10 high‑signal endpoints per hot host; param list with 2–3 confirmed inputs.
- **AuthZ**: At least one confirmed (or well‑proved negative) authorization test with evidence.
- **Case studies**: Replicated step‑by‑step; fixes documented; ethical boundaries maintained.
- **Release**: v1.3.0‑recon with scripts/wordlists/Burp project and field report.

