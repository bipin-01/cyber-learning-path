# Week 19 — **Capstone Build I**: Mini‑XDR/SIEM Platform (Sensors → Monitoring → Secure Backend → DFIR) — Deployable Online (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Build a deployable **mini‑XDR/SIEM** inspired by platforms like Palo Alto Cortex XSIAM / SentinelOne—on a smaller, open stack. It ingests logs from honeypots + hosts + network, normalizes events, runs detections/correlation, opens **cases**, and triggers **DFIR triage**. You’ll expose a safe **public honeynet front** to attract opportunistic traffic—but keep everything isolated and lawful.

> **Legal/OPSEC:** Use a **separate cloud account/project**. Strict **egress‑deny** from honeypots. Use clear banners and **terms**; don’t capture credentials beyond research necessity. Never execute unknown binaries. Respect provider ToS and applicable laws.

---

## Outcomes
- Deploy a **public-facing honeynet gateway** safely (low/medium interaction) feeding your pipeline.
- Stand up a **unified ingest** (Promtail/Grafana Agent → **Loki**) + optional long‑term store (**ClickHouse/OpenSearch**, optional).
- Normalize to a compact **event schema** (ECS‑lite) and tag to **ATT&CK** & **OWASP** where relevant.
- Author **detections/correlation** (Sigma→LogQL/DSL) and create **alerts** that open **cases** in a secure backend (OIDC/RLS).
- Integrate **DFIR tooling** (Week 11 & 18): push remote triage jobs (SSH/WinRM/JEA), attach artifacts, and track chain of custody.
- Publish `week19-capstone-mini-xdr` with infra diagrams, compose/K8s manifests (single‑node), API, case UI stubs, dashboards, and sample data.

## Repository layout (capstone, part I)

```
/week19-capstone-mini-xdr
  ├─ compose/
  │  ├─ docker-compose.yml            # Loki, Grafana, Postgres, API, Case UI, Promtail gateway
  │  ├─ loki-config.yml
  │  ├─ grafana-provisioning/
  │  │  ├─ datasources/
  │  │  └─ dashboards/
  │  └─ gateway/
  │     ├─ nginx.conf                 # TLS, rate limits, /honeynet/* routes only
  ├─ sensors/                          # public honeynet front (isolated VM/host)
  │  ├─ cowrie/                        # low-interaction SSH/Telnet
  │  ├─ opencanary/                    # FTP/HTTP/SMB...
  │  └─ honey-api/                     # inert API, token beacons
  ├─ backend/
  │  ├─ api/                           # FastAPI/Express: auth (OIDC), cases, detections, triage jobs
  │  ├─ detections/                    # Sigma rules + compiled queries (LogQL/DSL)
  │  ├─ workers/                       # alert→case, triage orchestration, enrichments (GeoIP/ASN)
  │  └─ db/                            # Postgres schema: cases, alerts, artifacts, RBAC/RLS
  ├─ ui/
  │  └─ case-console/                  # React minimal: alerts, cases, artifacts, queries
  ├─ dashboards/
  │  ├─ xdr-overview.json
  │  ├─ honeypot-ops.json
  │  ├─ auth-detectors.json
  │  └─ dfir-queue.json
  ├─ docs/
  │  ├─ architecture.md
  │  ├─ opsec.md
  │  ├─ schema.md                      # ECS‑lite mapping
  │  ├─ detections.md                  # queries + rationale
  │  ├─ dfir.md                        # triage playbooks
  │  ├─ deploy-cloud.md                # single-node online deploy
  │  └─ report-week19.md
  └─ README.md
```

---

# Day 1 — **Honeypot Basics (Public Front)** — your request

### Morning (Build, ~4h)
- Provision a **public VM** (separate project/VPC). Open only **22, 23, 80, 8080** (example). Apply **egress‑deny** SG/NSG; allow egress only to your **collector IP/port** for log shipping (TLS).
- Install **Cowrie** (SSH/Telnet) and **OpenCanary** (HTTP/FTP/SMB). Configure **safe banners** and fake accounts (no real creds).
- Ship logs with **Promtail** to your central **Loki** (Week 12). Label all events with `sensor`, `region`, `vpc`, `public=true`.

```yaml
# sensors/promtail-config.yml (public honeypot VM)
clients: [{ url: https://collector.yourlab.test/loki/api/v1/push }]
scrape_configs:
  - job_name: cowrie
    static_configs: [{ targets: [localhost], labels: { sensor: "cowrie01", region: "us-east", public: "true", __path__: "/var/log/cowrie/cowrie.json" } }]
  - job_name: opencanary
    static_configs: [{ targets: [localhost], labels: { sensor: "canary01", public: "true", __path__: "/var/log/opencanary.log" } }]
```
### Midday (Learn/Labs, ~3h)
- Draft **OPSEC**: what you collect, storage retention, disclosure, and rules for handling captured IPs / PII. No outbound connections from sensors.
- Smoke‑test with your Kali VM hitting SSH/HTTP; confirm logs in **Grafana Explore** with labels.

### Afternoon (Drill/Test, ~3h)
- Add **rate limits** / connection caps at the host firewall and reverse proxy (protect the VM).
- Create a basic **honeypot dashboard** (top users/passwords, commands, hits over time).

### Evening (Document/Share, ~2h)
- Record architecture and security controls in `docs/opsec.md` and `docs/architecture.md`; capture first signal screenshots.

### Acceptance criteria
- Public honeypot online; logs landing centrally; OPSEC doc written; dashboard shows live activity.

---

# Day 2 — **Platform Architecture & Schema (ECS‑lite)**

### Morning (Build, ~4h)
- Define **event schema** (`@timestamp`, `event.kind`, `event.category`, `src.ip`, `dst.ip`, `http.*`, `auth.*`, `process.*`, `rule.id/name`, `labels.*`).
- Create a **normalizer** (worker or Loki pipeline stages) that maps Cowrie/OpenCanary fields to schema; add **GeoIP/ASN** enrichment.

### Midday (Learn/Labs, ~3h)
- Plan data **retention tiers**: hot (Loki 7–14d), cold (ClickHouse/OpenSearch optional, 30–90d). Keep it simple for now: Loki only.
- Threat model platform surfaces: collector, API, UI, DB; tie to Week 14 (OIDC) and Week 17 (SSRF/RCE).

### Afternoon (Drill/Test, ~3h)
- Implement **labels** and `| json` pipelines; verify searchability and low cardinality.
- Draft `docs/schema.md` with field mapping tables and examples.

### Acceptance criteria
- Schema documented; normalizer working; events enriched with GeoIP/ASN; low‑cardinality labels verified.

---

# Day 3 — **Detections & Correlation (Sigma → Queries)**

### Morning (Build, ~4h)
- Select **5 core rules**: (1) SSH brute sustained; (2) first interactive shell on a sensor; (3) canary token used; (4) suspicious HTTP scanner UA; (5) first‑seen JA3. Save as Sigma + compiled LogQL queries.
- Create **correlations**: same `src.ip` hits honey‑API and Cowrie within 5m ⇒ **campaign** label.

### Midday (Learn/Labs, ~3h)
- Attach **ATT&CK** tags to rules (TA0006 Credential Access, TA0043 Recon, etc.). Record false‑positive handling.
- Set **Grafana alerts** to call backend **/alerts** webhook (Week 17 pattern) instead of email for case creation.

### Afternoon (Drill/Test, ~3h)
- Trigger synthetic events; confirm alerts create **cases** in Postgres via backend worker.
- Dashboard `xdr-overview.json`: alerts over time, top src.ip/ASN, rule hit tables.

### Acceptance criteria
- Rules compiled & active; correlation job runs; cases created automatically on alert; overview dashboard populated.

---

# Day 4 — **Secure Backend: API + Cases + Auth (OIDC)**

### Morning (Build, ~4h)
- Boot **API** (FastAPI/Express). Enable **OIDC** login (Week 14). Define tables: `alerts`, `cases`, `artifacts`, `triage_jobs`, `users` with **RLS** (Week 7).
- Expose endpoints: `GET /alerts`, `POST /cases`, `POST /cases/{id}/note`, `POST /triage/jobs` (Windows/Linux).

```sql
-- backend/db/schema (snippets)
CREATE TABLE cases(id uuid PRIMARY KEY, title text, status text, severity text, created_at timestamptz, owner text);
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
CREATE POLICY owner_or_admin ON cases USING (owner = current_setting('app.user', true) OR current_setting('app.role', true) = 'admin');
```
### Midday (Learn/Labs, ~3h)
- Implement **problem+json** error model; add **CORS/CSRF** as per Week 14; protect uploads (artifacts) with presigned URLs (Week 17).
- Add **idempotency keys** for alert→case creation to avoid duplicates.

### Afternoon (Drill/Test, ~3h)
- Write **contract tests** for endpoints; add **OpenAPI** spec and publish via `/docs`.
- Instrument API with **OTel logs** and LogQL exemplars to correlate with alerts.

### Acceptance criteria
- API with OIDC, RLS, idempotent case creation, and OTel logging; tests pass; OpenAPI rendered.

---

# Day 5 — **Case Console UI & Triage Orchestration**

### Morning (Build, ~4h)
- Create a minimal **React** case console: list alerts/cases, view details, attach artifacts, and trigger triage jobs.
- Job types: `linux_triage` (run Week 18 bash `ir.sh` via SSH), `windows_triage` (run Week 18 PowerShell via JEA/WinRM).

### Midday (Learn/Labs, ~3h)
- Workers pick up triage jobs, execute over secure channels, push **manifests** + **hashes** back, and store object paths (MinIO).
- Add **role separation**: responders vs analysts; RBAC enforced via scopes/roles.

### Afternoon (Drill/Test, ~3h)
- Run an end‑to‑end triage on a lab host; confirm artifacts show up in UI with hashes and download links (lab only).
- Add **queue health**/latency panels in `dfir-queue.json`.

### Acceptance criteria
- Console usable; a triage job completes; artifacts listed with hashes; queue metrics visible.

---

# Day 6 — **Online Deploy (Single‑Node) & Hardening**

### Morning (Build, ~4h)
- Deploy **compose** stack on a **private VM** (not the honeypot VM). Terminate TLS at **nginx** gateway; expose **/grafana** and **/api** to you only (VPN/IP allow‑list).
- Enable **HSTS**, **CSP**, `SameSite` cookies; set **rate limits** on `/api` and alert webhooks. Ensure **secrets** pulled from provider (Week 15).

### Midday (Learn/Labs, ~3h)
- Confirm **egress rules**: only required SaaS/updates. Block metadata endpoints; require **IMDSv2** (if cloud).
- Backups: DB dumps + dashboards/configs; practice **restore** on a second VM.

### Afternoon (Drill/Test, ~3h)
- Pen‑test the console/API in Burp (Week 13/14): CSRF, CORS, authZ, SSRF. Fix findings.
- Load test alerts/ingest to planned volumes; size retention and label cardinality in Loki.

### Acceptance criteria
- Stack live and reachable (restricted); backups verified; basic security tests pass; Loki stable under planned load.

---

# Day 7 — **Release Pack v1.9.0 (Capstone I)**

### Morning (Build, ~4h)
- Package **docs**, **compose**, **API**, **UI**, **dashboards**, **detections**, and **workers** with sample data. Add a one‑command **demo loader** to replay attacks (from logs).
- Include **redacted screenshots** and **walkthrough** for evaluators/interviewers.

### Midday (Learn/Labs, ~3h)
- Write `report-week19.md`: executive summary, architecture, data flow, detections, cases, DFIR integration, and security hardening.
- Open issues for Week 20 extensions: long‑term store, OSQuery fleet, automated enrichment, case timelines.

### Afternoon (Drill/Test, ~3h)
- Fresh install test on a clean cloud VM with a domain and TLS cert (lab CA ok); verify minimal secrets needed and default deny.
- Tag **v1.9.0-mini-xdr**; checksums for dashboard JSON and configs.

### Acceptance criteria
- Release reproducible; demo data loads; public honeynet continues feeding; documents are recruiter‑friendly.


---

## How this week advances your cybersecurity path
- **Engineering**: You can design and operate a **cohesive security platform** end‑to‑end.
- **Blue Team**: From raw signals to **actionable cases**, with triage workflows and evidence handling.
- **Purple Team**: You can safely attract traffic, test detections, and iterate quickly without endangering others.


---

## References / Study Hubs
- Grafana Loki/LogQL, Promtail/Grafana Agent — pipelines & alerting
- SigmaHQ rulesets and backends mapping
- Cowrie / OpenCanary honeypots — configuration & safety notes
- OpenTelemetry logs/metrics basics; Postgres RLS; OAuth2/OIDC PKCE patterns (Week 14)

## Rubric (Week 19)
- **Honeypot**: public, isolated, egress‑deny; logs shipping; dashboard live (Day 1).
- **Schema**: ECS‑lite mapping implemented; enrichment added; low‑cardinality labels.
- **Detections**: 5 core rules + correlations active; alerts open cases idempotently.
- **Backend**: OIDC, RLS, problem+json, presigned artifact handling; OTel logs.
- **DFIR**: remote triage jobs functional; artifacts hashed and attached; queue metrics visible.
- **Deploy**: online (restricted) stack with TLS, backups, and basic pen‑tests; v1.9.0 release pack complete.

