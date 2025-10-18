# Week 20 — **Capstone Build II**: Long‑Term Store, OSQuery Fleet, Timeline View, TI Enrichment, SLAs & Demo Loader (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Take your mini‑XDR/SIEM from Week 19 to the next level. Add a **long‑term data store** (ClickHouse/OpenSearch), deploy a lab **OSQuery fleet** for host visibility, build a **case timeline** UI with correlated events/artifacts, plug in **Threat Intelligence (TI) enrichment** with safe allow‑listed egress, and formalize **case SLAs** and response automations (lab‑safe). Ship a **demo loader** so reviewers can see the system immediately.

> **OPSEC:** Keep all enrichments behind an **allow‑listed egress** microservice (Week 17 safe‑fetch). Use **synthetic/demo** TI when offline. No destructive SOAR actions on real endpoints—lab only.

---

## Outcomes
- Operate **hot→cold** retention: hot logs in Loki (7–14d) and cold/analytical storage in **ClickHouse** (or OpenSearch) with a daily ETL.
- Deploy **OSQuery** to lab hosts; ship results to the platform; create **scheduled packs** (autoruns, processes, listening ports, unusual binaries).
- Implement **TI enrichment** (GeoIP/ASN already; add risky ASN, simple reputation cache, honey‑token correlation).
- Extend UI with a **case timeline** (alerts, events, artifacts, triage tasks) + search and filters.
- Define **case SLAs** (P1/P2/P3) and **response runbooks**; implement safe **automation hooks** (lab isolation, service stop, disable account).
- Publish `week20-capstone-adv` with long‑term store, OSQuery fleet configs, enrichment service, UI timeline, SLA policies, and demo data loader.

## Repository layout (capstone, part II)

```
/week20-capstone-adv
  ├─ compose/
  │  ├─ docker-compose.yml             # adds clickhouse + vector/fluent-bit + osquery-logforward
  │  ├─ clickhouse/
  │  │  ├─ users.xml
  │  │  ├─ server.xml
  │  │  └─ init.d/01_tables.sql        # DDL for ecs_lite.events
  │  ├─ vector/                         # optional: vector-based ETL from Loki to ClickHouse
  │  │  └─ vector.toml
  │  └─ opensearch/                     # alternative to ClickHouse (optional)
  ├─ osquery/
  │  ├─ fleetd/                         # optional Fleet-like configs (lightweight)
  │  ├─ packs/
  │  │  ├─ baseline.conf
  │  │  ├─ autoruns.conf
  │  │  └─ listening_ports.conf
  │  ├─ enricher/
  │  │  └─ map_osquery_to_ecs.py       # normalize into ecs-lite rows
  │  └─ shipping/
  │     └─ filebeat_promtail.md        # two options to ship to Loki → ETL
  ├─ backend/
  │  ├─ enrichment/
  │  │  ├─ service.(py|ts)             # TI microservice behind safe-fetch
  │  │  └─ cache.sqlite                 # local cache store
  │  ├─ api/
  │  │  ├─ timeline.(py|ts)            # timeline aggregator endpoints
  │  │  └─ sla.(py|ts)                 # SLA policy evaluation
  │  └─ workers/
  │     ├─ etl_loki_clickhouse.py      # scheduled job: export → normalize → insert
  │     └─ response_hooks.(py|ts)      # lab-only actions (isolate VM, stop service)
  ├─ ui/case-console/
  │  ├─ src/components/Timeline.tsx    # visual timeline (events, artifacts, actions)
  │  └─ src/pages/CaseView.tsx
  ├─ dashboards/
  │  ├─ osquery-overview.json
  │  └─ longterm-analytics.json
  ├─ docs/
  │  ├─ longterm_store.md
  │  ├─ osquery_fleet.md
  │  ├─ enrichment.md
  │  ├─ timeline_ui.md
  │  ├─ slas_runbooks.md
  │  └─ report-week20.md
  ├─ scripts/
  │  ├─ demo_loader.py                 # synthetic events + case with artifacts
  │  └─ backfill_clickhouse.py
  └─ README.md
```

---

# Day 1 — **Long‑Term Store (ClickHouse/OpenSearch) Design & DDL**

### Morning (Build, ~4h)
- Choose **ClickHouse** for analytic queries and cost; keep Loki for hot search. Add **ClickHouse** service to compose and expose on an internal network only.
- Create `ecs_lite.events` table and **daily partitions** with indexes on `@timestamp`, `event.category`, `src.ip`, `rule.id`.

```sql
-- compose/clickhouse/init.d/01_tables.sql
CREATE DATABASE IF NOT EXISTS ecs_lite;
CREATE TABLE IF NOT EXISTS ecs_lite.events (
  ts DateTime64(3) CODEC(Delta, ZSTD),
  event_kind LowCardinality(String),
  event_category LowCardinality(String),
  rule_id LowCardinality(String),
  src_ip IPv6,
  dst_ip IPv6,
  http_path String,
  user String,
  sensor LowCardinality(String),
  region LowCardinality(String),
  raw JSON
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (ts, event_category, sensor, src_ip)
SETTINGS index_granularity = 8192;
```
### Midday (Learn/Labs, ~3h)
- Define a **minimal ECS‑lite** mapping to store both honeypot and OSQuery data. Decide what goes in **columns** vs **raw JSON** for flexibility.
- Plan data **retention**: 30–90 days in ClickHouse (lab); delete partitions older than N days.

### Afternoon (Drill/Test, ~3h)
- Smoke‑test ClickHouse with sample inserts; confirm partitioning and basic queries.
- Prepare **materialized views** (optional) for common aggregations (top src_ip per rule/day).

### Acceptance criteria
- ClickHouse running; `ecs_lite.events` created; test query returns rows; retention policy documented.

---

# Day 2 — **ETL: Loki → ClickHouse (Daily Job)**

### Morning (Build, ~4h)
- Implement `etl_loki_clickhouse.py`: query Loki for the last 24h (by label selector), **normalize** to ECS‑lite, and **batch insert** to ClickHouse.
- Add **idempotency**: store a watermark (`last_ingested_ts`) and **dedup** by `(ts, sensor, src_ip, rule_id)`.

```python
# backend/workers/etl_loki_clickhouse.py (sketch)
import os, json, time, datetime as dt
from clickhouse_driver import Client
import requests
def run(since, until):
    q = '{sensor=~".+"} | json'  # example; refine by labels
    resp = requests.get("http://loki:3100/loki/api/v1/query_range", params={"query": q, "start": since, "end": until})
    rows = []
    for stream in resp.json().get("data",{}).get("result",[]):
        for v in stream["values"]:
            ts_ns, line = v
            ev = json.loads(line) if line.strip().startswith("{") else {"raw": line}
            rows.append((int(ts_ns)//1_000_000, ev.get("event","log"), ev.get("category","net"), ev.get("rule_id",""), ev.get("src_ip","::"), ev.get("dst_ip","::"), ev.get("path",""), ev.get("user",""), ev.get("sensor",""), ev.get("region",""), json.dumps(ev)))
    client = Client("clickhouse")
    client.execute("INSERT INTO ecs_lite.events (ts, event_kind, event_category, rule_id, src_ip, dst_ip, http_path, user, sensor, region, raw) VALUES", rows)
```
### Midday (Learn/Labs, ~3h)
- Schedule ETL as a **cron**/container **timer**; log metrics (rows/sec, lag).
- Create **Grafana panels** that query ClickHouse (via ClickHouse datasource) for **long‑range** trends.

### Afternoon (Drill/Test, ~3h)
- Backfill 7 days of data from Loki to ClickHouse with `scripts/backfill_clickhouse.py`.
- Verify **consistency** (row counts vs Loki estimates) and performance (seconds/minutes).

### Acceptance criteria
- ETL job moves daily data reliably; dedup/idempotency working; long‑range Grafana dashboards online.

---

# Day 3 — **OSQuery Fleet (Lab) & Shipping**

### Morning (Build, ~4h)
- Install **osqueryd** on Linux & Windows lab hosts. Configure **packs** for: processes, autoruns, listening ports, users/groups changes, suspicious binaries in temp dirs.
- Choose a shipping method: (A) write to **filesystem** and ship via Promtail → Loki → ETL; or (B) send directly to ClickHouse via a small forwarder.

```json
// osquery/packs/baseline.conf (snippet)
{
  "schedule": {
    "processes": { "query": "SELECT pid,name,path,cmdline,user FROM processes;", "interval": 300 },
    "listening": { "query": "SELECT pid,port,family,protocol FROM listening_ports;", "interval": 300 },
    "users": { "query": "SELECT * FROM users;", "interval": 1800 }
  }
}
```
### Midday (Learn/Labs, ~3h)
- Normalize OSQuery **result logs** with `osquery/enricher/map_osquery_to_ecs.py`. Map table outputs to `event.category=host|process|network`.
- Add **host labels** (role, environment) and confirm low label cardinality.

### Afternoon (Drill/Test, ~3h)
- Ship OSQuery logs; confirm appearance in Loki and/or ClickHouse.
- Build **osquery-overview** Grafana dashboard: top processes, new autoruns, new listening ports, users added.

### Acceptance criteria
- OSQuery running on ≥2 lab hosts; logs normalized and visible; dashboard panels populated.

---

# Day 4 — **Threat Intel (TI) Enrichment & Correlation**

### Morning (Build, ~4h)
- Implement an **enrichment service** behind **safe‑fetch** (Week 17): takes IP/JA3/URL → returns cached reputation (benign/suspicious), ASN risk score, and first‑seen time.
- Populate **local cache** from synthetic/demo feeds; support **TTL** and **manual seed** for offline mode.

```python
# backend/enrichment/service.py (sketch)
from datetime import datetime, timedelta
CACHE = {}  # { indicator: { verdict, asn_risk, first_seen, ttl } }
def lookup_ip(ip):
    e = CACHE.get(ip)
    if e and e['ttl'] > datetime.utcnow(): return e
    # else: call safe-fetch allowlisted provider OR return default 'unknown'
    return {"verdict":"unknown","asn_risk":0,"first_seen":None}
```
### Midday (Learn/Labs, ~3h)
- Add backend logic to **enrich alerts/cases** on ingestion; store **enrichment snapshots** on each case event.
- Correlate alerts across sources by **indicator** within a sliding window (e.g., same src_ip seen in Cowrie + OSQuery netstat).

### Afternoon (Drill/Test, ~3h)
- Simulate enriched indicators via the **demo loader**; verify case views show verdict/ASN and links to logs.
- Add **first‑seen** / **most‑recent** panels per indicator in long‑term analytics.

### Acceptance criteria
- Enrichment service online; cases receive enrichment; correlations link multi‑sensor activity via indicators.

---

# Day 5 — **Timeline UI & Case SLAs**

### Morning (Build, ~4h)
- Create **/timeline** API that aggregates **alerts, events, artifacts, actions** into ordered items with types and tags (ATT&CK/TI).
- Implement UI **Timeline** component with filters (source, type, indicator, ATT&CK).

```ts
// ui/case-console/src/components/Timeline.tsx (concept)
export type Item = { ts:string; type:'alert'|'event'|'artifact'|'action'; title:string; tags:string[]; link?:string };
// Render items grouped by hour/day with sticky headers; allow quick filters
```
### Midday (Learn/Labs, ~3h)
- Define **SLA policy**: P1 (respond <15m), P2 (<1h), P3 (<4h). Track **time to acknowledge (TTA)** and **time to contain (TTC)**; compute **breach risk**.
- Add backend **SLA evaluation** and UI badges; create alerts when cases approach breach windows.

### Afternoon (Drill/Test, ~3h)
- Use demo loader to create P1/P2 cases; simulate acknowledgments/actions; verify SLA metrics and warnings.
- Add a **case activity heatmap** and **lead time** panel in Grafana.

### Acceptance criteria
- Timeline UI functional; SLA metrics computed; breach warnings tested with demo data.

---

# Day 6 — **Response Hooks (Lab‑Safe) & Backups**

### Morning (Build, ~4h)
- Implement **lab‑safe** response hooks: isolate VM (detach network), stop a named service, disable test user; require admin scope and **two‑step confirm**.
- Log all actions with **who/when/why** and attach to case timeline with hashes of any changed configs.

### Midday (Learn/Labs, ~3h)
- Create **backups**: Postgres dumps (cases/alerts/artifacts), ClickHouse partition dumps; verify **restore** on a fresh VM.
- Define **retention** and **sanitization** for demo/public artifacts.

### Afternoon (Drill/Test, ~3h)
- Run a mock incident: alert → case → enrichment → triage job → action (stop service) → closure with SLA met.
- Export a **sanitized report** from the case including timeline and artifacts list.

### Acceptance criteria
- Response hooks gated & logged; backups/restores documented and tested; mock incident completed with SLA met.

---

# Day 7 — **Demo Loader & Release v2.0.0**

### Morning (Build, ~4h)
- Write `scripts/demo_loader.py` to generate synthetic alerts/events across 24h (Cowrie brute, canary hit, OSQuery new port), auto‑create a case, and attach faux artifacts.
- Include **screenshots** templates and a **walkthrough** so anyone can review without real traffic.

```python
# scripts/demo_loader.py (sketch)
import requests, time, random, uuid
def post_alert(rule_id, src_ip):
    return requests.post("http://api:4000/alerts", json={"id":str(uuid.uuid4()),"rule_id":rule_id,"src_ip":src_ip,"severity":"high"}).json()
for i in range(50):
    post_alert("cowrie.bruteforce", f"203.0.113.{random.randint(10,200)}")
time.sleep(1)
# create case, attach artifacts, post timeline notes...
```
### Midday (Learn/Labs, ~3h)
- Run demo loader on a clean stack; verify dashboards, timeline, and SLAs all populate; capture demo screenshots.
- Write `report-week20.md` with executive summary and **how to demo** steps.

### Afternoon (Drill/Test, ~3h)
- Finalize **v2.0.0** release notes; ensure one‑command demo script starts everything and loads data.
- Open backlog items: **MISP integration**, **OSQuery live query**, **Jupyter IR notebook export**.

### Acceptance criteria
- v2.0.0 release artifacts complete; demo reproduces reliably; documentation recruiter‑friendly.


---

## How this week advances your cybersecurity path
- **Scale & retention:** You operate hot/cold tiers and can query months of data cost‑effectively.
- **Endpoint depth:** OSQuery gives you process/autoruns/ports/users visibility to complement honeypots and network.
- **Analyst experience:** Timeline + SLAs + enrichment create a credible case workflow you can discuss in interviews.
- **Engineering craft:** ETL, schemas, caching, automation, and safe response hooks demonstrate system thinking.


---

## References / Study Hubs
- ClickHouse schema design for logs; Loki → external store ETL patterns; Grafana + ClickHouse datasource
- OSQuery schema & packs; shipping options; security considerations
- Case management best practices, SLA design, and timeline UIs (general patterns)

## Rubric (Week 20)
- **Long‑term**: ClickHouse/OpenSearch running; ETL with idempotency; long‑range dashboards live.
- **OSQuery**: packs deployed; logs shipped and normalized; dashboard shows host signals.
- **Enrichment**: TI service enriches cases; correlations by indicator work.
- **Timeline & SLAs**: timeline renders; SLA metrics computed; breach alerts tested.
- **Response & Backups**: lab‑safe actions logged; DB/CH backups verified.
- **Release**: v2.0.0 with demo loader and recruiter‑friendly walkthrough.

