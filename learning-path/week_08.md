# Week 08 — **Backend Resilience & Hardening**: Rate Limiting • Idempotency • Concurrency Controls • Reliability Patterns (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Turn your API into a **production‑credible** service: advanced rate limiting (per‑user/IP/tenant), **idempotency keys** with dedupe stores, safe concurrency (optimistic locking, row/advisory locks, SERIALIZABLE), job queues, retries with jitter, circuit breakers, graceful shutdown, and **observability SLOs** (p95 latency, 5xx rate, saturation). Map to **OWASP A05 Misconfiguration**, **A09 Logging/Monitoring**, **API4 Unrestricted Resource Consumption**, **API6 Business Flow**.

---

## Outcomes
- Implement layered **rate limiting** (global, per‑IP, per‑user/tenant) with **token‑bucket** semantics in Redis.
- Add **idempotency keys** to all mutating routes with a **dedupe table** in Postgres (unique constraints) + TTL cleanup.
- Handle concurrency safely using **optimistic locking** (version column + ETag), **SELECT … FOR UPDATE SKIP LOCKED**, and **SERIALIZABLE** transactions for money‑like flows.
- Introduce a job queue (e.g., **BullMQ**) for slow work; use **outbox pattern** to persist events before enqueue.
- Resilience patterns: **retry with jitter**, **circuit breaker**, **bulkheads**, **graceful shutdown** with in‑flight drain.
- Observability: **OpenTelemetry** traces, **pino** structured logs with correlation IDs, dashboards & SLO alerts.
- Ship `week08-backend-resilience` with tests, k6 load scripts, dashboards, and a mini‑report.

## Repository layout (this week)

```
/week08-backend-resilience
  ├─ app/
  │  ├─ src/
  │  │  ├─ server.ts|js
  │  │  ├─ middleware/
  │  │  │  ├─ rateLimiter.ts
  │  │  │  ├─ idempotency.ts
  │  │  │  └─ errors.ts
  │  │  ├─ lib/
  │  │  │  ├─ db.ts
  │  │  │  ├─ locks.ts
  │  │  │  ├─ retry.ts
  │  │  │  └─ breaker.ts
  │  │  ├─ jobs/
  │  │  │  ├─ queue.ts
  │  │  │  └─ workers/
  │  │  ├─ routes/
  │  │  └─ telemetry/
  │  ├─ test/
  │  │  ├─ e2e/
  │  │  ├─ race/
  │  │  └─ load/
  │  ├─ openapi.yaml
  │  └─ package.json
  ├─ db/
  │  ├─ schema.sql
  │  ├─ idempotency.sql
  │  └─ outbox.sql
  ├─ k6/
  │  ├─ bursts.js
  │  └─ races.js
  ├─ dashboards/
  │  └─ backend-panels.json
  ├─ docs/
  │  ├─ patterns.md
  │  ├─ slo.md
  │  └─ report-week08.md
  └─ README.md
```

---

# Day 1 — **Layered Rate Limiting (Token Bucket) with Redis**

### Morning (Build, ~4h)
- Add **global** and **per‑identity** limiters (IP and user/tenant). Consider separate buckets per route group (read vs write).
- Use Redis Lua script or `rate-limiter-flexible` to implement atomic token consumption with TTLs.
- Expose headers: `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`. Return **429** with problem+json.

```ts
// app/src/middleware/rateLimiter.ts (sketch)
import { RateLimiterRedis } from 'rate-limiter-flexible';
import Redis from 'ioredis';
const redis = new Redis(process.env.REDIS_URL);

const burst = new RateLimiterRedis({ storeClient: redis, points: 60, duration: 60 });
const userLimiter = new RateLimiterRedis({ storeClient: redis, points: 120, duration: 60, keyPrefix: 'user' });

export async function rateLimit(req, res, next){
  try {
    const ip = req.ip;
    const userKey = req.user?.id || `anon:${ip}`;
    await burst.consume(ip);
    await userLimiter.consume(userKey);
    res.setHeader('RateLimit-Limit', '120'); // example
    return next();
  } catch (e) {
    return res.status(429).json({ type: 'about:blank', title: 'Too Many Requests', detail: 'Rate limit exceeded' });
  }
}
```
### Midday (Learn/Labs, ~3h)
- Study **token bucket vs leaky bucket**; choose windows (burst vs sustained).
- Plan different limits for **admin** vs **user** vs **anonymous**; consider **cost‑based** limiting (weight per route).

### Afternoon (Drill/Test, ~3h)
- Write e2e tests to simulate bursts and sustained traffic; assert 429 timing and headers.
- Add a **dashboard** panel tracking 429s per route and per user/tenant.

### Evening (Document/Share, ~2h)
- Document limits and rationales; note abuse vectors (distributed clients) and mitigations (IP + user + CAPTCHA for auth flows).
- Commit k6 `bursts.js` to reproduce rate‑limit behavior.

### Acceptance criteria
- Per‑IP and per‑user rate limits enforced with helpful headers.
- 429s visible in dashboards; tests cover burst vs steady traffic.

---

# Day 2 — **Idempotency Keys & Dedupe Store**

### Morning (Build, ~4h)
- Require `Idempotency-Key` for **all mutating** routes; persist a record keyed by `(tenant_id, user_id, route, idempotency_key)` with a **unique constraint**.
- On first request: run handler inside a transaction, store **response hash & status**; on replay: short‑circuit and return same response.

```sql
-- db/idempotency.sql
CREATE TABLE app.idempotency (
  tenant_id uuid NOT NULL,
  user_id   uuid NOT NULL,
  route     text NOT NULL,
  key       text NOT NULL,
  response_status int NOT NULL,
  response_body   bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id, route, key)
);
```
```ts
// app/src/middleware/idempotency.ts (sketch)
export async function requireIdempotency(req,res,next){
  if (['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    if (!req.header('Idempotency-Key')) return res.status(400).json({ error: 'Idempotency-Key required' });
  }
  next();
}
```
### Midday (Learn/Labs, ~3h)
- Decide **TTL** (e.g., 24–72h) and storage size; add cleanup job.
- Consider **hash‑only** storage (avoid PII); store minimal response metadata for replay.

### Afternoon (Drill/Test, ~3h)
- Tests: resend the same request concurrently (race); ensure only one commit happens; the other calls return the cached result.
- Fuzz key collisions across tenants/users; verify uniqueness scope works.

### Evening (Document/Share, ~2h)
- Explain how idempotency prevents **double charge/orders** under retries/replays.
- Add diagrams for first‑time vs replay flow.

### Acceptance criteria
- Idempotency enforced on all mutating routes; replays return cached response.
- Unique constraint at DB proves correct dedupe behavior in races.

---

# Day 3 — **Safe Concurrency: Optimistic & Pessimistic**

### Morning (Build, ~4h)
- Add **version column** (`int` or `timestamptz`) to mutable records; enforce **If-Match ETag** on updates (optimistic locking).
- Implement **pessimistic** patterns: `SELECT … FOR UPDATE SKIP LOCKED` for worker queues and **advisory locks** for cross‑row resources.

```sql
-- optimistic
ALTER TABLE app.items ADD COLUMN version int NOT NULL DEFAULT 1;
-- on update: WHERE id=$1 AND version=$2; then SET version = version+1
```
```ts
// app/src/lib/locks.ts (advisory lock helpers)
export async function withAdvisoryLock(client, key, fn){
  await client.query('SELECT pg_advisory_lock($1)', [key]);
  try { return await fn(); } finally { await client.query('SELECT pg_advisory_unlock($1)', [key]); }
}
```
### Midday (Learn/Labs, ~3h)
- Read about **transaction isolation**; when to use **SERIALIZABLE** and how to handle serialization failures with retry/jitter.
- Design **bulkhead** boundaries: separate pools for read vs write; cap queue concurrency.

### Afternoon (Drill/Test, ~3h)
- Create **race tests** that perform concurrent updates with stale ETags → expect **409 Conflict**.
- Implement a worker pulling jobs with `FOR UPDATE SKIP LOCKED`; verify throughput under k6 load.

### Evening (Document/Share, ~2h)
- Explain tradeoffs of optimistic vs pessimistic; show failure modes and logs.
- Add metrics: lock wait time, 409 count, serialization retry count.

### Acceptance criteria
- Optimistic locking enforced via ETag; 409s returned on stale writes.
- Worker pattern avoids double work using `SKIP LOCKED`; tested under load.

---

# Day 4 — **Job Queue + Outbox Pattern**

### Morning (Build, ~4h)
- Add **BullMQ** (Redis) for background jobs; create `email:send` and `order:process` workers.
- Implement **Outbox** table: write domain events inside the same DB transaction as state changes; a relay publishes to the queue.

```sql
-- db/outbox.sql
CREATE TABLE app.outbox (
  id bigserial PRIMARY KEY,
  tenant_id uuid NOT NULL,
  type text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz
);
```
```ts
// app/src/jobs/queue.ts (sketch)
import { Queue } from 'bullmq';
export const orderQ = new Queue('order', { connection: { url: process.env.REDIS_URL }});
```
### Midday (Learn/Labs, ~3h)
- Understand **at‑least‑once** delivery; design **idempotent** workers using keys from payload.
- Plan dead‑letter queues and alerting on retries exhausted.

### Afternoon (Drill/Test, ~3h)
- Write tests: create order → outbox row exists → relay enqueues → worker processes exactly once (idempotent).
- Kill worker mid‑job; ensure retry works; verify no duplicate side‑effects.

### Evening (Document/Share, ~2h)
- Add runbook: how to drain queues on deploy; how to replay outbox safely.
- Dashboards: queue depth, processing latency, retry counts.

### Acceptance criteria
- Outbox persisted with main transaction; workers idempotent; retries visible.
- Queue depth & retries on dashboards; drain procedure documented.

---

# Day 5 — **Retries, Circuit Breakers, Graceful Shutdown**

### Morning (Build, ~4h)
- Implement **exponential backoff with jitter** for outbound calls (payment/email).
- Add **circuit breaker** (e.g., `opossum`) around unstable dependencies; expose breaker state metrics.

```ts
// app/src/lib/retry.ts
export async function retry(fn, {retries=3, base=100}={}){
  let attempt=0; let last;
  while(attempt<=retries){
    try { return await fn(); } catch(e){ last=e; const jitter = Math.random()*base; await new Promise(r=>setTimeout(r, (2**attempt)*base + jitter)); attempt++; }
  }
  throw last;
}
```
```ts
// app/src/lib/breaker.ts
import CircuitBreaker from 'opossum';
export function wrapBreaker(fn){
  return new CircuitBreaker(fn, { timeout: 3000, errorThresholdPercentage: 50, resetTimeout: 10000 });
}
```
### Midday (Learn/Labs, ~3h)
- Plan **graceful shutdown**: SIGTERM handler stops new traffic, drains in‑flight requests & jobs, closes DB/Redis.
- Decide **timeouts** (server, upstream) and **limits** (max headers/body).

### Afternoon (Drill/Test, ~3h)
- Chaos drill: force downstream failure; observe breaker open; verify fallback responses and logs.
- Send SIGTERM during load; ensure no requests are lost (in‑flight completion).

### Evening (Document/Share, ~2h)
- Add **operational checklists**: deployment, rollback, incident response for dependency outages.
- Update dashboards: breaker state, retry counts, error budget burn.

### Acceptance criteria
- Breaker opens on sustained failures and recovers; retries use jitter; graceful shutdown completes in‑flight.
- Dashboards expose breaker state and retry/error budget burn.

---

# Day 6 — **Observability, SLOs & Abuse Signals**

### Morning (Build, ~4h)
- Integrate **OpenTelemetry** (HTTP server/client) and **pino** logs with correlation IDs; export traces to Jaeger/Tempo.
- Define **SLOs**: p95 latency by route, 5xx rate < 1%, 429 rate acceptable range, queue latency < 5s.

### Midday (Learn/Labs, ~3h)
- Create dashboards: p50/p95/p99, error ratios by class (4xx vs 5xx), saturation (CPU/mem), queue depth, lock wait time, 409s.
- Configure alerts: burn rate for error budget (e.g., 2% over 1h), abnormal spikes in 403/429 (abuse).

### Afternoon (Drill/Test, ~3h)
- Run **k6** `bursts.js` and `races.js`; capture traces & panels; verify alerts trigger in test mode.
- Ensure log fields include tenant/user IDs (pseudonyms) + correlation IDs (no PII).

### Evening (Document/Share, ~2h)
- Write `docs/slo.md`: targets, measurement, alert policy, and playbooks.
- Attach screenshots of dashboards; export JSON to `/dashboards`.

### Acceptance criteria
- SLOs defined and dashboards/alerts implemented; k6 runs create expected signals.
- Logs/traces structured with correlation IDs and no sensitive data.

---

# Day 7 — **Mini‑Project & Release: Backend Resilience Pack**

### Morning (Build, ~4h)
- Polish: README with architecture diagrams for rate limiting, idempotency, concurrency, and outbox/queue.
- Add `Makefile` targets to run k6 tests and export reports; ensure deterministic seeds where relevant.

### Midday (Learn/Labs, ~3h)
- Do a clean bring‑up; re‑run e2e, race, and load tests; capture timings & pass/fail table.
- Check CI integrates lint/tests and uploads k6/coverage artifacts.

### Afternoon (Drill/Test, ~3h)
- Generate **release artifacts**: dashboard JSON, k6 results, traces screenshots, config samples.
- Tag **v0.8.0** and publish GitHub Release.

### Evening (Document/Share, ~2h)
- Write `report-week08.md` mapping controls to OWASP/API items and to service SLOs.
- Open issues for Week 9 (Burp mastery) and Week 10 (Nmap/NSE) integrations.

### Acceptance criteria
- Release contains code, tests, dashboards, reports; CI green.
- Resilience features demonstrably reduce errors under bursts and races.


---

## How this week advances your cybersecurity path
- **API Security**: You enforce **API4** with layered limits and idempotency; abuse is visible and controlled.
- **Platform/SRE**: You can run safe deploys, handle outages, and keep SLAs with SLO‑driven ops.
- **DFIR/Blue**: Rich telemetry (traces/logs) tightens incident timelines; 429/403/409 patterns surface abuse.


---

## References / Study Hubs
- [OpenTelemetry](https://opentelemetry.io/)
- [pino logger](https://github.com/pinojs/pino)
- [rate-limiter-flexible](https://github.com/animir/node-rate-limiter-flexible)
- [BullMQ](https://docs.bullmq.io/)
- [PostgreSQL: Concurrency Control](https://www.postgresql.org/docs/current/mvcc.html) & [Advisory Locks](https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS)
- [HTTP Conditional Requests (ETag/If-Match)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match)
- [Opossum (circuit breaker)](https://github.com/nodeshift/opossum)
- [k6](https://k6.io/)

## Similar GitHub repos / inspiration
- [segmentio/evergreen-idempotency](https://github.com/segmentio) (concepts)
- [temporalio/samples-typescript](https://github.com/temporalio/samples-typescript) (workflow idempotency ideas)
- [staylorx/bullmq-examples](https://github.com/staylorx/bullmq-examples)
- [open-telemetry/opentelemetry-js](https://github.com/open-telemetry/opentelemetry-js)

## Rubric (Week 8)
- **Limits**: layered rate limiting live; headers present; 429 tests + dashboards.
- **Idempotency**: key required on mutating; dedupe table; replay behavior proven; TTL cleanup.
- **Concurrency**: optimistic (ETag/409) and pessimistic (`SKIP LOCKED`/advisory) patterns tested.
- **Resilience**: retry with jitter; circuit breaker; graceful shutdown verified under load.
- **Observability**: p95/5xx/429/queue dashboards; SLOs + alerts; v0.8.0 release with artifacts.

