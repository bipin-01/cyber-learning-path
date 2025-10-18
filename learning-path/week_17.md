# Week 17 — **Backend Mastery II**: Secure File Handling • Queues • Webhooks • SSRF/RCE Hardening (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Ship a production‑credible **intake + processing pipeline** that is safe by default. You’ll master **secure uploads & extraction**, **AV/media sanitization**, **object storage with presigned URLs**, **idempotent queues & workers**, **webhook verification & replay defense**, and **SSRF/RCE hardening** at code, network, and OS/container layers. Mapped to **OWASP A01/A02/A03/A05/A08/A09** and **OWASP API1/API2/API4/API8**.

> **Safety:** All offensive tests run only in your lab stack. No execution of untrusted binaries. Resource‑cap and isolate all converters (ImageMagick, ffmpeg, unrar) if used.

---

## Outcomes
- Design an **upload → scan → sanitize → store → notify** pipeline using presigned URLs and background workers.
- Implement **strict validation** (size/MIME/sniffed type) and **safe extraction** (no Zip‑Slip, no symlinks) with quarantine & AV scans.
- Run image/PDF **sanitization** in a sandboxed container or seccomp/AppArmor profile with CPU/RAM/time limits.
- Build an **idempotent queue** (SQS/Rabbit/Redis Streams model) with dedup keys, DLQ, and poison‑message handling.
- Verify **webhooks** (HMAC signatures + timestamp + replay cache), **rate‑limit & backoff**, and only 2xx on success.
- Eliminate **SSRF/RCE** foot‑guns: egress allow‑list, DNS rebinding/IPv6/URL parsing pitfalls, template/command injection blocks.
- Publish `week17-backend-secure-pipeline` with services, configs, tests, dashboards, and a field report.

## Repository layout (this week)

```
/week17-backend-secure-pipeline
  ├─ services/
  │  ├─ api/                        # FastAPI/Express upload API (issues presigned URLs; registers jobs)
  │  │  ├─ src/
  │  │  │  ├─ main.(py|ts)
  │  │  │  ├─ storage.py|ts         # presigned url helpers
  │  │  │  ├─ validators.(py|ts)    # size/MIME/sniff/sniff+magic
  │  │  │  └─ webhook.(py|ts)       # HMAC verifier + replay cache
  │  │  └─ tests/
  │  ├─ worker/                     # background: download → AV → sanitize → store
  │  │  ├─ src/worker.(py|ts)
  │  │  └─ sandbox/                 # docker profile, rlimits, seccomp/apparmor notes
  │  ├─ safe-fetch/                 # SSRF‑safe outbound fetch microservice (allowlist, DNS pinning)
  │  │  └─ src/index.(py|ts)
  │  └─ queue/                      # adapter: SQS/Rabbit/Redis Streams
  │     └─ src/queue.(py|ts)
  ├─ compose/
  │  ├─ docker-compose.yml          # object storage (MinIO), ClamAV, Redis/Rabbit, API, worker
  │  ├─ minio.env
  │  └─ grafana-loki/               # log pipeline reuse from Week 12
  ├─ configs/
  │  ├─ content-policy.yml          # size/extension/MIME allowlist; per‑tenant overrides
  │  ├─ webhook-providers.yml       # secrets + signature schemes
  │  └─ egress-allowlist.yml        # SSRF: allowed hosts/schemes/ports
  ├─ scripts/
  │  ├─ zap_zip_slip_samples.sh     # generate traversal test zips
  │  └─ load_webhooks.js            # replay & backoff simulator
  ├─ dashboards/
  │  ├─ intake-overview.json
  │  └─ webhook-ops.json
  ├─ docs/
  │  ├─ pipeline.md
  │  ├─ uploads.md
  │  ├─ queues.md
  │  ├─ webhooks.md
  │  ├─ ssrf_rce_hardening.md
  │  └─ report-week17.md
  └─ README.md
```

---

# Day 1 — **Architecture & Presigned Uploads**

### Morning (Build, ~4h)
- Stand up **object storage** (MinIO via compose) and the **API** service. Implement an `POST /uploads` that authenticates the user (Week 14 OIDC), validates **intended** content type & size, and returns a **presigned PUT URL** to object storage.
- Design an **intake record** (DB): `file_id, owner, content_intent, size_max, mime_expected, status, dedup_key, created_at`. Mark `status='pending'`.
- Emit an **idempotency key** and client‑side checksum (SHA‑256) for integrity verification later.

```python
# services/api/src/storage.py (FastAPI example using boto3 to MinIO/S3)
import hashlib, time, uuid, boto3
def issue_presigned(owner_id, intent, size_max, mime_expected):
    file_id = str(uuid.uuid4())
    key = f"intake/{owner_id}/{file_id}"
    s3 = boto3.client("s3", endpoint_url="http://minio:9000", aws_access_key_id="minio", aws_secret_access_key="minio123")
    url = s3.generate_presigned_url("put_object", Params={"Bucket":"uploads","Key":key,"ContentType":mime_expected}, ExpiresIn=900)
    return {"file_id": file_id, "key": key, "put_url": url, "expires": int(time.time())+900}
```
### Midday (Learn/Labs, ~3h)
- Explain **why presigned**: API never streams attacker‑controlled bytes; storage enforces size; later the worker pulls from storage (not from user).
- Plan **naming & tenancy**: per‑tenant prefixes and lifecycle rules; **no public buckets**.

### Afternoon (Drill/Test, ~3h)
- Upload from client to MinIO using the presigned URL; then call `POST /uploads/{file_id}/complete` to enqueue processing.
- Record **hash** (client‑provided) and size in DB for later comparison.

### Evening (Document/Share, ~2h)
- Write `docs/pipeline.md` with the sequence diagram; add schema migration for `uploads` table; capture a happy‑path run.

### Acceptance criteria
- Presigned URL flow works; DB record created; completion enqueues a job; no direct upload through API server.

---

# Day 2 — **Validation, AV Scan, and Safe Extraction**

### Morning (Build, ~4h)
- Implement **server‑side validation**: verify stored object’s **size <= size_max**, **Content‑Type** matches **sniffed magic** (libmagic), **extension whitelist** by intent.
- Integrate **ClamAV** container for a simple `INSTREAM` scan. Quarantine on hit; tag DB status + reason; never attempt execution.

```python
# services/worker/src/worker.py (scan step sketch)
from magic import from_file
def validate_and_scan(obj_path, expect_mime, size_max):
    assert os.path.getsize(obj_path) <= size_max, "size_exceeded"
    actual = from_file(obj_path, mime=True)
    if actual != expect_mime: raise ValueError(f"mime_mismatch:{actual}")
    # ClamAV scan (clamd)
    import clamd; cd = clamd.ClamdNetworkSocket('clamav', 3310)
    result = cd.scan(obj_path); 
    if result and list(result.values())[0][0] != 'OK': raise ValueError('av_detected')
```
### Midday (Learn/Labs, ~3h)
- **Zip‑Slip** & **Tar traversal**: normalize paths, reject any member escaping the intended directory; block symlinks/hardlinks; cap member count and total uncompressed size (zip bomb defense).
- Decide **sanitize vs reject** per content type (e.g., re‑encode images → JPEG/PNG; strip metadata with exiftool/pyexiv2).

### Afternoon (Drill/Test, ~3h)
- Build test archives with traversal and huge compression ratios; confirm rejection with clear error codes.
- Log structured reasons to Loki (Week 12) and create a panel of **rejected-by‑reason**.

### Evening (Document/Share, ~2h)
- Write `uploads.md` covering validations, quarantine policy, and test recipes; store sample rejected artifacts (metadata only).

### Acceptance criteria
- Validation + AV integrated; traversal/zip‑bomb tests fail safely; structured rejection reasons visible in dashboards.

---

# Day 3 — **Sandbox Converters & Resource Limits**

### Morning (Build, ~4h)
- Run converters (ImageMagick/ffmpeg/gs) **in a sidecar container** with restricted user, **read‑only FS**, **no network**, **CPU & memory limits**, and **timeout**.
- Prefer safe libraries (e.g., **Sharp** for images). If you must shell out, pass **fixed arg lists** and explicit paths; avoid string interpolation.

```bash
# docker run example (sketch)
docker run --rm --network=none --cpus=0.5 --memory=256m -v /sandbox/in:/in:ro -v /sandbox/out:/out:rw imagetools:stable   convert /in/input.png -strip -resize 1600x1600\> /out/safe.jpg
```
### Midday (Learn/Labs, ~3h)
- **RCE mitigations**: no `eval`, template auto‑escape on, treat filenames as data (not code); for Python, **subprocess** with `list[str]` and `check=True`; for Node, **child_process.execFile** with **args array** only.
- **Time/space bombs**: set OS `ulimit`, container memory/CPU/timeouts; kill on limit breach; mark job as `failed_sandboxed`.

### Afternoon (Drill/Test, ~3h)
- Feed crafted PDFs/images that previously crashed converters; confirm timeouts and graceful failure.
- Verify **no network egress** from converter container.

### Evening (Document/Share, ~2h)
- Add `sandbox/README` with seccomp/AppArmor notes and example profiles; record before/after stability metrics.

### Acceptance criteria
- Converters run sandboxed with resource caps; malicious samples fail safely; no network access observed.

---

# Day 4 — **Idempotent Queues, DLQ, and Practical Exactly‑Once**

### Morning (Build, ~4h)
- Implement a **queue adapter** (SQS/Rabbit/Redis Streams). For SQS: use **FIFO + content‑based dedup** or explicit `MessageDeduplicationId`. Maintain your own **idempotency table** keyed by `(job_type, dedup_key)` with status/result hash.
- Design **DLQ**: after N attempts or fatal error class, route to **dead‑letter** with reason and context.

```python
# services/queue/src/queue.py (sketch)
def enqueue_upload(file_id, dedup_key):
    client.send_message(QueueUrl=Q, MessageBody=json.dumps({"file_id":file_id}), MessageGroupId="uploads", MessageDeduplicationId=dedup_key)
```
### Midday (Learn/Labs, ~3h)
- **Exactly‑once** is a myth across distributed systems—achieve **at‑least‑once + idempotency**. Persist **job steps** with checkpoints; make storage writes **upsert** on `file_id`.
- Detect **poison messages**: same error N times → DLQ; create a **replay tool** gated by admin auth.

### Afternoon (Drill/Test, ~3h)
- Simulate duplicates/out‑of‑order delivery; confirm idempotency table prevents reprocessing.
- Create Grafana panels: in‑flight jobs, retries, DLQ by reason.

### Evening (Document/Share, ~2h)
- Write `queues.md` with flowcharts and failure modes; add runbooks for DLQ triage.

### Acceptance criteria
- Queue adapter with dedup works; replays safe; DLQ populated only for true poisons; dashboards show health.

---

# Day 5 — **Webhooks: Signatures, Replay Defense & Backoff**

### Morning (Build, ~4h)
- Create `/webhooks/{provider}` endpoint. Implement **HMAC** verification with provider secret, **timestamp tolerance** (e.g., ±5 min), and **replay cache** (store event IDs for 24h).
- Respond **quickly** (ack) and push work to the queue; implement **retry‑after/backoff** on failures.

```ts
// services/api/src/webhook.ts (Express)
import crypto from 'crypto';
function verify(sigHeader: string, raw: string, secret: string, toleranceSec=300){
  const [tsPart, macPart] = sigHeader.split(',');
  const ts = parseInt(tsPart.replace('ts=',''),10);
  if (Math.abs(Date.now()/1000 - ts) > toleranceSec) throw new Error('stale');
  const expected = crypto.createHmac('sha256', secret).update(`${ts}.${raw}`).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(macPart.replace('sig=','')))) throw new Error('bad_sig');
}
```
### Midday (Learn/Labs, ~3h)
- Normalize **payload** exactly as provider signs it (raw body). Enforce **Content‑Type** and **IP allow‑list** where appropriate.
- Add **idempotency** by event ID; store minimal payload + signature fields for audit; redact PII before logs.

### Afternoon (Drill/Test, ~3h)
- Build a **simulator** to send signed/unsigned/stale/replayed webhooks; verify responses and retries.
- Add Grafana panels: delivery success %, median latency, retries, top failure reasons.

### Evening (Document/Share, ~2h)
- Write `webhooks.md` (verification matrix per provider, e.g., Stripe/GitHub‑style), and add alerting: **failure‑rate spike** and **replay storm**.

### Acceptance criteria
- Signatures verified; replays blocked; metrics & alerts configured; simulator proves correctness.

---

# Day 6 — **SSRF/RCE Hardening (Code • Network • OS/Containers)**

### Morning (Build, ~4h)
- Move all outbound HTTP calls to **safe‑fetch** microservice. Enforce **allow‑list** (host:port/scheme), **blocklink‑local** (127.0.0.0/8, 10.0.0.0/8, 169.254.169.254, ::1, fe80::/10), and **DNS pinning** (resolve → connect to that IP; re‑resolve periodically).
- Sanitize URLs: **no `file://`, `gopher://`, `ftp://`**; strip credentials; cap redirects; block **IPv6 literals** unless allowlisted.

```python
# services/safe-fetch/src/index.py (sketch with allow-list + local net block)
from urllib.parse import urlparse
import ipaddress, socket, requests
ALLOW = {"https://api.example.test:443", "https://geo.test:443"}
def is_private(ip):
    ipn = ipaddress.ip_address(ip)
    return ipn.is_private or ipn.is_loopback or ipn.is_link_local or ipn.is_multicast or ipn.is_reserved
def safe_get(url):
    u = urlparse(url); assert u.scheme in ("https","http"); assert u.username is None
    dest = f"{u.scheme}://{u.hostname}:{u.port or (443 if u.scheme=='https' else 80)}"
    if dest not in ALLOW: raise ValueError("dest_not_allowed")
    ip = socket.getaddrinfo(u.hostname, u.port or 443)[0][4][0]
    if is_private(ip): raise ValueError("private_net_blocked")
    return requests.get(url, timeout=5, allow_redirects=False)
```
### Midday (Learn/Labs, ~3h)
- At **network** layer: egress firewall on containers (only to MinIO, SQS, AV, safe‑fetch). Block metadata services (e.g., 169.254.169.254) and require IMDSv2 in cloud labs.
- At **OS/containers**: drop `CAP_*`, run as non‑root, read‑only FS, seccomp/AppArmor; log denied syscalls for tuning.

### Afternoon (Drill/Test, ~3h)
- Run SSRF test cases (http → localhost, file://, DNS rebinding hostnames); confirm **blocked** with explicit error reasons.
- Probe template injection (SSTI) with harmless payloads; ensure auto‑escape and no server‑side template eval on user input.

### Evening (Document/Share, ~2h)
- Write `ssrf_rce_hardening.md` with blocklists/allow‑lists, container profiles, and test matrices.

### Acceptance criteria
- All SSRF vectors blocked; outbound calls only via safe‑fetch; containers least‑privilege and read‑only; explicit documentation of denied cases.

---

# Day 7 — **Mini‑Project & Release: Secure Intake & Webhook Pack**

### Morning (Build, ~4h)
- End‑to‑end demo: **upload → scan → sanitize → store → webhook notify** to a sample partner endpoint (lab).
- Collect evidence: logs, dashboards, AV detections, sanitizer outputs, webhook delivery reports.

### Midday (Learn/Labs, ~3h)
- Create `report-week17.md` with risks/controls mapping: file upload, SSRF, RCE, authz boundaries, and ops SLOs (latency, failure budgets).
- Open backlog items for scale: chunked uploads, async multipart, out‑of‑process thumbnails, AV signature updates cadence.

### Afternoon (Drill/Test, ~3h)
- Perform a **fresh install** test from README; ensure secrets/keys via env/Secrets Manager; validate all negative tests.
- Tag **v1.7.0-backend-sec**; include checksums for dashboard JSON and configs.

### Evening (Document/Share, ~2h)
- Cross‑link to prior weeks: Week 12 (Loki alerts), Week 13 (Burp findings feeding into sanitization rules), Week 14 (OIDC), Week 15 (KMS keys & RLS).

### Acceptance criteria
- Release reproducible; upload and webhook flows hardened; SSRF/RCE tests pass; dashboards & alerts show day‑1 value.


---

## How this week advances your cybersecurity path
- **AppSec engineering**: You build pipelines that stay safe under untrusted input at scale.
- **Platform/SRE**: You operate queues, DLQs, sandboxed workers, and alerting with low toil.
- **Red→Blue**: You can reason from Burp findings (uploads/SSRF) to **defensive code & infra** quickly.


---

## References / Study Hubs
- OWASP Cheat Sheets: File Upload Security, Deserialization, Server‑Side Request Forgery Prevention, Logging, Secure Headers
- Stripe/GitHub/Twilio Webhook signature docs (concept patterns, not vendor‑lock)
- ClamAV docs; libmagic/filetype sniffing best practices; MinIO/S3 presigned URL guides
- Container hardening: seccomp/AppArmor basics; Docker `--cap-drop`, `--read-only`
- SQS/Rabbit/Redis Streams idempotency and DLQ patterns

## Rubric (Week 17)
- **Uploads**: presigned URLs; size/MIME/sniff validated; AV + quarantine; safe extraction; sanitizer sandboxed.
- **Queues**: dedup/idempotency implemented; DLQ + replay tooling; health dashboards present.
- **Webhooks**: HMAC + timestamp + replay cache; backoff + success‑only ack; metrics + alerts.
- **SSRF/RCE**: outbound via safe‑fetch allow‑listed; containers least‑privilege; test matrix passes.
- **Release**: v1.7.0‑backend‑sec with docs/configs/tests/dashboards; clean bring‑up verified.

