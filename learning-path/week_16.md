# Week 16 — **Honeypots + Advanced Security Monitoring** — Capstone Prep (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Design and deploy a **deception layer** that produces high‑signal telemetry without risk to production. Build a **multi‑sensor honeypot stack** (Cowrie SSH/Telnet, Dionaea malware catcher, OpenCanary services, custom honey‑API), integrate with your **Loki/Grafana** pipeline (Week 12), add **Zeek** on a SPAN/mirror for north‑south visibility (Week 11), and ship **dashboards, alerts, and playbooks**. Prepare the architecture and artifacts you’ll expand into your **capstone** (Weeks 19–20).

> **Safety & Ethics:** Run honeypots in an **isolated lab VPC** with strict **egress deny** except for your log shipping. Do not store or execute captured malware. Never impersonate real services in a way that violates policy.

---

## Outcomes
- Stand up a **multi‑sensor honeypot** stack via docker‑compose (Cowrie, Dionaea, OpenCanary, a custom honey‑API).
- Route logs to **Loki** (Promtail/Agent), parse to **JSONL**, and visualize in **Grafana** with attacker behavior panels (brute attempts, commands, binaries, canary hits).
- Enrich events with **GeoIP/ASN/JA3** (local databases) and tag by **tactic** (credential stuffing, scanning, exploit attempt).
- Instrument **canary tokens/decoys** (fake AWS key, honey JWT, honey DB creds, URL beacons) and track use.
- Build **alerts & playbooks** (blocking optional in lab), including correlation with Sysmon/Zeek where relevant.
- Publish `week16-honeypot-capstone-prep` with configs, dashboards, alerts, playbooks, and a redacted field report.

## Repository layout (this week)

```
/week16-honeypot-capstone-prep
  ├─ compose/
  │  ├─ docker-compose.yml         # Cowrie, Dionaea, OpenCanary, Promtail, (optional) Zeek
  │  ├─ promtail-config.yml
  │  └─ networks.md                # isolation notes
  ├─ sensors/
  │  ├─ cowrie/
  │  │  ├─ cowrie.cfg
  │  │  └─ userdb.txt              # fake users/passwords
  │  ├─ dionaea/                   # minimal config
  │  ├─ opencanary/
  │  │  └─ opencanary.conf
  │  └─ honey-api/
  │     ├─ server.py               # Flask/FastAPI, logs all hits, never performs actions
  │     └─ requirements.txt
  ├─ enrichment/
  │  ├─ geoip.mmdb                 # (placeholder) local DB path
  │  ├─ enrich_config.yml          # pipeline mapping → labels
  │  └─ enrich_samples.md
  ├─ dashboards/
  │  ├─ honeypot-overview.json
  │  ├─ cowrie-ssh.json
  │  ├─ dionaea-malware.json
  │  └─ canary-hits.json
  ├─ alerts/
  │  ├─ loki-rules.yaml
  │  └─ grafana-contact-points.json
  ├─ playbooks/
  │  ├─ brute-ssh.md
  │  ├─ canary-credential.md
  │  └─ exploit-attempt.md
  ├─ docs/
  │  ├─ architecture.md
  │  ├─ opsec.md
  │  ├─ dashboards.md
  │  ├─ field-report-template.md
  │  └─ report-week16.md
  └─ README.md
```

---

# Day 1 — **Architecture & Isolation**

### Morning (Build, ~4h)
- Draw the **network plan**: isolated subnet/VPC, SGs/NSGs allow inbound to honeypot ports (22, 23, 80, 445, 1433/3306 optional), **egress deny** except to Loki/updates.
- Create `compose/docker-compose.yml` with **Cowrie**, **Dionaea**, **OpenCanary**, **Promtail**. Ensure each has a dedicated volume for logs; mount Promtail to read them.

```yaml
# compose/docker-compose.yml (sketch)
services:
  cowrie:
    image: cowrie/cowrie
    volumes: [ "../sensors/cowrie:/cowrie" ]
    ports: [ "22:2222", "23:2223" ]   # host 22/23 → container 2222/2223
  dionaea:
    image: dtagdevsec/dionaea
    ports: [ "80:80", "445:445" ]
    volumes: [ "../sensors/dionaea:/var/dionaea" ]
  opencanary:
    image: thinkst/opencanary
    volumes: [ "../sensors/opencanary:/etc/opencanary" ]
    ports: [ "21:21", "8080:8080" ]
  honeyapi:
    build: ../sensors/honey-api
    ports: [ "3001:3001" ]
  promtail:
    image: grafana/promtail:latest
    volumes: [ "../compose/promtail-config.yml:/etc/promtail/config.yml:ro", "../sensors:/logs:ro" ]
    command: -config.file=/etc/promtail/config.yml
networks:
  default:
    name: hpnet
```
### Midday (Learn/Labs, ~3h)
- Write **OPSEC**: banner disclaimers, never execute uploaded binaries, rotate hostnames/IPs sparingly, and no outbound connections from sensors.
- Define **target personas** (brute‑forcers, scanners, opportunistic exploiters) and what telemetry you want from each.

### Afternoon (Drill/Test, ~3h)
- Bring up the stack; validate ports exposed; verify **no egress** by default (deny rules).
- Check Promtail can read and ship a test line to Loki/Grafana (Week 12).

### Evening (Document/Share, ~2h)
- Document the isolation model in `docs/opsec.md` and `compose/networks.md`; capture screenshots of Explore showing first logs.

### Acceptance criteria
- Compose up succeeds; services listening; Loki shows at least one log from each sensor; egress deny verified.

---

# Day 2 — **Cowrie SSH/Telnet: High‑Signal Command Telemetry**

### Morning (Build, ~4h)
- Configure **Cowrie**: set hostname/motd, fake filesystem, command logging, and **userdb** with believable accounts (no real creds).
- Enable **JSON log output** and rotate daily; label streams in Promtail by `sensor=cowrie` and `type=ssh|telnet`.

```ini
# sensors/cowrie/cowrie.cfg (snippets)
[honeypot]
hostname = files01
[output_jsonlog]
logfile = log/cowrie.json
[ssh]
listen_port = 2222
[telnet]
listen_port = 2223
```
### Midday (Learn/Labs, ~3h)
- Create **Grafana panels**: top usernames/passwords, top commands, session duration, interactive vs non‑interactive sessions.
- Define **alert**: sustained brute force (≥100 attempts/5m) or first interactive shell on a sensor.

### Afternoon (Drill/Test, ~3h)
- Simulate activity from Kali (within lab): SSH/Telnet attempts, run a few benign commands to populate data.
- Verify Loki queries for brute thresholds; tune to avoid noise.

### Evening (Document/Share, ~2h)
- Add screenshots to `dashboards/cowrie-ssh.json` and note log fields used (src_ip, username, command).

### Acceptance criteria
- Cowrie logs visible with structured fields; dashboards show top creds/commands; alert triggers on simulated brute force.

---

# Day 3 — **Dionaea & Malware Capture (Metadata‑Only)**

### Morning (Build, ~4h)
- Configure **Dionaea** to emulate SMB/HTTP services and log **download attempts** (URLs, hashes).
- Ensure files are **not executed**; set a job to compute **SHA256** and immediately quarantine or discard files.

### Midday (Learn/Labs, ~3h)
- Create panel: top **malware URLs**, **file types**, **hash families**, and **source IPs/ASNs**; link to external sandboxes only by **hash** (do not upload binaries).
- Add alert: first time‑seen hash family or sudden spike in download attempts.

### Afternoon (Drill/Test, ~3h)
- Simulate HTTP pulls with benign files to exercise the path; verify hashing and quarantine behavior.
- Add Loki parsing for Dionaea’s log format (regex/`| json`).

### Evening (Document/Share, ~2h)
- Document safe handling and retention limits in `docs/opsec.md`; add dashboard JSON to repo.

### Acceptance criteria
- Dionaea logging and hash computation works; dashboards populate; alert fires on synthetic spike.

---

# Day 4 — **OpenCanary + Honey Tokens/Decoys**

### Morning (Build, ~4h)
- Configure **OpenCanary** services (FTP/HTTP/SMB/MSSQL) and point logging to file; set believable banners (version strings) without matching your production.
- Create **canary tokens**: fake AWS key (in a private test repo), **honey JWT** with tell‑tale `iss`, **honey DB creds** that resolve only to the honeypot.

```json
// sensors/opencanary/opencanary.conf (snippet)
{
  "device.node_id": "canary-01",
  "ftp.enabled": true,
  "http.enabled": true,
  "http.port": 8080,
  "http.banner": "Apache/2.4.41 (Ubuntu)",
  "mssql.enabled": false,
  "logger": { "class": "PyLogger", "kwargs": { "formatters": { "plain": {} }, "handlers": { "TimedRotatingFileHandler": { "filename": "/var/log/opencanary.log" }}}}
}
```
### Midday (Learn/Labs, ~3h)
- Define **token placement strategy**: tokens only in **lab** assets (test repo/wiki), not in real production code. Document clear markers to avoid accidental use.
- Create **alerts**: any canary token use = **HIGH**; honey JWT use on honey‑API = **HIGH**.

### Afternoon (Drill/Test, ~3h)
- Trigger a honey JWT against the honey‑API; verify Loki ingestion & alert; ensure API never performs real actions.
- Record end‑to‑end timing: token creation → use → alert notification latency.

### Evening (Document/Share, ~2h)
- Add `playbooks/canary-credential.md` with triage steps, scoping questions, and containment options.

### Acceptance criteria
- OpenCanary logs flow; token hits trigger alerts with context; honey‑API is inert and safe.

---

# Day 5 — **Enrichment & Correlation (GeoIP/ASN/JA3 + Zeek)**

### Morning (Build, ~4h)
- Add a lightweight **enrichment step** (Promtail pipeline or Loki query stage) to attach **GeoIP/ASN** labels using a local MMDB. For TLS flows, capture **JA3** fingerprints (from Zeek logs).
- Parse Cowrie user‑agent strings and command lines to categorize activity (scanner vs interactive).

### Midday (Learn/Labs, ~3h)
- Correlate with **Zeek** (Week 11): join by 5‑tuple + time to validate inbound flows; confirm no outbound traffic from sensors.
- Create dashboard panels for **Top ASNs**, **Top JA3s**, and **First‑time‑seen IP/JA3**.

### Afternoon (Drill/Test, ~3h)
- Replay captured pcaps (lab) to Zeek; verify join queries in Grafana (multi‑query view).
- Document data retention and PII handling (IP addresses considered personal data in some regions).

### Evening (Document/Share, ~2h)
- Update `dashboards/honeypot-overview.json` with enrichment panels and `docs/dashboards.md` with query recipes.

### Acceptance criteria
- Enrichment labels appear; panels render; no sensor emits outbound traffic; correlation with Zeek verified.

---

# Day 6 — **Alerts, Playbooks & Failure Drills**

### Morning (Build, ~4h)
- Write **Loki alert rules**: sustained brute attempt, interactive shell opened, first‑time‑seen malware hash family, canary token used, first‑seen JA3.
- Define **runbooks** (playbooks directory) with: validation, enrichment, scope, contain, lessons‑learned.

```yaml
# alerts/loki-rules.yaml (snippet)
- alert: HoneypotBruteforceSustained
  expr: sum(count_over_time(({sensor="cowrie"} |= "login attempt")[5m])) by (dst_host) > 200
  for: 2m
  labels: { severity: medium }
- alert: CanaryTokenUsed
  expr: sum(count_over_time(({sensor="honeyapi"} |= "honey_jwt_used")[5m])) > 0
  for: 0m
  labels: { severity: critical }
```
### Midday (Learn/Labs, ~3h)
- Define **noise budgets** and escalation paths; implement **silences/maintenance windows** for lab tests.
- Plan **auto‑ticketing** (optional) via webhook contact points.

### Afternoon (Drill/Test, ~3h)
- Trigger each alert scenario with scripts; verify notification delivery, deduplication, and correct severity.
- Perform **failure drills**: take Loki down; ensure Promtail buffers; confirm recovery and **no data loss** beyond tolerance.

### Evening (Document/Share, ~2h)
- Finalize playbooks with screenshots and timing; update `docs/report-week16.md` with lessons learned.

### Acceptance criteria
- All target alerts trigger in simulations; playbooks actionable; pipeline recovers from induced failure.

---

# Day 7 — **Mini‑Project & Release: Deception Pack v1.6.0**

### Morning (Build, ~4h)
- Package `week16-honeypot-capstone-prep` with compose files, configs, dashboards, alerts, playbooks, and a sample **field report** template.
- Include **redacted** example logs and a **README** for single‑node bring‑up.

### Midday (Learn/Labs, ~3h)
- Run **fresh install** test on a clean VM; measure time‑to‑first‑signal (TTFS).
- Open issues for capstone expansion: additional services (RDP, MySQL honeypot), external TI feeds, active responses (blackhole lists) — **lab only**.

### Afternoon (Drill/Test, ~3h)
- Create a short **demo** (optional) showing brute force → alert → playbook flow (screenshots OK).
- Tag **v1.6.0-deception** release; add checksums for JSON dashboards and configs.

### Evening (Document/Share, ~2h)
- Cross‑link to prior weeks: Week 11 (Zeek), Week 12 (Loki alerts), Week 13 (recon → to honeypot), Week 14 (auth telemetry).

### Acceptance criteria
- Release reproducible; TTFS measured; capstone TODOs created; isolation & safety rules prominent.


---

## How this week advances your cybersecurity path
- **Blue/Detections:** You now generate high‑signal alerts on attacker behavior while minimizing false positives.
- **Purple‑team:** You can safely simulate and validate detections end‑to‑end using your own deception layer.
- **Capstone readiness:** You have a deployable foundation to integrate with advanced monitoring, DFIR pipelines, and app security controls.


---

## References / Study Hubs
- Cowrie (SSH/Telnet honeypot), Dionaea (malware), OpenCanary (service decoys), Zeek (network), Grafana Loki/Promtail, Grafana dashboards & alerting docs
- Honeypot OPSEC best practices (isolation, egress deny, legal/ethics)
- JA3 fingerprinting primers; GeoIP/ASN enrichment how‑tos

## Rubric (Week 16)
- **Isolation**: honeypots run in a locked‑down network; egress deny enforced.
- **Telemetry**: logs from all sensors ship to Loki; enrichment labels present; dashboards render.
- **Alerts**: brute, interactive shell, malware hash, canary use, first‑seen JA3 — all tested and documented.
- **Playbooks**: clear validation/containment; failure drills executed; recovery verified.
- **Release**: v1.6.0‑deception with compose/configs/dashboards/alerts/playbooks and report; clean install succeeds.

