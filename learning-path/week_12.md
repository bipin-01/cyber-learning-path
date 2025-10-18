# Week 12 — **Security & System Monitoring Mastery**: Sysmon/Sigma → Loki/Promtail/Grafana (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Build a production‑credible **security telemetry pipeline** end‑to‑end. Instrument Windows (Sysmon) and Linux (Sysmon for Linux + journald), collect with **Grafana Agent/Promtail**, store in **Loki**, visualize in **Grafana**, and alert on **Sigma‑derived** queries. You’ll add **OpenTelemetry logs** from your app, correlate signals, and deliver **day‑1 value dashboards** mapped to OWASP A09 and ATT&CK.

> **Ethics & Safety:** Only collect and retain data in your controlled lab. Redact or hash PII before sharing artifacts publicly.

---

## Outcomes
- Deploy **Sysmon (Windows)** and **Sysmon for Linux** with hardened configs.
- Ship logs with **Grafana Agent (Windows Event Log → Loki)** and **Promtail** (journald/syslog) on Linux.
- Stand up **Loki + Grafana** (docker‑compose) and enable **alerting** with LogQL.
- Compile **Sigma** rules to **Loki** queries and integrate alerts.
- Correlate **app logs** (OpenTelemetry) with host telemetry via correlation IDs.
- Publish `week12-monitoring-pipeline` with configs, dashboards, Sigma, and an alert playbook.

## Repository layout (this week)

```
/week12-monitoring-pipeline
  ├─ windows/
  │  ├─ sysmon-config.xml
  │  ├─ agent-config.yaml
  │  └─ install.ps1
  ├─ linux/
  │  ├─ sysmon-linux-config.xml
  │  ├─ promtail-config.yml
  │  └─ install.sh
  ├─ compose/
  │  ├─ docker-compose.yml
  │  ├─ loki-config.yml
  │  └─ grafana-provisioning/
  │     ├─ datasources/loki.yml
  │     └─ dashboards/
  │        ├─ sysmon-overview.json
  │        ├─ auth-security.json
  │        ├─ app-api-owasp.json
  │        └─ postgres-audit.json
  ├─ sigma/
  │  ├─ windows/powershell_encoded.yml
  │  ├─ windows/suspicious_schtasks.yml
  │  ├─ windows/rdp_logon_spike.yml
  │  ├─ linux/suspicious_shell_history.yml
  │  └─ linux/unexpected_useradd.yml
  ├─ alerts/
  │  ├─ loki-rules.yaml
  │  └─ grafana-contact-points.json
  ├─ otel/
  │  └─ app-logs-collector.yaml
  ├─ docs/
  │  ├─ pipeline.md
  │  ├─ sigma-to-loki.md
  │  ├─ dashboards.md
  │  ├─ alert-playbook.md
  │  └─ report-week12.md
  └─ README.md
```

---

# Day 1 — Platform Bring‑up

### Tasks
- Compose up **Loki + Grafana**.
- Provision Grafana datasource for Loki and verify Explore.

### Snippets
```yaml
services:
  loki:
    image: grafana/loki:2.9.0
    command: -config.file=/etc/loki/local-config.yaml
    volumes: [ "./loki-config.yml:/etc/loki/local-config.yaml" ]
    ports: [ "3100:3100" ]
  grafana:
    image: grafana/grafana:10.4.0
    volumes: [ "./grafana-provisioning:/etc/grafana/provisioning" ]
    ports: [ "3000:3000" ]
```
---

# Day 2 — Windows Sysmon + Agent

### Tasks
- Install Sysmon with hardened config; ship **Sysmon/Security** channels via **Grafana Agent** to Loki.
- Build first dashboard panels: EncodedCommand, Failed Logons, Parent→Child tree.

### Snippets
```yaml
logs:
  configs:
    - name: windows-evtx
      scrape_configs:
        - job_name: windows-eventlog
          windows_events:
            eventlog_name: ["Microsoft-Windows-Sysmon/Operational","Security"]
            xpath_query: "*[System[(EventID=1 or EventID=3 or EventID=4688 or EventID=4625)]]"
      clients: [ { url: http://localhost:3100/loki/api/v1/push } ]
```
---

# Day 3 — Linux Sysmon + Promtail

### Tasks
- Install Sysmon for Linux; scrape **journald** with Promtail.
- Panels: sudo actions, new users/groups, cron/systemd changes.

### Snippets
```yaml
scrape_configs:
  - job_name: journal
    journal: { json: true }
    labels: { host: "{{ .Hostname }}" }
    clients: [ { url: http://localhost:3100/loki/api/v1/push } ]
```
---

# Day 4 — Sigma → Loki + Correlation

### Tasks
- Write Sigma rules (PowerShell EncodedCommand, schtasks).
- Translate to LogQL queries; add OpenTelemetry app logs with correlation IDs and pivot dashboards.

### Snippets
```text
{channel="Microsoft-Windows-Sysmon/Operational", event_id="1"} |= "powershell.exe" |= "EncodedCommand"
```
---

# Day 5 — Alerting & Playbooks

### Tasks
- Create Loki alert rules (EncodedCommand, failed logon spike).
- Write triage playbooks and test notifications.

### Snippets
```yaml
- alert: PowerShellEncodedCommand
  expr: sum(count_over_time(({event_id="1"} |= "powershell.exe" |= "EncodedCommand")[5m])) > 0
  for: 1m
  labels: { severity: high }
```
---

# Day 6 — Performance & Hygiene

### Tasks
- Tune labels & retention; add ingestion health dashboards.
- Run failure drills (Loki down → shipper backoff).

---

# Day 7 — Release Pack

### Tasks
- Run a simulation day; capture dashboards + alerts.
- Tag **v1.2.0-monitoring**; package configs, dashboards, Sigma, and report.


---

## References
- Sysmon (Windows & Linux), Grafana Loki/Promtail/Agent, SigmaHQ, LogQL docs.

