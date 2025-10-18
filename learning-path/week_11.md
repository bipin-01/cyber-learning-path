# Week 11 — **DFIR Mastery**: Host • Memory • Network Forensics (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Triage and investigate an endpoint compromise end‑to‑end. You’ll practice **forensicly sound collection**, build **timelines**, analyze **memory images** (Volatility3), and extract **network evidence** (Zeek/Wireshark). You’ll correlate with logs you built in earlier weeks (Sysmon, pgAudit, app logs) and publish an **evidence‑grade incident report** with IOC packs, Sigma/YARA, and a repeatable notebook.

> **Ethics & Safety:** Only examine systems you control or have explicit permission to analyze. Handle potentially sensitive data with strict access controls; redact before publishing.

---

## Outcomes
- Perform **forensically sound triage** on Windows & Linux: volatile data, disk artifacts, and logs without altering MAC times.
- Parse **Windows artifacts** (Event Logs, SRUM, Shimcache/Amcache, Prefetch, USN Journal) & **Linux** (journald, auth logs, bash history, services, crontab).
- Analyze **memory images** using **Volatility3**: processes, DLLs, network, handles, malfind, registry hives.
- Turn **pcaps → evidence** with **Zeek** and Wireshark; extract files, reconstruct sessions, and derive IOCs.
- Create **super‑timelines** with **Plaso/Timesketch**; correlate against Sysmon/pgAudit/app logs and your Zeek logs.
- Write **YARA** (memory/disk) and **Sigma** (log) rules; produce IOC packs (hashes, domains, URIs, JA3).
- Publish `week11-dfir-endtoend` with scripts, checklists, notebooks, dashboards, and a redacted incident report.

## Repository layout (this week)

```
/week11-dfir-endtoend
  ├─ acquisition/
  │  ├─ triage_windows.ps1          # live response (safe mode)
  │  ├─ triage_linux.sh             # live response
  │  └─ chain_of_custody.md
  ├─ analysis/
  │  ├─ notebooks/
  │  │  ├─ timeline_correlate.ipynb
  │  │  └─ zeek_pcap_walkthrough.ipynb
  │  ├─ volatility3_notes.md
  │  ├─ windows_artifacts.md
  │  ├─ linux_artifacts.md
  │  └─ zeek_playbook.md
  ├─ iocs/
  │  ├─ indicators.csv              # type,value,context,confidence
  │  ├─ yara/
  │  │  └─ mem_suspicious_webshell.yar
  │  └─ sigma/
  │     └─ sysmon_webshell.yml
  ├─ tools/
  │  ├─ plaso_pipeline.md
  │  ├─ timesketch_setup.md
  │  └─ parse_evtx.py
  ├─ dashboards/
  │  ├─ sysmon-hunt.json
  │  └─ zeek-overview.json
  ├─ docs/
  │  ├─ dfir_checklists.md
  │  ├─ chain_of_custody_template.docx
  │  ├─ report-week11.md
  │  └─ readme_evidence_handling.md
  └─ README.md
```

---

# Day 1 — **Triage Playbooks & Evidence Handling**

### Morning (Build, ~4h)
- Write **chain_of_custody_template** and `readme_evidence_handling.md`: who/what/when/where, hash algorithms (SHA‑256), time sync policy.
- Author `triage_windows.ps1` to collect: running processes, network conns, services, autoruns, scheduled tasks, important registry hives, Event Logs (EVTX), Prefetch, SRUM, Shimcache/Amcache, and a **RAM image** (if allowed in lab). Ensure **no automatic cleaning** of Prefetch or logs.
- Author `triage_linux.sh` to collect: processes, open files, listening ports, users/groups/sudoers, cron/systemd timers, journald/syslog, bash/zsh history, `/etc` configs, and memory (if supported).

```powershell
# acquisition/triage_windows.ps1 (snippet)
$dest = "C:\IR\triage_$(Get-Date -Format yyyyMMdd_HHmmss)"
New-Item -ItemType Directory -Path $dest | Out-Null
wevtutil epl Security "$dest\Security.evtx"
Get-Process | Sort-Object -Property StartTime | Export-Csv "$dest\processes.csv" -NoTypeInformation
Get-NetTCPConnection | Export-Csv "$dest\net_tcp.csv" -NoTypeInformation
# ... add Autoruns, services, tasks, SRUM export steps, and hash all outputs
Get-ChildItem $dest -Recurse | Get-FileHash -Algorithm SHA256 | Export-Csv "$dest\hashes.csv" -NoTypeInformation
```
### Midday (Learn/Labs, ~3h)
- Review **order of volatility**; ensure scripts capture volatile data first (net, proc, memory) then disk artifacts.
- Set up a **hashing** standard (SHA‑256) and a **time‑source** (NTP) for all hosts to keep timelines consistent.

### Afternoon (Drill/Test, ~3h)
- Run the scripts in a **Windows VM** and a **Linux VM**; verify outputs and compute hashes; store in `/evidence/<host>/<yyyymmdd>/`.
- Create `dfir_checklists.md` (triage steps, do/don’t, safe commands) and `chain_of_custody.md` for your lab sample.

### Evening (Document/Share, ~2h)
- Document **acquisition pitfalls** (Volume Shadow Copies, permissions, AV interference) and mitigations.
- Add a **redaction policy** for PII (replace emails/usernames with pseudonyms in public artifacts).

### Acceptance criteria
- Both triage scripts run cleanly and produce hashed evidence packages.
- Checklists and chain‑of‑custody templates are ready for use.

---

# Day 2 — **Windows Forensics: Artifacts Deep‑Dive**

### Morning (Build, ~4h)
- Analyze **EVTX** (Security, Sysmon, PowerShell/Operational, TaskScheduler, WMI‑Activity, TerminalServices) using `parse_evtx.py` to extract key fields (TimeCreated, EventID, User, Computer, CommandLine, Parent).
- Parse **Shimcache (AppCompatCache)**, **Amcache**, **Prefetch**, and **SRUM** to uncover execution & persistence, app usage, network patterns.

```python
# tools/parse_evtx.py (sketch)
import sys, json
from xml.etree import ElementTree as ET
from glob import glob

def event_rows(path):
    for f in glob(path):
        for line in open(f, 'rb'):
            pass
    # For brevity, implement using external libraries in your real lab (e.g., Evtx)
    # Here, document the fields you target and how to export to CSV/JSONL.
```
### Midday (Learn/Labs, ~3h)
- Read what each artifact proves: **Shimcache** = executed or attempted, **Amcache** = installs/first run, **Prefetch** = program execution (+ last runs), **SRUM** = app & network usage trends.
- Map to **MITRE ATT&CK**: Execution (T1059), Persistence (T1060 variants), Lateral Movement, Discovery.

### Afternoon (Drill/Test, ~3h)
- Generate benign activity (PowerShell commands, scheduled task, WMI query); verify artifacts show expected traces.
- Export **IOC candidates** (paths, hashes, command lines) to `iocs/indicators.csv` with context and confidence.

### Evening (Document/Share, ~2h)
- Write `windows_artifacts.md` with tables per artifact: source, tool, timestamp types, strengths/limits, example entries.
- Add Sigma draft for suspicious PowerShell with `EncodedCommand` and `DownloadString` patterns.

### Acceptance criteria
- Artifacts parsed with at least 10 example lines each; understanding of timestamp semantics documented.
- Sigma draft committed; IOC candidates extracted with rationale.

---

# Day 3 — **Linux Forensics & Logs**

### Morning (Build, ~4h)
- Collect and parse **auth.log/journald** (logins, sudo), **systemd units/timers**, **cron**, **bash history** with timestamps (`HISTTIMEFORMAT`).
- Inspect **/etc/passwd**/**shadow**, SSH keys/`authorized_keys`, known_hosts, and suspicious services or startup scripts.

### Midday (Learn/Labs, ~3h)
- Review **bash history gaps** (no timestamps, HISTCONTROL), and how to reconstruct sessions from **auditd** if available.
- Understand common persistence vectors: systemd units, cron, rc.local, profile.d, LD_PRELOAD, SSH backdoors.

### Afternoon (Drill/Test, ~3h)
- Generate benign sudo and SSH sessions; create/disable a simple systemd service to practice detection.
- Extract IOCs (IPs, usernames, paths) and add to `indicators.csv`; propose Sigma rules for SSH anomalies.

### Evening (Document/Share, ~2h)
- Write `linux_artifacts.md` with walk‑through and pitfalls (log rotation, time zones, containers).
- Add a quick **Falco/Sysmon for Linux** note if you run it in lab for extra telemetry.

### Acceptance criteria
- Linux timeline artifacts captured and summarized with at least 8 notable events.
- IOC entries and Sigma drafts updated for Linux findings.

---

# Day 4 — **Memory Forensics with Volatility3**

### Morning (Build, ~4h)
- Ingest a **memory image** into **Volatility3**: enumerate processes (`pslist/psscan`), DLLs (`dlllist`), network (`netscan`), handles, and suspicious memory regions (`malfind`).
- Dump suspicious processes or modules; compute hashes; attempt **YARA scans** against memory regions.

```bash
# Typical Volatility3 flow (paths depend on your lab)
vol -f mem.vmem windows.pslist
vol -f mem.vmem windows.netscan
vol -f mem.vmem windows.malfind --dump
vol -f mem.vmem windows.cmdline
vol -f mem.vmem yarascan.YaraScan --yara-file iocs/yara/mem_suspicious_webshell.yar
```
### Midday (Learn/Labs, ~3h)
- Understand **EPROCESS/ETHREAD**, injected code patterns (RWX regions), hollowing indicators, and parent/child anomalies.
- Review acquiring memory safely (hiberfil, pagefile, live capture tradeoffs).

### Afternoon (Drill/Test, ~3h)
- Correlate suspicious process → command line → network connections; pivot to disk artifacts for supporting evidence.
- Export findings to `volatility3_notes.md` with screenshots and hashes.

### Evening (Document/Share, ~2h)
- Refine **YARA** rule(s) based on observed strings/sections; document false positives and scoping advice.
- Update `indicators.csv` with memory findings (module hashes, mutexes, C2 URIs).

### Acceptance criteria
- Volatility3 baseline plugins executed; at least one dumped region analyzed; YARA scan produces signal or clean negative with rationale.
- Memory findings integrated into IOC pack.

---

# Day 5 — **Network Forensics: Zeek + Wireshark**

### Morning (Build, ~4h)
- Run **Zeek** on lab **pcap** to generate `conn.log`, `http.log`, `dns.log`, `ssl.log`, `files.log`; enable file extraction for HTTP/SMB where safe.
- Summarize **top talkers**, **JA3/JA3S** fingerprints, **User‑Agents**, **DNS queries** and anomalies (entropy, rare TLDs).

```bash
# Zeek from a pcap
zeek -Cr evidence/sample.pcap local "Site::local_nets += { 10.0.0.0/8 }"
# logs appear in current dir; aggregate with zeek-cut or jq
```
### Midday (Learn/Labs, ~3h)
- Use **Wireshark** to reconstruct suspect sessions (Follow TCP Stream) and export files for hashing.
- Learn to pivot **JA3 → known families** (document offline), and how to treat JA3 as heuristic not truth.

### Afternoon (Drill/Test, ~3h)
- Extract at least one file from `files.log`/Wireshark; hash and triage; check against your policy (do not run unknown binaries).
- Build small **Kibana/Grafana panels** from Zeek logs (status codes, unusual ports, new external IPs).

### Evening (Document/Share, ~2h)
- Write `zeek_playbook.md` with parsing commands, jq one‑liners, and triage tips.
- Update IOC pack with domains, JA3, URIs, IPs with confidence scores.

### Acceptance criteria
- Zeek logs produced and summarized; at least one extracted object analyzed (hash only).
- Panels/screenshots show useful overviews (conn volume, DNS, JA3).

---

# Day 6 — **Super‑Timeline & Correlation (Plaso/Timesketch)**

### Morning (Build, ~4h)
- Run **Plaso (log2timeline.py)** against your triage set and disk image (if available) to build a **super‑timeline**.
- Import into **Timesketch** (or analyze CSV locally) and tag events: initial access, execution, persistence, C2, exfiltration, cleanup.

```bash
# Plaso example (adjust paths to your lab)
log2timeline.py --status_view window evidence.plaso /evidence/host01/
psort.py -o L2tcsv -w timeline.csv evidence.plaso
```
### Midday (Learn/Labs, ~3h)
- Normalize **timezones** and **clock skew**; reconcile with Sysmon & PowerShell logs collected Week 3.
- Define **event labels** consistent with your report (e.g., PHASE:EXECUTION, PHASE:PERSISTENCE).

### Afternoon (Drill/Test, ~3h)
- Correlate **memory** (process start) → **disk** (prefetch, shimcache) → **network** (Zeek) → **DB/app logs**. Build a chain that explains attacker objectives.
- Draft **timeline figures** (Mermaid or table) for the report.

### Evening (Document/Share, ~2h)
- Export `timeline.csv`; add `timeline_correlate.ipynb` notebook with small pandas pivots (counts by phase, user, host).
- Update `report-week11.md` with a preliminary narrative (who/what/when/how/so‑what).

### Acceptance criteria
- Super‑timeline produced; at least 5 labeled key events with cross‑evidence references.
- Preliminary narrative connects artifacts to attacker behaviors.

---

# Day 7 — **Mini‑Project & Release: Incident #001**

### Morning (Build, ~4h)
- Finalize **IOC pack** (`iocs/indicators.csv`), **YARA**, **Sigma**, and any Zeek queries used; include confidence & false positive notes.
- Finish `report-week11.md` with Executive Summary, Scope, Methodology, Findings, Impact, IOCs, Recommended Actions, and **Appendices** (hashes, tool versions, chain of custody).

### Midday (Learn/Labs, ~3h)
- Peer‑review checklist: repeatability, timestamps in UTC, redactions applied, evidence hashes verified, conclusions tied to artifacts.
- Open issues for **automation** (next week): case templates, auto‑hashing, auto‑Zeek/Plaso pipelines.

### Afternoon (Drill/Test, ~3h)
- Package a release: redact and zip **notebooks**, **scripts**, **dashboards**, **IOC pack**, and `report-week11.md`.
- Create a small **README** that explains how to reproduce core steps with your sample evidence (or redacted mock).

### Evening (Document/Share, ~2h)
- Tag **v1.1.0-inc001**; include checksums for artifacts; add a visual of the attack chain.
- Write next‑steps tickets: endpoint collection hardening, Zeek sensors, Sigma → SIEM integration.

### Acceptance criteria
- Release includes report, IOC pack, Sigma/YARA, notebooks, dashboards, and acquisition scripts; hashes documented.
- Executive Summary + timeline figures tell a coherent story that maps to ATT&CK and to concrete mitigations.


---

## How this week advances your cybersecurity path
- **Blue/DFIR**: You can acquire, analyze, and report with **evidence discipline** end‑to‑end.
- **Purple‑team**: You translate attack traces into **detections** (Sigma/YARA) and **hardening actions** with confidence scores.
- **Platform/SecOps**: You produce artifacts (dashboards, pipelines) teams can run weekly, not just during incidents.


---

## References / Study Hubs
- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
- [Windows Forensic Artifacts (Hunt for SRUM, Amcache, Shimcache)](https://learn.microsoft.com/)
- [Plaso/Timesketch](https://plaso.readthedocs.io/) & [Timesketch](https://timesketch.org/)
- [Zeek](https://docs.zeek.org/en/current/)
- [Sigma HQ](https://github.com/SigmaHQ/sigma) & [YARA](https://yara.readthedocs.io/)

## Similar GitHub repos / inspiration
- [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)
- [google/timesketch](https://github.com/google/timesketch)
- [log2timeline/plaso](https://github.com/log2timeline/plaso)
- [zeek/zeek](https://github.com/zeek/zeek)
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

## Rubric (Week 11)
- **Acquisition**: scripts produce hashed evidence; chain of custody documented.
- **Analysis**: Windows/Linux artifacts parsed; memory (Volatility3) baseline + YARA; Zeek logs & Wireshark file extraction.
- **Correlation**: super‑timeline built; ≥5 key events labeled and cross‑referenced; IOCs triaged with confidence.
- **Detections**: Sigma/YARA authored; dashboards & queries present; negatives documented.
- **Reporting**: Executive Summary + appendices; reproducible notebooks; v1.1.0‑inc001 release with checksums.

