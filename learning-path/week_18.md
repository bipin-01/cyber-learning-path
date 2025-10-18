# Week 18 — **Shell Mastery Deep Dives**: PowerShell (Core/Windows) + Bash (POSIX/Linux) (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Become fluent in the two shells you’ll use most as a security engineer. You’ll master **PowerShell** (objects, remoting/JEA, CIM/WMI, ETW, Pester, module authoring) and **Bash** (strict‑mode, traps, awk/sed/jq/yq, systemd/journald, networking), build **cross‑platform IR/ops scripts**, and publish a **reusable toolkit** that plugs into Weeks 11–17 (DFIR, monitoring, backend, honeypots).

> **Safety:** Practice on lab VMs and containers you control. Remoting/JEA configurations should be scoped to the lab domain/hosts and audited.

---

## Outcomes
- Write **idiomatic PowerShell** (Core 7.x) with robust error handling, structured logging, and object‑pipelines.
- Author and test a **PowerShell module** with **Pester**; publish artifacts for reuse across the plan.
- Operate **PowerShell Remoting** and **JEA** roles safely; query Windows telemetry via **CIM/WMI**, Registry, ETW, and Event Logs.
- Write **production‑grade Bash** in strict mode with traps, safe temp files, and data‑oriented pipelines (awk/sed/jq/yq).
- Automate **system introspection** on Linux (journald, systemd units/timers, auditd/Falco if present) and network triage.
- Ship `week18-shell-mastery` containing a PowerShell module, Bash utilities, tests, and a cross‑platform IR mini‑suite.

## Repository layout (this week)

```
/week18-shell-mastery
  ├─ powershell/
  │  ├─ Modules/SecOps.Tools/
  │  │  ├─ SecOps.Tools.psd1
  │  │  ├─ SecOps.Tools.psm1
  │  │  └─ Private/ , Public/       # function folders
  │  ├─ scripts/
  │  │  ├─ Get-SysmonSummary.ps1
  │  │  ├─ Get-NmapDelta.ps1        # compare Nmap XML → JSONL
  │  │  ├─ Invoke-DFIR-Triage.ps1
  │  │  └─ New-JEASession.ps1
  │  ├─ tests/
  │  │  └─ SecOps.Tools.Tests.ps1   # Pester tests
  │  └─ profile/README.md           # PSReadLine, prompt, transcript
  ├─ bash/
  │  ├─ bin/
  │  │  ├─ sysmon_summary.sh        # Linux Sysmon/journald summary
  │  │  ├─ nmap_delta.sh
  │  │  ├─ ir_triage.sh
  │  │  └─ zeek_stats.sh
  │  ├─ lib/
  │  │  ├─ strict.sh                # set -Eeuo pipefail + traps
  │  │  └─ json.sh                  # jq helpers
  │  ├─ tests/
  │  │  └─ bats/                    # if you use bats-core (optional)
  │  └─ systemd/
  │     ├─ ir-triage.service
  │     └─ ir-triage.timer
  ├─ docs/
  │  ├─ powershell_cookbook.md
  │  ├─ bash_cookbook.md
  │  ├─ cross_platform_ir.md
  │  └─ report-week18.md
  └─ README.md
```

---

# Day 1 — **PowerShell Core Fundamentals: Objects > Text**

### Morning (Build, ~4h)
- Install **PowerShell 7.x** (if not already). Configure **PSReadLine** (history search, predictive IntelliSense).
- Warm up on **object pipelines**: `Get-Process | Sort CPU -Desc | Select -First 5 | Format-Table` vs `... | ConvertTo-Json` for machine output.
- Create `SecOps.Tools` skeleton (module manifest + module file, Public/Private folders).

```powershell
# powershell/Modules/SecOps.Tools/Public/Get-TopProcess.ps1
function Get-TopProcess {
  [CmdletBinding()] param([int]$Top = 5, [string]$Order = 'CPU')
  Get-Process | Sort-Object -Property $Order -Descending | Select-Object -First $Top |
    Select-Object Name, Id, CPU, WS, StartTime
}
Export-ModuleMember -Function Get-TopProcess
```
### Midday (Learn/Labs, ~3h)
- Understand **streams** (Success/Verbose/Warning/Error/Debug) and how to use `Write-Information` + `Start-Transcript` for auditable runs.
- Use **parameter validation** attributes and `ShouldProcess` for safe **-WhatIf** behavior.

### Afternoon (Drill/Test, ~3h)
- Implement `Get-SysmonSummary.ps1`: read **Sysmon** event log, group by Event ID, top parents/children, top network destinations.
- Add `Get-NmapDelta.ps1`: parse Nmap XML (Week 10) and output **JSONL** with open port deltas since last run.

```powershell
# powershell/scripts/Get-SysmonSummary.ps1 (snippet)
$log = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5000 |
  Select-Object TimeCreated, Id, MachineName, @{n='Image';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[10].Value}}
$byId = $log | Group-Object Id | Sort-Object Count -Desc | Select-Object -First 10
$byId | Format-Table Name,Count
```
### Evening (Document/Share, ~2h)
- Write `powershell_cookbook.md` (streams, parameters, pipeline). Take before/after screenshots (table vs JSON).

### Acceptance criteria
- `SecOps.Tools` imports cleanly; example functions return **objects**; Sysmon summary and Nmap delta scripts run on your lab VM.

---

# Day 2 — **Pester Testing, Error Handling & Structured Logs**

### Morning (Build, ~4h)
- Add **Pester** tests for module functions; stub external calls; include **ShouldProcess** tests.
- Implement a **structured logger** helper that emits **JSON** to file (suitable for Loki ingestion).

```powershell
# powershell/tests/SecOps.Tools.Tests.ps1 (snippet)
Import-Module "$PSScriptRoot/../Modules/SecOps.Tools/SecOps.Tools.psd1"
Describe 'Get-TopProcess' {
  It 'returns Top items' {
    (Get-TopProcess -Top 3).Count | Should -Be 3
  }
}
```
```powershell
# powershell/Modules/SecOps.Tools/Private/Write-JsonLog.ps1
function Write-JsonLog { param([string]$Message,[string]$Level='Info',[hashtable]$Data)
  $obj = [pscustomobject]@{ ts=(Get-Date).ToUniversalTime().ToString('o'); level=$Level; msg=$Message; data=$Data }
  $obj | ConvertTo-Json -Compress | Out-File -FilePath "$env:TEMP\secops.log" -Append -Encoding utf8
}
```
### Midday (Learn/Labs, ~3h)
- Study **terminating vs non‑terminating** errors, `try/catch/finally`, and `$ErrorActionPreference`.
- Adopt **CmdletBinding(SupportsShouldProcess)** and return **status objects** rather than writing text.

### Afternoon (Drill/Test, ~3h)
- Refactor scripts to use `Write-JsonLog`; verify logs appear in Loki (Week 12) via file scraper.
- Add a **Pester CI** step (local script) that runs tests on each change.

### Evening (Document/Share, ~2h)
- Expand cookbook with **error handling** patterns and a small **style guide** (nouns for functions, approved verbs).

### Acceptance criteria
- Green Pester run; JSON logs captured; functions implement `-WhatIf` and `-Confirm` semantics where risky.

---

# Day 3 — **Remoting & JEA; CIM/WMI; Registry/ACLs**

### Morning (Build, ~4h)
- Enable **PowerShell Remoting** in lab; create a **JEA** endpoint limiting commands (Get‑Process, Get‑Service, Get‑EventLog, custom functions).
- Write `New-JEASession.ps1` helper to enter JEA and run a limited command set.

```powershell
# powershell/scripts/New-JEASession.ps1 (snippet)
$session = New-PSSession -ConfigurationName 'SecOpsJEA' -ComputerName LAB-WS01
Invoke-Command -Session $session -ScriptBlock { Get-Process | Select Name,Id,CPU -First 5 }
```
### Midday (Learn/Labs, ~3h)
- Query with **CIM** (`Get‑CimInstance Win32_Process`, `Win32_QuickFixEngineering`) and **Registry** via `Get‑ItemProperty`.
- Modify **file/registry ACLs** safely with `Get‑Acl/Set‑Acl`; audit changes.

### Afternoon (Drill/Test, ~3h)
- Build `Invoke-DFIR-Triage.ps1` that runs via JEA: processes, services, autoruns (where allowed), EVTX export, hash evidence; no admin commands allowed.
- Add ETW/Operational channel query examples (PowerShell/Operational, TaskScheduler).

### Evening (Document/Share, ~2h)
- Document JEA role capabilities and **least privilege** rationale; add cleanup instructions.

### Acceptance criteria
- JEA endpoint works; triage runs under limited rights; CIM/registry queries succeed; ACL edits tested in a safe directory.

---

# Day 4 — **Bash Strict‑Mode, Traps, and Data Pipelines**

### Morning (Build, ~4h)
- Create `lib/strict.sh` with `set -Eeuo pipefail`, `IFS=$'\n\t'`, a robust `trap` for ERR/EXIT, and **mktemp** usage.
- Write helpers in `lib/json.sh` for jq wrappers and a `die()` function that prints structured errors.

```bash
# bash/lib/strict.sh
set -Eeuo pipefail
IFS=$'
	'
cleanup(){ :; }
err(){ echo "{"ts":"$(date -Is)","level":"error","msg":"${1:-fail}"}" >&2; }
trap 'err "line $LINENO"; cleanup' ERR
tmpd="$(mktemp -d)"; trap 'rm -rf "$tmpd"' EXIT
```
```bash
# bash/bin/sysmon_summary.sh
#!/usr/bin/env bash
. "$(dirname "$0")/../lib/strict.sh"
journalctl -u sysmon --since "1 day ago" | awk '{print $3}' | sort | uniq -c | sort -nr | head -20
```
### Midday (Learn/Labs, ~3h)
- Review quoting rules; **arrays** and **assoc arrays**; **parameter expansion** (`${var:-default}`, `${var%pattern}`).
- Practice with `awk` joins and `sed` transforms; convert CSV↔JSON using `mlr` or `awk` + `jq`.

### Afternoon (Drill/Test, ~3h)
- Write `nmap_delta.sh`: parse two XMLs with `xmlstarlet` or `xsltproc`, produce JSON diff via jq.
- Write `zeek_stats.sh`: summarize Zeek logs (conn.log/http.log) for top talkers, JA3s, status codes.

### Evening (Document/Share, ~2h)
- Document strict‑mode pitfalls (set -e with pipelines), and how `set -o pipefail` changes failure semantics.

### Acceptance criteria
- Scripts run with strict‑mode and traps; delta/stats outputs are machine‑readable and stable.

---

# Day 5 — **Bash Ops: systemd/journald, Networking & Parallelism**

### Morning (Build, ~4h)
- Create a **systemd service + timer** for `ir_triage.sh` (daily). Add journald structured fields with `logger -t` and JSON payloads.
- Networking triage: `ss -tulpen`, `ip -brief a`, `ip route`, `nft list ruleset` (or `iptables -S`) with safe read‑only commands.

```ini
# bash/systemd/ir-triage.service
[Service]
Type=oneshot
ExecStart=/opt/week18/bash/bin/ir_triage.sh
User=root
```
```bash
# bash/bin/ir_triage.sh (snippet)
. "$(dirname "$0")/../lib/strict.sh"
logger -t ir_triage '{"event":"start"}'
ss -tulpen | tee "$tmpd/ports.txt"
logger -t ir_triage '{"event":"done"}'
```
### Midday (Learn/Labs, ~3h)
- Use **GNU parallel** (or `xargs -P`) to fan‑out safe read operations; design **rate limits** and **timeouts**.
- Add SSH config best practices: ControlMaster, ProxyJump, `ssh -J` for bastions, **no agent forwarding** by default.

### Afternoon (Drill/Test, ~3h)
- Benchmark triage with and without parallelism; ensure logs capture timing and errors.
- Create a minimal **network snapshot** artifact (routes, ARP, ports) for DFIR correlation.

### Evening (Document/Share, ~2h)
- Update `bash_cookbook.md` with systemd/journald usage and SSH hardening notes.

### Acceptance criteria
- Service+timer run and log to journald; network snapshot reproducible; parallel triage safe and faster.

---

# Day 6 — **Cross‑Platform IR Scripting: Correlate & Package**

### Morning (Build, ~4h)
- Create a **single entrypoint**: `Invoke-IR.ps1` (Windows) and `ir.sh` (Linux) to collect: processes, users/sessions, network, autoruns/services, recent logs, and optional Zeek summaries; compute **SHA‑256** of the bundle.
- Normalize output to a common folder structure and **JSONL** where possible.

```powershell
# powershell/scripts/Invoke-DFIR-Triage.ps1 (snippet)
param([string]$Out="C:\IR\$(Get-Date -Format yyyyMMdd_HHmmss)")
New-Item -ItemType Directory -Force -Path $Out | Out-Null
Get-Process | Select Name,Id,CPU,StartTime | ConvertTo-Json -Depth 2 > "$Out\process.json"
Get-NetTCPConnection | ConvertTo-Json > "$Out\net_tcp.json"
Compress-Archive -Path $Out -DestinationPath "$Out.zip"
```
```bash
# bash/bin/ir.sh (snippet)
. "$(dirname "$0")/../lib/strict.sh"
out="${1:-/var/tmp/ir_$(date +%Y%m%d_%H%M%S)}"; mkdir -p "$out"
ps aux --sort=-%cpu | awk 'NR<=30{print}' > "$out/process.txt"
ss -tunap > "$out/net.txt"
tar -C "$(dirname "$out")" -czf "$out.tar.gz" "$(basename "$out")"
```
### Midday (Learn/Labs, ~3h)
- Add **hashing** and **manifest** files; optionally push manifests to **Loki** for searchable evidence indexes.
- Create **redaction** steps for usernames, IPs, and hostnames when publishing artifacts.

### Afternoon (Drill/Test, ~3h)
- Run both triage entrypoints on lab hosts; verify structure and hashes; load JSONL into your Week 12 dashboards for quick overviews.
- Optionally add a **KQL/LogQL** query cheat sheet for common pivots.

### Evening (Document/Share, ~2h)
- Finish `cross_platform_ir.md` with folder structures, command maps (PowerShell vs Bash), and sample pivots.

### Acceptance criteria
- Cross‑platform triage works and produces comparable artifacts; manifests include hashes; dashboards ingest summaries.

---

# Day 7 — **Mini‑Project & Release: Shell Toolkit v1.8.0**

### Morning (Build, ~4h)
- Package **SecOps.Tools** (module) + Bash utilities with tests into a release; include example **JEA** config and **systemd timer**.
- Add two CLI commands that pipe into Week 12: `ps:hot` (top CPU/mem) and `net:spikes` (conn deltas).

### Midday (Learn/Labs, ~3h)
- Smoke‑test on fresh Windows/Linux VMs; document prerequisites; ensure **no admin** required for read‑only tasks wherever possible.
- Create **man pages**/help for each script and function (`Get-Help` content, `--help` output).

### Afternoon (Drill/Test, ~3h)
- Capture demo screenshots: JEA session running triage; journald view of timer; Loki Explore showing JSON logs from both shells.
- Tag **v1.8.0-shells**; include checksums and changelog.

### Evening (Document/Share, ~2h)
- Open issues for future: PS DSC samples, Bash `bpftrace` snippets, cross‑host fan‑out via Ansible/WinRM.


### Acceptance criteria
- Release reproducible; tests pass; docs complete; artifacts integrate with previous weeks’ pipelines.


---

## How this week advances your cybersecurity path
- **Incident response:** Faster, scripted triage with consistent artifacts on both Windows and Linux.
- **Engineering quality:** Tested modules/scripts with structured logs integrate directly into your monitoring stack.
- **Purple‑team:** You can reproduce attacker traces (safely) and convert them into queries/detections quickly.


---

## References / Study Hubs
- PowerShell Docs (Core 7.x): about_*, CIM/WMI, ETW/Event Logs, Remoting, JEA, Pester
- Bash Reference Manual; ShellCheck; bats‑core; GNU coreutils; gawk/sed; jq/yq
- Windows Sysmon/Eventing; Linux journald/systemd; Zeek basics

## Rubric (Week 18)
- **PowerShell**: module compiles; Pester tests; remoting/JEA; CIM/registry operations; structured logs.
- **Bash**: strict‑mode + traps; jq/awk/sed pipelines; journald/systemd integration; networking triage.
- **Cross‑platform**: IR scripts produce normalized artifacts with hashes; dashboards/queries demonstrated.
- **Release**: v1.8.0-shells with docs, examples, tests; runs on clean Windows/Linux lab VMs.

