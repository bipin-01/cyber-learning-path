# Week 03 – **PowerShell Mastery + Windows Administration** (In‑Depth)

_Generated: October 18, 2025_

> **Theme:** Build production‑quality PowerShell (modules, tests, lint) and master Windows administration essentials: accounts/groups, JEA, Sysmon, WinRM/Remoting, and log shipping. Everything maps to **OWASP A05 (Misconfiguration)**, **A09 (Logging/Monitoring)**, and prepares you for DFIR and purple‑team drills.

---

## Outcomes
- Author **pipeline‑friendly** PowerShell functions with `CmdletBinding`, parameter validation, robust error handling, and object output.
- Publish a reusable **module** (`Company.SecOps`) with PSScriptAnalyzer clean, Pester tests, and CI.
- Deploy and tune **Sysmon** (SwiftOnSecurity config), and query high‑value events (1, 3, 7, 10, 11, 12, 13, 22).
- Stand up **log collection** (Winlogbeat or WEF) for Security + Sysmon + PowerShell logs into your SIEM (Elastic/Loki).
- Create a **JEA** (Just Enough Administration) endpoint for least‑privilege operator tasks.
- Secure **WinRM over HTTPS**, use **script signing**, and handle secrets safely (SecretManagement/CredMan/DPAPI).
- Publish the **Week 03 mini‑project**: `week03-powershell-admin-suite` with README, scripts, module, configs, tests, and a release.

## Repository layout (this week)

```
/week03-powershell-admin-suite
  ├─ src/Company.SecOps/
  │   ├─ Company.SecOps.psd1         # module manifest
  │   ├─ Company.SecOps.psm1         # module code (exports)
  │   └─ Public/ Private/            # functions
  ├─ scripts/                         # one-off admin scripts (bootstrap, install-sysmon, etc.)
  ├─ configs/
  │   ├─ sysmon-config.xml            # (reference to community config; include link, not vendor files)
  │   ├─ winlogbeat.yml               # sample, Security + Sysmon channels
  │   ├─ JEA/
  │   │   ├─ RoleCapabilities/OperatorTasks.psrc
  │   │   └─ SessionConfigs/OperatorEndpoint.pssc
  ├─ tests/                           # Pester tests
  ├─ examples/                        # sample outputs (JSON/CSV), screenshots
  ├─ .github/workflows/ci.yml
  ├─ .psscriptanalyzersettings.json
  └─ README.md
```

---

# Day 1 — **Module Skeleton, Coding Standards, Analyzer & Tests**

### Morning (Build, ~4h)
- Create folder structure above. Initialize `Company.SecOps.psd1` with `New-ModuleManifest` (set RootModule to `Company.SecOps.psm1`).
- Add a public function **Get-AuthFailures** that queries 4625/529 style failures via `Get-WinEvent -FilterHashtable`. Return **objects**, not strings.
- Add a public function **Get-ProcessNetAnomalies** that correlates processes (4688 or Sysmon 1) with outbound connections (Sysmon 3).
- Add a public function **Get-LocalAdminsDiff** that snapshots `Administrators` group and diffs against yesterday's JSON.

```powershell
function Get-AuthFailures {
  [CmdletBinding()]
  param(
    [int]$Hours = 24
  )
  $since = (Get-Date).AddHours(-$Hours)
  $filter = @{ LogName='Security'; Id=4625; StartTime=$since }
  Get-WinEvent -FilterHashtable $filter | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [pscustomobject]@{
      TimeCreated = $_.TimeCreated
      TargetUser  = $xml.Event.EventData.Data | ? { $_.Name -eq 'TargetUserName' } | % { $_.'#text' }
      IpAddress   = $xml.Event.EventData.Data | ? { $_.Name -eq 'IpAddress' } | % { $_.'#text' }
      LogonType   = $xml.Event.EventData.Data | ? { $_.Name -eq 'LogonType' } | % { $_.'#text' }
      Computer    = $_.MachineName
      EventId     = $_.Id
    }
  }
}
```
### Midday (Learn/Labs, ~3h)
- Read: **Advanced functions** (`[CmdletBinding()]`, `SupportsShouldProcess`, `ValueFromPipeline`).
- Study **ErrorActionPreference**, `try/catch/finally`, and exceptions vs non‑terminating errors.
- Add comment‑based help and examples to each public function.

### Afternoon (Drill/Test, ~3h)
- Create **PSScriptAnalyzer** settings (`.psscriptanalyzersettings.json`) and fix all issues.
- Write **Pester** tests for the three functions (use `Mock` for `Get-WinEvent`).
- Ensure functions **emit objects**, support `-Verbose`, and do not write random host output.

### Evening (Document/Share, ~2h)
- Write README: module goals, exported functions, example usage, and expected output schemas.
- Add CI workflow to run PSScriptAnalyzer + Pester on PRs.

### Why are we doing this?
PowerShell in real environments must be **reliable**, **testable**, and emit **structured objects**. This is what differentiates scripts from **tools**.

### Real‑world mapping
- SOC/IR: query security events quickly and reliably with reusable tooling.
- Platform: modules with tests integrate into enterprise automation safely.

### Acceptance criteria
- Analyzer clean; Pester tests passing in CI.
- Each public cmdlet has help (`Get-Help`) and example output in README.

---

# Day 2 — **Accounts, Groups, Local Policy & Baselines**

### Morning (Build, ~4h)
- Create **New-SecLocalUser** to add a local user with randomized secure password (or key‑based if applicable), non‑expiring optionally, and disabled interactive logon if service account.
- Create **Set-SecLocalPolicy** to toggle local security policies via `secedit` or `LGPO.exe` (if available) for lockout, audit policy, and RDP restrictions.
- Add **Get-LocalAdminsSnapshot** to capture members of the `Administrators` group to JSON with hashes.

### Midday (Learn/Labs, ~3h)
- Read: **Local Users and Groups**, password policy, **UAC** basics, and `AuditPol /get /category:*`.
- Practice: baseline collection then change one setting and capture the diff report.

### Afternoon (Drill/Test, ~3h)
- Build **Compare-AdminsSnapshot** that reads yesterday/today JSON and produces adds/removes.
- Generate a report (CSV + JSON) with who added when; test with a benign add/remove.

### Evening (Document/Share, ~2h)
- Document Joiner/Mover/Leaver flows and how your cmdlets enforce **least privilege**.
- Create troubleshooting notes for common errors (access denied, UAC prompts).

### Why?
Identity posture is the #1 control plane. Clear baselines + diffs make drift and privilege escalation visible.

### Real‑world mapping
- On‑boarding and access reviews (compliance evidence).
- IR: confirm whether an attacker added a local admin.

### Acceptance criteria
- Snapshot/diff works and exits non‑zero on unexpected admin adds.
- Policy function changes at least one auditable setting and logs proof.

---

# Day 3 — **Sysmon Deployment & Event Tuning**

### Morning (Build, ~4h)
- Download **Sysmon** from Microsoft and use the reputable **SwiftOnSecurity** config (link in README).
- Write `scripts/Install-Sysmon.ps1` to install/update Sysmon with hash validation on the config file and idempotent reconfigure.
- Enable **PowerShell logging** (module/script block) via Group Policy/local policy where appropriate.

### Midday (Learn/Labs, ~3h)
- Review Sysmon events: **1 Process Create**, **3 Network Connect**, **7 Image Loaded**, **10 Process Access**, **11 File Create**, **12/13 Registry**, **22 DNS**.
- Lab: generate benign events (open PowerShell, run a web request, create files) and view them in Event Viewer.

### Afternoon (Drill/Test, ~3h)
- Add **Get-SysmonHotspots**: query specific patterns (e.g., `-EncodedCommand`, suspicious parents like `winword.exe` → `powershell.exe`).
- Export hits to JSON and include example outputs under `/examples`.

### Evening (Document/Share, ~2h)
- README section: "Which Sysmon events do we care about and why" with examples per event ID.
- Record a GIF of installing/updating Sysmon and viewing events.

### Why?
Sysmon enriches native logs with **high‑fidelity telemetry** essential for detection engineering.

### Real‑world mapping
- Threat hunting and IR triage with consistent event schemas.
- Purple‑team: verifying detections for common TTPs (living off the land).

### Acceptance criteria
- Sysmon installed and producing events; config under version control (reference to upstream, not vendored binaries).
- `Get-SysmonHotspots` returns data and exits non‑zero on hits (for CI gating).

---

# Day 4 — **Log Collection: Winlogbeat or WEF; Query Packs**

### Morning (Build, ~4h)
- Option A: configure **Winlogbeat** to ship Security + Sysmon + PowerShell logs to Elastic (or OpenSearch).
- Option B: configure **Windows Event Forwarding** to a collector (lab) and ingest centrally.
- Create a `QueryPacks` folder with reusable **Get-WinEvent** filters for: 4624/4625/4672/4688/4720/4728/4732/4756/1102 and Sysmon 1/3/22.

### Midday (Learn/Labs, ~3h)
- Read channel names and provider GUIDs; test subscriptions with small time windows to avoid overload.
- Ensure clocks are synced (NTP), otherwise timelines break.

### Afternoon (Drill/Test, ~3h)
- Generate benign auth failures and process starts; confirm they appear in SIEM within acceptable latency.
- Export a **daily digest** (CSV/HTML) using your module functions and attach to README.

### Evening (Document/Share, ~2h)
- Document Beats/WEF setup with screenshots (sanitized) and common pitfalls (permissions, quotas).
- Add a troubleshooting guide for dropped events.

### Why?
Logs must **leave the box**. Tamper‑resistant centralized logs are essential for forensics and compliance.

### Real‑world mapping
- SOX/PCI/SOC2 evidence, IR timelines, MDR integrations.

### Acceptance criteria
- Events visible centrally; a dashboard or saved search screenshot included.
- Daily digest script runs and creates an artifact in `/examples`.

---

# Day 5 — **Secure Remoting, JEA, Script Signing, and Secrets**

### Morning (Build, ~4h)
- Enable **WinRM over HTTPS** (create self‑signed cert in lab), restrict to specific subnets, and set `TrustedHosts` appropriately for the lab.
- Set execution policy to **AllSigned** (for prod) or **RemoteSigned** (for lab); create a code‑signing cert and **sign your module** with `Set-AuthenticodeSignature`.
- Install **SecretManagement** + **SecretStore** (or Credential Manager backend) and refactor scripts to not embed secrets.

### Midday (Learn/Labs, ~3h)
- Build **JEA Role Capability** (OperatorTasks.psrc) exposing only: `Get-AuthFailures`, `Get-LocalAdminsDiff`, `Get-ProcessNetAnomalies`.
- Create **Session Configuration** (OperatorEndpoint.pssc) and **Register-PSSessionConfiguration**; test with a limited user.

### Afternoon (Drill/Test, ~3h)
- From another host, `Enter-PSSession -ConfigurationName OperatorEndpoint` and verify you cannot run disallowed cmdlets.
- Attempt to modify a protected setting; confirm access is denied and audit logs record it.

### Evening (Document/Share, ~2h)
- Write a **security note** explaining why JEA and signing matter; include sample transcript with signed script validation.
- Add rollback instructions and safety notes for WinRM/HTTPS and execution policy.

### Why?
Least‑privilege operational access and integrity controls reduce blast radius and prevent script tampering.

### Real‑world mapping
- Helpdesk/operator access without domain admin rights.
- Enforceable change control through signed tooling.

### Acceptance criteria
- JEA endpoint usable by a limited user; only approved commands allowed.
- Module or scripts show **Valid** signature; secrets are retrieved via a vault, not in plaintext.

---

# Day 6 — **Scheduled Tasks, Packaging, and CI/CD**

### Morning (Build, ~4h)
- Create a **Scheduled Task** running `Company.SecOps\Get-AuthFailures` and `Get-LocalAdminsDiff` daily, writing to `C:\ProgramData\SecOps\reports`.
- Ensure the task runs under a **least‑privileged service account** with `Log on as a batch job` right.

### Midday (Learn/Labs, ~3h)
- Study **Task Scheduler** security contexts, triggers, and history; handle path quoting and network shares safely.
- Version your module (SemVer) and update the manifest; add `CmdletsToExport` explicitly.

### Afternoon (Drill/Test, ~3h)
- Build a **GitHub Actions** workflow (`windows-latest`) to run Pester + Analyzer; on tags, package the module (`.zip`) and **upload release assets**.
- Add badges (build passing) and a changelog.

### Evening (Document/Share, ~2h)
- Create an **Operations Runbook**: how to import the module, register JEA, deploy Sysmon, and set up logging on a new host.
- Record a short demo of the scheduled task creating the report.

### Why?
Operationalizing the toolkit proves you can deliver **secure automation** that runs reliably and produces evidence.

### Real‑world mapping
- SRE/SecOps: scheduled reports and continuous compliance checks.
- AppSec: CI gates and artifact signing for release integrity.

### Acceptance criteria
- Scheduled task outputs artifacts on schedule; history shows success.
- Release pipeline zips the module and attaches to a GitHub Release on tag.

---

# Day 7 — **Mini‑Project & Release: Windows SecOps Starter Kit**

### Morning (Build, ~4h)
- Polish: add `Get-Help` examples, parameter validation attributes (`ValidateSet`, `ValidateRange`), and `SupportsShouldProcess` where destructive.
- Bundle: module + JEA configs + sample Sysmon config link + Winlogbeat example + runbooks.

### Midday (Learn/Labs, ~3h)
- Run a **clean install** on a fresh Windows VM: import module, enable WinRM HTTPS, register JEA, install Sysmon, start log shipping.
- Verify detections: produce a benign `-EncodedCommand` and observe Sysmon/PowerShell logs flowing to SIEM.

### Afternoon (Drill/Test, ~3h)
- Generate a weekly **security digest** (HTML/CSV) and save under `/examples`.
- Execute `Get-LocalAdminsDiff` across two snapshots showing an add/remove.

### Evening (Document/Share, ~2h)
- Tag **v0.3.0** release with artifacts and screenshots; publish a 1–2 page narrative: "Rolling out Windows SecOps Starter Kit".
- Open `good first issue` tickets and a roadmap for Week 4+ integrations.

### Acceptance criteria
- End‑to‑end lab demo works from clean VM.
- Public release with CI badge, artifacts, and clear instructions.


---

## How this week advances your cybersecurity path
- **DFIR**: High‑value telemetry (Sysmon+Security) and query packs accelerate incident timelines.
- **Blue team**: JEA and scheduled reporting build sustainable operations.
- **AppSec/Platform**: Analyzer+Pester+CI means your automation is safe to trust and easy to integrate.
- **Purple‑team**: You can emulate benign TTPs and measure detections end‑to‑end.


---

## References / Study Hubs
- [PowerShell Docs – Advanced Functions](https://learn.microsoft.com/powershell/scripting/developer/cmdlet/advanced-functions)
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer)
- [Pester](https://pester.dev/docs/quick-start)
- [JEA (Just Enough Administration)](https://learn.microsoft.com/powershell/scripting/security/remoting/jea/overview)
- [WinRM over HTTPS](https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
- [Script Signing](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_Signing)
- [Windows Security Auditing – Event IDs](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-auditing)
- [Sysmon (Microsoft)](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Winlogbeat](https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-overview.html)
- [Windows Event Forwarding (WEF)](https://learn.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- [SecretManagement](https://learn.microsoft.com/powershell/utility-modules/secretmanagement/overview)

## Similar GitHub repos / inspiration
- [PowerShell/PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer)
- [pester/Pester](https://github.com/pester/Pester)
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- [elastic/beats (Winlogbeat)](https://github.com/elastic/beats)
- [PowerShell/Win32-OpenSSH (reference)](https://github.com/PowerShell/Win32-OpenSSH)
- [redcanaryco/atomic-red-team (for test ideas; review carefully and run safely in lab)](https://github.com/redcanaryco/atomic-red-team)

## Rubric (Week 3)
- **Code quality**: Analyzer clean; advanced functions; comment‑based help; pipeline‑friendly object output.
- **Tests**: ≥12 Pester tests with meaningful `Mock` usage; CI required for PR merge.
- **Security**: JEA endpoint works; WinRM HTTPS; signed scripts; secrets via vault backend.
- **Telemetry**: Sysmon installed and tuned; logs shipping centrally; daily digest generated.
- **Release**: v0.3.0 tag with module zip and documentation.

