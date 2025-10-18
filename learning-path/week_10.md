# Week 10 — **Nmap/NSE Mastery**: Recon → Fingerprinting → Scripted Findings (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Master **network discovery** and **service fingerprinting** with Nmap, then write **custom NSE scripts** to turn raw surfaces into high‑signal findings. You’ll build repeatable scan profiles, handle IPv4/IPv6, TCP/UDP nuances, evasions (lab‑only), and produce evidence‑grade outputs (XML/GNMAP/JSON) with parsers and dashboards. Maps to **OWASP A05 Misconfiguration**, **A09 Logging/Monitoring**, and the recon phase for all API/Web/DFIR work.

> **Ethics & Safety:** Only scan lab targets you own/control or have explicit written authorization. Be gentle: start with `-T2`, avoid intrusive NSE categories outside isolated labs.

---

## Outcomes
- Design **scan profiles** (fast sweep, thorough TCP, selected UDP, verification) with consistent file outputs (`-oA`).
- Fingerprint services with **version detection** (`-sV`, `--version-intensity`) and **scripted probes** (`-sC`, `--script`).
- Execute **UDP** & **IPv6** scans reliably; understand when **host discovery** lies and how to handle `-Pn`.
- Use **NSE** safely: default/safe/vuln categories; write **custom Lua NSE** for HTTP and banner‑driven detections.
- Generate **machine‑readable** artifacts (XML/GNMAP/JSONL) and convert to dashboards/reports integrated with Week 1/5/8 pipelines.
- Publish `week10-nmap-nse-lab` with profiles, scripts, parsers, sample reports, and a mini‑write‑up.

## Repository layout (this week)

```
/week10-nmap-nse-lab
  ├─ profiles/                     # reusable scan profiles
  │  ├─ fast-sweep.md
  │  ├─ thorough-tcp.md
  │  ├─ udp-selective.md
  │  └─ verify-focused.md
  ├─ scripts/                      # your custom NSE scripts
  │  ├─ http-csp-check.nse
  │  ├─ http-json-banner.nse
  │  └─ tls-expiry-lite.nse
  ├─ parsers/
  │  ├─ xml_to_md.py               # XML → Markdown tables
  │  ├─ xml_to_jsonl.py            # XML → JSON Lines
  │  └─ gnmap_merge.sh
  ├─ docs/
  │  ├─ nmap-cheatsheet.md
  │  ├─ udp-notes.md
  │  ├─ evasion-lab-only.md
  │  ├─ nse-dev-notes.md
  │  └─ report-week10.md
  ├─ dashboards/
  │  └─ nmap-panels.json
  ├─ wordlists/
  │  ├─ top1k-tcp.txt
  │  └─ udp-interesting.txt
  └─ README.md
```

---

# Day 1 — **Scan Profiles & Host Discovery**

### Morning (Build, ~4h)
- Create **profiles/fast-sweep.md**: ICMP + ARP + top 100 TCP; safe timings.
- Create **profiles/thorough-tcp.md**: full TCP ports, service/version detection, default scripts; staged timing.
- Create **profiles/udp-selective.md**: focused UDP ports (53, 67/68, 123, 137, 161/162, 500, 1900, 5353, 11211) with retries.

```bash
# Fast sweep (IPv4)
nmap -sn -PE -PA80,443 -PR 10.0.0.0/24 -oA scans/fast_sweep_v4

# Fast sweep (IPv6) – neighbor discovery becomes key
nmap -6 -sn fe80::/64 -oA scans/fast_sweep_v6

# Thorough TCP (full port scan + version + default scripts)
nmap -sS -p- -T3 -Pn --min-rate 1000 -sV --version-intensity 7 -sC -O \
  -oA scans/thorough_tcp 10.0.0.5

# Selective UDP (slow/respectful)
nmap -sU -Pn --top-ports 50 --defeat-icmp-ratelimit --max-retries 2 --host-timeout 20m \
  -oA scans/udp_selective 10.0.0.5
```
### Midday (Learn/Labs, ~3h)
- Study **host discovery** methods: `-PE -PP -PR -PS -PA` and when to prefer `-Pn` (firewalled/production).
- Understand **timing** (`-T0..5`) and its tradeoffs; avoid `-T5` unless isolated lab and you know the target capacity.

### Afternoon (Drill/Test, ~3h)
- Run sweep on your lab subnet; compare `-sn` vs `-Pn` results; log false negatives/positives.
- Document into `docs/nmap-cheatsheet.md` your go‑to flags and when to use each.

### Evening (Document/Share, ~2h)
- Add a **runbook** section: cadence (fast sweep daily, thorough weekly), artifact locations (`-oA`).
- Screenshot of results summary and explain deltas between profiles.

### Acceptance criteria
- Profiles exist with commands + rationale; verified outputs stored under `scans/`.
- Cheatsheet documents discovery flags, timing, and when to `-Pn`.

---

# Day 2 — **Service Fingerprinting & Version Detection**

### Morning (Build, ~4h)
- Exercise **version detection**: vary `--version-intensity {0..9}` and observe accuracy/latency tradeoffs.
- Capture **TLS cert** metadata (`--script ssl-cert,ssl-enum-ciphers`) and **ALPN/HTTP2** hints on 443.

```bash
# Focused fingerprinting on a single host
nmap -sS -sV --version-intensity 9 -p 22,80,443,3306,5432 \
  --script banner,ssl-cert,ssl-enum-ciphers -oA scans/fingerprint 10.0.0.5
```
### Midday (Learn/Labs, ~3h)
- Read how Nmap **probes** work and why some daemons lie (proxies, WAFs).
- Learn **OS detection** basics (`-O`, `--osscan-guess`) and how to record **confidence** not certainty.

### Afternoon (Drill/Test, ~3h)
- Collect multiple runs with different intensities; store XML/GNMAP; practice **delta diffs** between runs.
- Add **verification profile** for follow‑up (`profiles/verify-focused.md`).

### Evening (Document/Share, ~2h)
- Note **false banner** examples and mitigations (speak protocol, not just TCP connect).
- Update cheatsheet with `--script` combos for TLS hygiene checks.

### Acceptance criteria
- Fingerprint report with version + TLS info saved; verification commands documented.
- Confidence scoring adopted (e.g., list `accuracy` from `-sV`).

---

# Day 3 — **UDP Realities & IPv6**

### Morning (Build, ~4h)
- Create `docs/udp-notes.md`: ICMP rate limiting, silent drops, service‑dependent retries; when to settle for banner checks.
- Build a **selective** UDP scan (`-sU`) with timeouts per port class; add SNMP v2/v3 checks (safe).

```bash
# SNMP safe probe
nmap -sU -p 161 --script snmp-info -oA scans/udp_snmp 10.0.0.5

# mDNS/SSDP (local nets)
nmap -sU -p 1900,5353 --script dns-service-discovery,ssdp-discovery -oA scans/udp_local 10.0.0.0/24
```
### Midday (Learn/Labs, ~3h)
- Review **IPv6 scanning** strategies; link‑local scope and router advertisements.
- Understand **defeat-icmp-ratelimit** and its practical limits.

### Afternoon (Drill/Test, ~3h)
- Run your UDP profile on 2–3 lab hosts; annotate **open|filtered** vs **closed** and why.
- Collect **pcap** during a UDP run to visualize retries and ICMP responses.

### Evening (Document/Share, ~2h)
- Add screenshots/graphs to `docs/udp-notes.md` and conclusions on where UDP matters (DNS, NTP, SNMP, QUIC).

### Acceptance criteria
- UDP profile yields useful, reproducible results with clear caveats.
- IPv6 notes include commands and observed differences from IPv4.

---

# Day 4 — **NSE Fundamentals + First Custom Script**

### Morning (Build, ~4h)
- Study **NSE categories** (`default`, `safe`, `auth`, `vuln`, `intrusive`, `discovery`). Choose **safe** for shared labs.
- Create your first **NSE**: `scripts/http-json-banner.nse` that fetches `/` (or `/health`) and extracts JSON fields like `service`, `version`.

```lua
-- scripts/http-json-banner.nse
description = [[Grabs a JSON banner and emits key details for dashboards.]]
categories = {"default", "safe"}
author = "You"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local json = require "json"
local shortport = require "shortport"

portrule = shortport.port_or_service({80, 443}, {"http","https"})

action = function(host, port)
  local path = nmap.registry.args["http-json-banner.path"] or "/"
  local r = http.get(host, port, path)
  if not r or not r.body then return nil end
  local ok, obj = pcall(json.parse, r.body)
  if not ok or type(obj) ~= "table" then return nil end
  local svc = obj.service or "unknown"
  local ver = obj.version or obj.build or "unknown"
  return ("json-banner: %s v%s on %s:%d"):format(svc, ver, host.ip, port.number)
end
```
### Midday (Learn/Labs, ~3h)
- Read **NSEDev** docs: I/O libraries (http, tls, smtp), `shortport` matchers, `nmap.registry.args` for user params.
- Plan **script arguments** for tuning (e.g., `--script-args http-json-banner.path=/status`).

### Afternoon (Drill/Test, ~3h)
- Run your script on a local HTTP service that returns JSON; store the normal output and XML.
- Integrate into your **verification** profile (`--script scripts/http-json-banner.nse`).

### Evening (Document/Share, ~2h)
- Write `docs/nse-dev-notes.md` explaining the modules you used and how to pass args.
- Commit sample outputs and a before/after scan diff showing your script’s added value.

### Acceptance criteria
- Custom NSE runs without errors; adds data not present in `-sV` alone.
- Script accepts `--script-args` and is included in a profile.

---

# Day 5 — **TLS Hygiene & CSP Checks via NSE**

### Morning (Build, ~4h)
- Author `scripts/tls-expiry-lite.nse`: get server cert and compute **days‑to‑expiry**; flag thresholds (<=30, <=7).
- Author `scripts/http-csp-check.nse`: fetch headers and parse **Content‑Security‑Policy**; warn if missing/weak.

```lua
-- scripts/tls-expiry-lite.nse
description = [[Reports TLS cert expiry window in days (lite).]]
categories = {"safe", "default"}
author = "You"

local sslcert = require "sslcert"
local shortport = require "shortport"

portrule = shortport.ssl

action = function(host, port)
  local status, cert = sslcert.getCertificate(host, port)
  if not status or not cert or not cert.cert or not cert.cert.valid_to then return nil end
  local now = stdnse.clock()
  local days = math.floor((cert.cert.valid_to - now) / 86400)
  local lvl = (days <= 7) and "CRIT" or ((days <= 30) and "WARN" or "OK")
  return ("tls-expiry: %s (%d days)"):format(lvl, days)
end
```
```lua
-- scripts/http-csp-check.nse
description = [[Checks presence/quality of Content-Security-Policy header.]]
categories = {"safe","default"}
author = "You"

local http = require "http"
local shortport = require "shortport"
local string = require "string"

portrule = shortport.port_or_service({80,443},{"http","https"})

action = function(host, port)
  local r = http.get(host, port, "/")
  if not r or not r.header then return nil end
  local csp = r.header["content-security-policy"] or r.header["Content-Security-Policy"]
  if not csp then return "csp: MISSING" end
  if string.find(csp, "'unsafe-inline'") or string.find(csp, "*") then
    return "csp: WEAK ("..csp..")"
  end
  return "csp: OK"
end
```
### Midday (Learn/Labs, ~3h)
- Compare your results with Nmap’s built‑in `ssl-cert` output; ensure you’re not duplicating heavy work.
- Decide **reporting format** (short lines for XML `script` outputs → easy to parse).

### Afternoon (Drill/Test, ~3h)
- Run your scripts against a few HTTPS endpoints (lab); capture XML; parse to Markdown/JSONL with your parsers.
- Add panels in `dashboards/nmap-panels.json` to visualize expiring certs and CSP status.

### Evening (Document/Share, ~2h)
- Explain **false positives** (CDN/front door policies) and tuning per path.
- Write remediation notes that link back to Week 4 (headers) and Week 6 (auth flows).

### Acceptance criteria
- Scripts return consistent outputs (OK/WARN/CRIT and MISSING/WEAK/OK).
- Dashboards show cert‑expiry and CSP coverage across hosts.

---

# Day 6 — **Evasion Techniques (Lab‑Only) & Validation**

### Morning (Build, ~4h)
- Create `docs/evasion-lab-only.md`: fragment packets (`-f`), randomize targets (`--randomize-hosts`), decoys (`-D RND:10`), data length padding (`--data-length`), and source port tricks (`-g`).
- Run **only** inside your isolated lab against your own hosts; compare deltas vs normal scans.

```bash
# Evasion playground (lab-only)
nmap -sS -p- -f --data-length 24 -D RND:5 --randomize-hosts -T2 -oA scans/evasion_lab 10.0.0.0/28
```
### Midday (Learn/Labs, ~3h)
- Review why evasions often yield **worse** fingerprinting and more false negatives; IDS may still flag.
- Plan **validation**: re‑run verification profile to confirm findings are real.

### Afternoon (Drill/Test, ~3h)
- Run evasion scan and the **verify‑focused** profile; reconcile differences in `report-week10.md`.
- Note any **service flapping** (e.g., rate limiting causing timeouts).

### Evening (Document/Share, ~2h)
- Add a clear **policy**: evasions only in approved labs; always follow with verification.
- Summarize tooling limits and legal bounds.

### Acceptance criteria
- Evasion write‑up produced; verification reconciles key deltas; no evasions used on non‑lab targets.
- Cheatsheet updated with a **Do/Don’t** table.

---

# Day 7 — **Mini‑Project & Release: Nmap+NSE Pack**

### Morning (Build, ~4h)
- Run full **thorough‑tcp**, **udp‑selective**, and **verify‑focused** profiles on your lab; produce `-oA` artifacts.
- Use `parsers/xml_to_jsonl.py` to create JSONL and load into your dashboard for coverage/expiry/CSP panels.

```python
# parsers/xml_to_jsonl.py (sketch)
import sys, json
import xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1]); root = tree.getroot()
for host in root.findall('host'):
    addr = host.find('address').get('addr')
    for port in host.findall('.//port'):
        state = port.find('state').get('state')
        svc   = port.find('service')
        name  = svc.get('name') if svc is not None else None
        product = svc.get('product') if svc is not None else None
        version = svc.get('version') if svc is not None else None
        scripts = [s.get('id')+': '+(s.findtext('output') or '') for s in port.findall('script')]
        print(json.dumps({"host": addr, "port": port.get('portid'), "proto": port.get('protocol'),
                          "state": state, "service": name, "product": product, "version": version,
                          "scripts": scripts}))
```
### Midday (Learn/Labs, ~3h)
- Cross‑reference findings with Week 4 headers, Week 6 auth, Week 7 DB ports; open issues to **harden** or **close** unexpected services.
- Optionally run `--script vuln` on a separate **vulnerable** container (e.g., DVWA) to practice report writing (lab only).

### Afternoon (Drill/Test, ~3h)
- Produce **report-week10.md** with tables: open ports by host, expiring certs, CSP status, and notable banners.
- Tag **v1.0.0** of the Nmap+NSE pack; attach XML, GNMAP, JSONL, dashboards, and screenshots.

### Evening (Document/Share, ~2h)
- Add a **how‑to** for integrating these scans into CI/CD or nightly jobs (safe profiles only).
- Write next‑steps issues: add Vulners/CVE enrichment, SNMP audit pack, and IPv6 expansion.

### Acceptance criteria
- Release contains scan artifacts, custom NSE scripts, parsers, dashboards, and a well‑reasoned report.
- Cheatsheet + profiles provide a repeatable, respectful scanning methodology.


---

## How this week advances your cybersecurity path
- **Recon to Action**: You move from blind port lists to **fingerprinted, contextual** findings that map to concrete hardening tasks.
- **Automation**: Profiles and parsers make scans repeatable and consumable by teams (dashboards/evidence).
- **Researcher skills**: Writing NSE increases your leverage—custom checks for your exact stack.


---

## References / Study Hubs
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [NSE Documentation](https://nmap.org/book/nse.html) & [NSEDoc libs](https://nmap.org/nsedoc/)
- [Nmap Book (Official)](https://nmap.org/book/)
- [Nmap Timing & Performance](https://nmap.org/book/performance.html)
- [Nmap IPv6](https://nmap.org/book/port-scanning-ipv6.html)
- [Nmap UDP Scans](https://nmap.org/book/scan-methods-udp-scan.html)

## Similar GitHub repos / inspiration
- [nmap/nmap](https://github.com/nmap/nmap)
- [trickest/nmap-vulners](https://github.com/trickest/nmap-vulners) (CVE enrichment)
- [offensive-security/exploitdb](https://github.com/offensive-security/exploitdb) (map versions → exploits; research use only)

## Rubric (Week 10)
- **Profiles**: fast/thorough/udp/verify documented and reproducible; artifacts saved with `-oA`.
- **Fingerprinting**: version/TLS data collected; confidence noted; deltas analyzed.
- **NSE**: ≥2 custom scripts working with args; included in verification profile; outputs parse cleanly.
- **Artifacts**: XML/GNMAP/JSONL + dashboards; report with prioritized hardening actions; v1.0.0 release.
- **Safety**: evasion used only in lab; verification reconciles differences; ethical guidelines respected.

