# Week 01 – Lab & Monitoring Baseline + Nmap

_Generated: October 18, 2025_

## Outcomes
- Reproducible, dockerized cyber lab that you can demo.
- Initial dashboards and alert to prove value on day 1.
- Nmap fundamentals with automation + CI artifact.
- Threat model seeded and linked to issues.

## Build list
- Spin up a **Dockerized home lab**: reverse proxy + vulnerable targets (DVWA, deliberately vulnerable API), Postgres, Keycloak, Zeek sensor, Loki stack.
- Create a **GitHub monorepo** (`cyber-lab`) with subfolders: `/infra`, `/apps`, `/dfir`, `/dashboards`, `/notes`. Use Issues + Projects board.
- Establish **monitoring baseline**: system metrics, container logs, basic auth logs; wire **Promtail/Winlogbeat** to a local Loki/Elastic.
- Master **Nmap fundamentals**: host discovery, service/version detection, safe scripting (`-sC -sV`).

### Day 1: Kickoff + Lab Skeleton & Dashboards (Day‑1 value)
#### Morning (Build, ~4h)
- Install Docker & Compose; create `docker-compose.yml` with services: `reverse-proxy (Caddy)`, `dvwa`, `vulnapi` (e.g., json-server), `postgres`, `keycloak`, `loki`, `promtail`, `zeek` (on a span port or host net).
- Initialize GitHub monorepo with MIT LICENSE, `README.md`, and `/infra` folder.
- Pin versions (immutable tags); add `.env.example` for secrets.

#### Midday (Learn/Read + Labs, ~3h)
- Add **Promtail** config to ship container logs to **Loki**; start Grafana and import a basic logs dashboard.
- Document network layout with **Mermaid** diagram in README (services, ports, trust zones).

#### Afternoon (Drill/Fuzz/Test, ~3h)
- Run `docker compose up -d`; verify health endpoints; confirm logs visible in Grafana Explore.
- Create initial **Nmap sweep** of your lab network: `nmap -sn 172.18.0.0/16` then `nmap -sC -sV -O -T3 <targets>`.

#### Evening (Document & Share, ~2h)
- Commit infra files; open GitHub Issue: “Baseline Lab & Dashboards” with screenshots and checklists.
- Write a short post-mortem: risks, assumptions, next steps.

#### Why are we doing this?
You need a reproducible lab and visible telemetry **from day one**. Dashboards prove value early; Nmap maps attack surface so every future task is anchored to observable change.

#### Real‑world mapping
- Infra/SecOps: dockerizing services; version pinning; .env handling (12-factor).
- Blue team: central log collection and first dashboards.
- Red team/appsec: identifying exposed services rapidly with Nmap.

#### Acceptance criteria / Demo
- Grafana shows logs for at least 3 services; screenshots committed.
- `nmap` HTML/XML report committed under `/notes/week01/day1/`.
- `docker compose ps` all healthy; README has Mermaid diagram.

#### Notes & Extras
- Keep all commands you run in `/notes/week01/commands.md` for repeatability.


---

### Day 2: Service Fingerprints & Safe Scans
#### Morning (Build, ~4h)
- Enumerate banners: `nmap -sV --version-all -oA scans/day2 <targets>`; store XML for future parsing.
- Run default scripts: `nmap -sC -oN scans/day2_default.nmap <targets>`.

#### Midday (Learn/Read + Labs, ~3h)
- Read **Nmap Reference** sections on timing, host discovery, version detection.
- Practice on a public "test target" in your own lab (never random IPs).

#### Afternoon (Drill/Fuzz/Test, ~3h)
- Compare results with container images’ official ports/docs; validate false positives.
- Add a Makefile target `make scan` for standard scan profiles.

#### Evening (Document & Share, ~2h)
- Update dashboard panels: top talkers, error rates, service counts from scan outputs (manually summarized).
- Write notes: how fingerprint changes when you toggle TLS, headers, banners.

#### Why are we doing this?
Fingerprinting is the backbone of recon and change detection. Safe defaults build muscle memory before aggressive scans.

#### Real‑world mapping
- Pentest scoping: safe vs intrusive flags.
- Change monitoring: detect drift in prod-like environments.

#### Acceptance criteria / Demo
- `scans/` folder with XML + grepable outputs; Makefile committed.
- Dashboard panel showing service inventory snapshot (manual).


---

### Day 3: Dashboards that matter
#### Morning (Build, ~4h)
- Create Grafana panels: HTTP status histogram, container restarts over time, failed logins from Keycloak (if configured).
- Set alert rule: excessive 5xx or container restart storm.

#### Midday (Learn/Read + Labs, ~3h)
- Read Loki & Promtail docs; extract JSON logs, parse labels.
- Add Winlogbeat on a Windows VM and forward to local Elastic (or to Loki via Logstash if you prefer).

#### Afternoon (Drill/Fuzz/Test, ~3h)
- Generate events intentionally (failed logins, 404s) and verify alerts fire.
- Capture PCAP during tests for later DFIR (Zeek will parse).

#### Evening (Document & Share, ~2h)
- Publish screenshots + `dashboards/` JSON exports; document how to reproduce.
- Open a GitHub discussion: feedback you’d want from reviewers.

#### Why are we doing this?
Security monitoring adds immediate visibility and forces you to think in signals and detections.

#### Real‑world mapping
- SRE/SecOps dashboards; early detection of auth abuse or failing services.

#### Acceptance criteria / Demo
- At least 3 Grafana panels functional; one alert fires under load.
- PCAP saved and referenced for Week 13 DFIR.


---

### Day 4: Nmap Output Automation
#### Morning (Build, ~4h)
- Parse XML to Markdown with a small Python script; summarize open ports per host.
- Create a CI job (GitHub Actions) that runs `make scan` against lab and publishes artifact.

#### Midday (Learn/Read + Labs, ~3h)
- Read NSE basics; list scripts relevant to HTTP and SSL/TLS.
- Try `--script=http-title,ssl-cert` on lab services.

#### Afternoon (Drill/Fuzz/Test, ~3h)
- Experiment with safe NSE scripts; document any instability.
- Compare results vs Grafana logs for correlation.

#### Evening (Document & Share, ~2h)
- Commit Python parser under `/tools/nmap_xml_to_md.py` with README.
- Record a short demo GIF showing the CI artifact.

#### Why are we doing this?
You’ll reuse scan automation everywhere: baselining, change detection, pipeline gates.

#### Real‑world mapping
- CI pipelines that fail a build when unexpected ports open.

#### Acceptance criteria / Demo
- CI run visible in Actions; artifact attached with latest scan markdown.
- Script handles at least 2 hosts and outputs a neat table.


---

### Day 5: Threat Model the Lab
#### Morning (Build, ~4h)
- Draw a dataflow diagram (Mermaid) labeling trust boundaries (browser ↔ proxy ↔ apps ↔ DB ↔ IdP).
- Identify assets, actors, entry points; map to **OWASP Top 10** categories.

#### Midday (Learn/Read + Labs, ~3h)
- Read OWASP Top 10 intros (A01–A10).
- Review PortSwigger Academy structure; enroll and bookmark.

#### Afternoon (Drill/Fuzz/Test, ~3h)
- List concrete abuse stories per component (e.g., SSRF via proxy, weak session settings, DB RLS gaps).
- Create issues in GitHub tagged `threat-model`.

#### Evening (Document & Share, ~2h)
- Publish `/notes/week01/threat-model.md` linking issues to components.
- Plan which threats map to upcoming weeks.

#### Why are we doing this?
Design-level thinking prevents band-aids later. You’ll tie tasks to concrete risks.

#### Real‑world mapping
- AppSec program kickoff; backlog seeding for sprints.

#### Acceptance criteria / Demo
- Threat model file + at least 10 actionable issues mapped to Top 10.


---

### Day 6: Hardening Pass 0
#### Morning (Build, ~4h)
- Enable basic headers on reverse proxy: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
- Set strict container resource limits and read-only filesystems where possible.

#### Midday (Learn/Read + Labs, ~3h)
- Read MDN HSTS/CSP; plan CSP for later when app routes are known.
- Document tradeoffs (cookies vs JWT) for later auth weeks.

#### Afternoon (Drill/Fuzz/Test, ~3h)
- Re-run Nmap; compare diffs vs earlier scans; explain any changed banners/ports.
- Update dashboards to include reverse proxy metrics.

#### Evening (Document & Share, ~2h)
- Commit proxy config; open PR with before/after screenshots.
- Write a decision record (ADR-0001) about reverse proxy choices.

#### Why are we doing this?
Early hardening reduces noisy findings and focuses your future testing on meaningful issues.

#### Real‑world mapping
- Security headers and infra baselines that auditors will ask for.

#### Acceptance criteria / Demo
- Headers visible in HTTP responses; diffs captured; ADR merged.


---

### Day 7: Weekly Wrap & Mini‑Project Deploy
#### Morning (Build, ~4h)
- **Mini‑project:** "Lab in a Box" – one-command bring-up with `docker compose`, default dashboards, and a README walkthrough.

#### Midday (Learn/Read + Labs, ~3h)
- Create a release tag `v0.1.0` and a short video walkthrough; publish to GitHub Releases.

#### Afternoon (Drill/Fuzz/Test, ~3h)
- Open ‘good first issues’ for community; write contribution guide.
- Timebox 1–2 PortSwigger Academy labs to keep momentum.

#### Evening (Document & Share, ~2h)
- Reflect: What did you observe? What surprised you? What will you change next week?
- Write a weekly changelog in `/notes/week01/changelog.md`.

#### Why are we doing this?
Shipping small but complete artifacts builds reputation and a public portfolio.

#### Real‑world mapping
- Internal platforms/docs; reproducible labs for red/blue/purple teams.

#### Acceptance criteria / Demo
- Release `v0.1.0` with assets (dashboards JSON, screenshots, demo).
- Two Academy labs solved and documented.


---

## References & Docs
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [NSE Dev Guide](https://nmap.org/book/nse.html)
- [Grafana docs](https://grafana.com/docs/grafana/latest/)
- [Grafana Loki](https://grafana.com/docs/loki/latest/)
- [Promtail](https://grafana.com/docs/loki/latest/clients/promtail/)
- [Winlogbeat docs](https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-overview.html)
- [Sigma HQ rules](https://github.com/SigmaHQ/sigma)
- [Wazuh docs](https://documentation.wazuh.com/current/index.html)
- [Zeek docs](https://docs.zeek.org/en/current/)
- [Suricata User Guide](https://docs.suricata.io/)
- [Kali Docs](https://www.kali.org/docs/)
- [Kali Training (Kali Revealed)](https://www.kali.org/docs/general-use/kali-training/)
- [Kali Tools portal](https://www.kali.org/tools/all-tools/)
- [Docker Compose reference](https://docs.docker.com/compose/)
- [Mermaid diagrams in GitHub](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-diagrams)

## Starter GitHub Repos
- [docker/compose (reference)](https://github.com/docker/compose)
- [telekom-security/tpotce (for future week, preview)](https://github.com/telekom-security/tpotce)

