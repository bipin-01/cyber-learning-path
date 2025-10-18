# Week 02 – **Bash Mastery + Linux Administration** (In‑Depth)

_Generated: October 18, 2025_

> **Theme:** Become dangerous with Bash and foundational Linux admin. Ship real, security‑relevant automation while hardening a fresh Linux server (users, groups, sudo, SSH, firewall). Everything ties to OWASP A05 (Misconfiguration) and A09 (Logging/Monitoring), and prepares you for API/DFIR work.

---

## Outcomes
- Write robust Bash scripts using strict mode, safe quoting, functions, `getopts`, arrays, traps, and parallelism.
- Harden a Linux server: users/groups, sudoers (least privilege), SSH hardening, firewall rules, audit basics.
- Automate daily security tasks: log slicing, anomaly summaries, permission audits, service health checks.
- Package scripts with **ShellCheck/shfmt** lint + **Bats** tests + Makefile targets + GitHub Actions CI.
- Publish a **Week 02 mini‑project**: `week02-bash-admin-toolkit` with README, examples, and demo GIFs.

## Repository layout (this week)

```
/week02-bash-admin-toolkit
  ├─ bin/                         # executable scripts (symlink-friendly)
  ├─ lib/                         # shared helpers (sourced)
  ├─ tests/                       # bats tests
  ├─ examples/                    # sample logs/configs for demos
  ├─ Makefile
  ├─ .shellcheckrc
  ├─ .editorconfig
  ├─ .github/workflows/ci.yml
  └─ README.md
```

---

# Day 1 — **Strict‑mode Bash & Project Skeleton**

### Morning (Build, ~4h)
- Create repo `week02-bash-admin-toolkit` and scaffold folders above.
- Add **strict mode** headers to a starter script `bin/say_hello.sh`:

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

cleanup() { :; }          # customize if you create temp files
trap cleanup EXIT

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

main() {
  [[ $# -ge 1 ]] || die "usage: $0 NAME"
  printf 'hello, %s\n' "$1"
}

main "$@"
```
- Write a **library** file `lib/log.sh` with JSON‑line logging helpers: `log_info`, `log_warn`, `log_err` (use `date -Is`).
- Initialize **Makefile** with targets: `make lint` (ShellCheck), `make fmt` (shfmt), `make test` (Bats), `make all`.
- Add `.shellcheckrc` with common suppressions you agree on (e.g., SC1090 for deliberate dynamic source with validation).

### Midday (Learn/Labs, ~3h)
- Read: **ShellCheck** rationale for common errors (SC2086, SC2046, SC2001, SC2155).
- Practice: convert 3 unsafe one‑liners into safe, quoted functions.
- Add a helper `lib/args.sh` that uses `getopts` to parse `-v/--verbose` and `-o/--output` in a safe pattern.

### Afternoon (Drill/Test, ~3h)
- Write **Bats tests** for `say_hello.sh` and `args.sh` to verify quoting and option handling.
- Create **CI** workflow `.github/workflows/ci.yml` to run `make lint test`.
- Add `bin/health.sh` that returns non‑zero exit on failure (used later by monitoring).

### Evening (Document/Share, ~2h)
- Write README: what strict mode prevents, why JSON‑lines logs matter (SIEM friendly).
- Record a short GIF of CI passing using terminal recording (asciinema or peek).

### Why are we doing this?
Strict‑mode + lint/tests is what separates **one‑off scripts** from **production automation**. JSON‑lines logs make every script SIEM‑ready and debuggable.

### Real‑world mapping
- Platform/SecOps: every task runner, cron job, and migration script benefits from strict mode, logging, and tests.
- Compliance & forensics: JSON‑line logs become evidence you can search and correlate.

### Acceptance criteria
- `make lint` and `make test` pass in CI.
- README explains strict mode and includes a log snippet sample.

---

# Day 2 — **Users/Groups, Sudoers, Permissions & ACLs**

### Morning (Build, ~4h)
- Spin up a fresh Ubuntu VM/Container (lab). Create groups: `dev`, `secops`. Create users: `alice` (dev), `bob` (secops).
- Add `bob` to passwordless sudo for **specific** commands only (least privilege):

```bash
# /etc/sudoers.d/secops-bob (edit with visudo)
Cmnd_Alias SECOPS_CMDS = /usr/bin/journalctl, /usr/bin/systemctl status *, /usr/sbin/ss, /usr/bin/du
bob ALL=(root) NOPASSWD: SECOPS_CMDS
```
- Disable root SSH login and password auth in `/etc/ssh/sshd_config`; allow only keys and specific users.

```bash
# /etc/ssh/sshd_config (snippet)
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
AllowUsers alice bob
MaxAuthTries 3
LoginGraceTime 20
```
- Restart sshd, verify with a second session before closing the original.
- Create a **permission audit** script `bin/perm_audit.sh`: list world‑writable files, SUID/SGID binaries, and home dir perms anomalies.

### Midday (Learn/Labs, ~3h)
- Read: Linux DAC vs ACL; `chmod`/`umask`; sticky bit semantics.
- Lab: set ACL on a shared folder so `dev` can read/write but others cannot (`setfacl/getfacl`).

### Afternoon (Drill/Test, ~3h)
- Run `perm_audit.sh` and capture findings as JSON; push to `examples/perm_audit.jsonl`.
- Write Bats tests with fixture directories to validate audit logic on edge cases.

### Evening (Document/Share, ~2h)
- Document your **least‑privilege** sudoers approach and why blanket `sudo` is dangerous.
- Include a hardening checklist for SSH and accounts in README.

### Why are we doing this?
Account hygiene and SSH hardening stop common breaches. Sudoers **by command** enforces **principle of least privilege** and yields great audit trails.

### Real‑world mapping
- Blue team: reduce lateral movement paths, improve identity posture.
- Pentest prep: many findings begin with weak SSH/permissions.

### Acceptance criteria
- SSH keys only; `PermitRootLogin no`; `PasswordAuthentication no`.
- `perm_audit.sh` outputs JSON‑lines and passes Bats tests.

---

# Day 3 — **Processes, Services (systemd), Logs (journald)**

### Morning (Build, ~4h)
- Write `bin/proc_watch.sh`: list suspicious parent→child relationships (e.g., `bash` spawning `nc`), processes running from world‑writable dirs, or from `/tmp`.
- Create `bin/svc_status.sh`: enumerate `systemctl` services, highlight failed or restarted units (>3 restarts in 10m).

### Midday (Learn/Labs, ~3h)
- Read: `systemd` unit types; `Restart=` policies; `journald` query language.
- Lab: build a simple systemd service that tails a file and fails occasionally to test restarts.

### Afternoon (Drill/Test, ~3h)
- Generate benign suspicious activity (test script in `/tmp` making a web request); ensure `proc_watch.sh` flags it.
- Query logs with `journalctl -u <your-service> --since "1 hour ago"` and export to JSON for later DFIR.

### Evening (Document/Share, ~2h)
- Add Bats tests with mock `ps` output (use fixtures).
- README: playbook – "If `proc_watch` flags a process, what next?"

### Why?
Process/service awareness underpins **incident triage**. Detecting odd parents and temp‑exec is a classic malware signal.

### Real‑world mapping
- SOC triage, IR: identify living‑off‑the‑land abuse (e.g., `curl|bash`).
- SRE: find flapping services before they cascade.

### Acceptance criteria
- Scripts exit non‑zero on findings; structured JSON output.
- At least one **systemd** unit and journald export included in `/examples`.

---

# Day 4 — **Networking, Firewall, Basic Recon**

### Morning (Build, ~4h)
- Write `bin/net_listeners.sh`: list listening sockets (TCP/UDP), owning users, and resolve common services.
- Write `bin/fw_lockdown.sh`: configure UFW (or `nftables`) to allow SSH from your IP, deny inbound by default, allow app ports explicitly.

### Midday (Learn/Labs, ~3h)
- Read: `ss`, `ip`, `ip route`, `nft`, `ufw` fundamentals.
- Lab: open a new service port, verify block/allow behavior end‑to‑end.

### Afternoon (Drill/Test, ~3h)
- Run **Nmap** against your host before and after firewall changes; commit diffs.
- Parse Nmap XML into Markdown table using your Week‑1 parser; link into README.

### Evening (Document/Share, ~2h)
- Document your default‑deny policy; add rollback steps.
- Add a Makefile target `make lockdown` to run fw script safely with prompts.

### Why?
**Default‑deny** and explicit allowlists are critical for attack surface reduction and SSRF containment later.

### Real‑world mapping
- Cloud hardening (NSGs/SecGroups); egress restriction for app nodes.

### Acceptance criteria
- Nmap shows only intended ports open.
- Firewall script is idempotent; re‑running doesn’t duplicate rules.

---

# Day 5 — **Log Slicing & Security Summaries (grep/sed/awk/jq)**

### Morning (Build, ~4h)
- Create `bin/log_slice.sh`: from stdin or file glob, emit JSON‑lines for 4xx/5xx with IP, route, UA, ts. Use `awk` + `jq`.
- Create `bin/auth_fail_summary.sh`: summarize top failed SSH sources (from `/var/log/auth.log`).

### Midday (Learn/Labs, ~3h)
- Read: regex vs ERE; `awk` fields; `jq` selectors; handling multiline logs safely.
- Lab: generate sample logs (curl bursts, bad creds); test scripts on them.

### Afternoon (Drill/Test, ~3h)
- Pipe outputs to **Grafana Loki** or to CSV for a quick dashboard import.
- Write Bats tests with fixture logs covering edge cases (weird UAs, IPv6).

### Evening (Document/Share, ~2h)
- README: add examples & pipelines (`journalctl … | log_slice.sh | tee errors.jsonl`).
- Commit fixtures under `/examples/logs/` with license/README.

### Why?
Being able to **turn messy logs into signals** is a core blue‑team skill and accelerates IR and monitoring work.

### Real‑world mapping
- Build SIEM queries and quick triage pipelines when dashboards are missing.

### Acceptance criteria
- Two slicers produce JSON‑lines; tests cover at least 6 cases.
- Dashboard screenshot showing your data visualized.

---

# Day 6 — **Automation: Cron, systemd Timers, Packaging & CI**

### Morning (Build, ~4h)
- Create **systemd timer** units to run `auth_fail_summary.sh` hourly and `perm_audit.sh` daily. Store outputs under `/var/log/sec/`.
- Write `bin/pkg_bundle.sh` to tar up artifacts with SHA256 manifest.

### Midday (Learn/Labs, ~3h)
- Read: systemd timer `OnCalendar=` syntax; cron pitfalls (env, PATH, shells).
- Lab: simulate failures; ensure timers log to journald and your JSON files.

### Afternoon (Drill/Test, ~3h)
- Add **pre‑commit** hooks: `shellcheck`, `shfmt`.
- CI: upload build artifacts (weekly report tarball) on tagged release.

### Evening (Document/Share, ~2h)
- Write an **Operations Runbook**: how to enable/disable timers, where outputs land, retention policy.
- Create a short screencast (commands only) – link in README.

### Why?
Repeatable, scheduled tasks with artifacts are what make your work **operational**. CI enforces quality.

### Real‑world mapping
- Site reliability & SecOps: scheduled health checks and evidence packs for audit/IR.

### Acceptance criteria
- Timer units present, enabled, and logs prove execution.
- Release built with tarball + manifest in GitHub Releases.

---

# Day 7 — **Mini‑Project & Release: Bash Admin Security Toolkit**

### Morning (Build, ~4h)
- Polish: banner, `--help` for each script, examples, idempotency checks, safe prompts (`read -r -p`).
- Add `bin/bootstrap_server.sh` to orchestrate: users/groups, ssh hardening, firewall default‑deny, timers enable.

### Midday (Learn/Labs, ~3h)
- Do a **clean run** on a new VM to ensure bootstrap covers a blank host safely.
- Re‑scan with Nmap before/after bootstrap; commit diff.

### Afternoon (Drill/Test, ~3h)
- Run `proc_watch`, generate benign suspicious activity, confirm alert JSON is emitted and dashboard shows it.
- Verify timers produced the expected reports in `/var/log/sec/`.

### Evening (Document/Share, ~2h)
- Tag **v0.2.0** release: attach demo GIFs, sample JSON outputs, and your ADRs for SSH/sudo/firewall decisions.
- Write a 1–2 page **real‑world scenario**: "New Ubuntu server joins prod – how this toolkit hardens & monitors day 1".

### Acceptance criteria
- Single command (or Make target) bootstraps a blank VM safely end‑to‑end.
- Public release with clear README, examples, and CI badge.


---

## How this week advances your cybersecurity path
- **Offense**: Knowing default misconfigs and service behaviors accelerates recon/exploitation (you’ll test them safely later).
- **Defense**: You can now harden, observe, and automate on day one of an engagement.
- **Platform/AppSec**: Your scripts integrate with CI and export structured logs – exactly what modern teams expect.
- **DFIR**: Your outputs (JSON, manifests, logs) are **evidence‑ready**.


---

## References / Study Hubs
- [ShellCheck](https://www.shellcheck.net/) – common pitfalls and explanations
- [shfmt](https://github.com/mvdan/sh) – formatting
- [Bats](https://github.com/bats-core/bats-core) – Bash testing
- [GNU coreutils manual](https://www.gnu.org/software/coreutils/manual/coreutils.html) – `grep/sed/awk/sort/find` essentials
- [OpenSSH hardening (Mozilla)](https://infosec.mozilla.org/guidelines/openssh)
- [systemd timers](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html) & [journald](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html)
- [Linux ACLs](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/securing_networks/configuring-file-system-access-control-lists_securing-networks)
- [UFW](https://manpages.ubuntu.com/manpages/focal/man8/ufw.8.html) / [nftables](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)
- [Mermaid Diagrams](https://mermaid.js.org/) for docs

## Similar GitHub repos / inspiration
- [koalaman/shellcheck](https://github.com/koalaman/shellcheck)
- [mvdan/sh (shfmt)](https://github.com/mvdan/sh)
- [bats-core/bats-core](https://github.com/bats-core/bats-core)
- [awesome-shell](https://github.com/alebcay/awesome-shell) – curated shell scripts & patterns
- [dev-sec/ansible-ssh-hardening](https://github.com/dev-sec/ansible-ssh-hardening) (concepts you’re scripting by hand this week)

## Rubric (Week 2)
- **Code quality**: ShellCheck clean; shfmt formatted; functions modular; no unquoted expansions.
- **Tests**: ≥10 Bats tests across 4+ scripts; CI required for PR merge.
- **Security**: SSH hardened, sudoers least‑privilege, default‑deny firewall, JSON‑line logs.
- **Docs**: README with architecture diagram, runbook, examples, and recorded demo.
- **Release**: v0.2.0 tag with artifacts (toolkit tarball, manifest, screenshots/GIFs).

