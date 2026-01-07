# Day-2 — Service Fingerprints & Safe Scans (Runbook)

> Repo module: `~/Desktop/cyber-learning-path/week1/day1_lab_starter`

This runbook enumerates banners/versions safely, stores XML + grepable outputs, and generates a small service inventory you can paste into Grafana as a manual snapshot.

---

## 0) Pre-flight

```bash
# where compose lives
cd ~/Desktop/cyber-learning-path/week1/day1_lab_starter/infra

# stack up (idempotent)
docker compose up -d
docker compose ps

# back to module root for outputs
cd ..
mkdir -p scans/day2 notes/week01/day2
