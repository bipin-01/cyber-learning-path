# Day-1 Lab — Restart & Trace-Check Runbook

This runbook restarts the Day-1 lab stack and verifies logs (“traces”) end-to-end: Promtail → Loki → Grafana, plus app health and an initial Nmap sweep.

> Paths assume your project is at `~/Desktop/cyber-learning-path/week1/day1_lab_starter`.

---

## 0) Pre-flight

```bash
# Go to the infra folder (where docker-compose.yml lives)
cd ~/Desktop/cyber-learning-path/week1/day1_lab_starter/infra

# Sanity-check compose file
docker compose config -q

# Optional: show current containers
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```


## 1) Restart the Stack
```bash
# Stop and remove containers (keeps named volumes)
docker compose down

# Start everything
docker compose up -d

# Watch status unit healthy
docker compose ps

