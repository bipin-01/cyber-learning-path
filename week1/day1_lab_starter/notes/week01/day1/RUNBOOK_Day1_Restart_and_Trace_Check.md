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
```

## 2) Health probes (generate fresh logs)
```bash
# Core infra
curl -fsS http://localhost:3100/ready && echo "Loki OK"
curl -fsS http://localhost:9080/ready && echo "Promtail OK"
curl -fsS http://localhost:3000/api/health && echo "Grafana OK"

# Apps (touch endpoints to create new log lines)
curl -fsS http://localhost:8081/ >/dev/null || true   # DVWA
curl -fsS http://localhost:8082/ >/dev/null || true   # vulnapi
curl -fsS http://localhost:8083/ >/dev/null || true   # Keycloak (302 is expected)
curl -fsS http://localhost/health >/dev/null || true  # Caddy (if you wired a /health)
```

## 3) Trace check: Promtail → Loki
### 3.1) Confirm labels and job in Loki
```bash
curl -sS "http://localhost:3100/loki/api/v1/labels" | jq .
curl -sS "http://localhost:3100/loki/api/v1/label/job/values" | jq .
```
### 3.2) Query recent streams
```bash
START=$(date -u -d '20 minutes ago' +%s%N); END=$(date -u +%s%N)

# Count matching streams
curl -sG "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="docker-logs"}' \
  --data-urlencode "start=$START" --data-urlencode "end=$END" \
  --data-urlencode 'limit=100' | jq '.data.result | length'

# Peek the first stream’s labels (should show a service name)
curl -sG "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="docker-logs"}' \
  --data-urlencode "start=$START" --data-urlencode "end=$END" \
  --data-urlencode 'limit=1' | jq '.data.result[0].stream'
```

### 3.3) Promtail metrics (sent vs dropped)
```bash
curl -sS http://localhost:9080/metrics | \
  egrep -i 'promtail_sent_entries_total|promtail_dropped_entries_total' || true
```

## 4) Grafana quick check
1. Open http://localhost:3000

2. Ensure Loki data source points to http://loki:3100

3. Explore → run {job="docker-logs"} and confirm you see logs from ≥3 services
(e.g., reverse-proxy, loki, dvwa, vulnapi, grafana, keycloak).

