# Week 01 / Day 1 — Baseline Lab & Dashboards

Spin up a reproducible cyber lab with visible telemetry from day one.

## Services (pinned where practical)
- Reverse proxy: **Caddy** (`caddy:2.8.4`)
- Vulnerable web app: **DVWA** (`vulnerables/web-dvwa:latest`) — pin by digest later
- Vulnerable API: **json-server** (custom image here, pinned to Node 20)
- DB: **Postgres** (`postgres:16.3`)
- IAM: **Keycloak** (`quay.io/keycloak/keycloak:26.0.2`)
- Logs store: **Loki** (`grafana/loki:2.9.8`)
- Log shipper: **Promtail** (`grafana/promtail:2.9.8`)
- Dashboards: **Grafana** (`grafana/grafana:11.2.0`)
- Network sensor: **Zeek** (`zeek/zeek:6.2.0`)

> **Note on version pinning**: Some community images don’t publish semantic tags. For long-term reproducibility, replace `:latest` with immutable digests. Keep a `/notes/pins.md` with `docker buildx imagetools inspect` outputs.

## Network Layout

```mermaid
flowchart LR
  subgraph Internet / Host
    RP[Reverse Proxy :80]:::pub
  end

  subgraph Trust Zone: Lab Network (172.18.0.0/16)
    G[Grafana :3000]
    L[Loki :3100]
    P[Promtail]
    D[DVWA :80]
    A[Vuln API :3000]
    DB[(Postgres :5432)]
    KC[Keycloak :8080]
  end

  ZH[(Zeek on host net)]:::sens

  RP -->|/grafana| G
  RP -->|/dvwa| D
  RP -->|/api| A
  RP -->|/auth| KC
  G --> L
  P --> L
  KC --> DB

classDef pub fill:#e3f2fd,stroke:#42a5f5,stroke-width:2px;
classDef sens fill:#fff3e0,stroke:#fb8c00,stroke-width:2px;
```

## Quickstart

```bash
cp .env.example .env   # edit strong passwords
docker compose -f infra/docker-compose.yml --env-file .env up -d
docker compose -f infra/docker-compose.yml ps

# Grafana at:    http://localhost/grafana
# DVWA at:       http://localhost/dvwa
# Vuln API at:   http://localhost/api
# Keycloak at:   http://localhost/auth
# Reverse proxy health: http://localhost/health
```

## Acceptance Criteria
- Grafana shows logs for at least **3 services** (e.g., Caddy, Grafana, DVWA) — screenshots committed.
- `nmap` HTML/XML report committed under `/notes/week01/day1/nmap/`.
- `docker compose ps` shows all **healthy**.
- README contains the **Mermaid** diagram above.

## Notes
Keep **every command you run** in `/notes/week01/commands.md` for repeatability.
