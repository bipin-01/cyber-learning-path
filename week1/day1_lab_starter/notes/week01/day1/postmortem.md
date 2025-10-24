# Day 1 Post-Mortem (Short)

**What went well**
- Reproducible stack spun up with reverse-proxy + dashboards
- Loki/Promtail pipeline operational

**Risks / Assumptions**
- Using `latest` for DVWA; pin by digest in Week 1
- Zeek visibility limited if host net restricted

**Next steps**
- Add Zeek log shipping to central store
- Add alert rules in Grafana/Loki
- Harden Keycloak + TLS via Caddy
