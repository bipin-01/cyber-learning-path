# Week 07 — **Database Security: Postgres RLS, Least‑Privilege, & pgAudit** (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Implement **strong multi‑tenant data isolation** with **Row‑Level Security (RLS)**, engineer **least‑privilege roles**, integrate **application‑level identity → DB session settings**, and light up **pgAudit** + dashboards to detect exfil and abuse. You’ll also build a **safe vs vulnerable branch** to see how injection interacts with RLS, and you’ll practice backups/migrations/rotation. Maps to **OWASP A03 Injection**, **A01/API1 Broken Access Control**, **A05 Misconfiguration**, and **A09 Logging/Monitoring**.

---

## Outcomes
- Data model & **RLS policies** that enforce tenant/user isolation in the DB (defense‑in‑depth for BOLA).
- Least‑privilege **role design**: authenticator → app role (no DDL), immutable `search_path`, only needed schemas.
- App integration: set `app.current_tenant`, `app.current_user`, `app.current_roles` per‑request/transaction.
- **pgAudit** logging for SELECT/INSERT/UPDATE/DELETE/COPY + role changes; dashboards & alerts (exfil patterns).
- Injection lab: parameterized queries vs concat; how RLS helps & what it cannot stop.
- Backups/migrations: repeatable schema changes, restore drill, and password rotation.
- Ship `week07-db-security-rls` with schema, policies, tests, app integration, audit, and a mini‑report.

## Repository layout (this week)

```
/week07-db-security-rls
  ├─ db/
  │  ├─ schema.sql
  │  ├─ policies.sql
  │  ├─ seed.sql
  │  ├─ roles.sql
  │  └─ pgaudit.sql
  ├─ app/
  │  ├─ src/
  │  │  ├─ db.ts                 # pool, SET LOCAL helpers
  │  │  ├─ repos/                # parameterized queries only
  │  │  ├─ routes/
  │  │  └─ tests/
  │  └─ package.json
  ├─ docker/
  │  ├─ docker-compose.yml       # Postgres + pgAudit enabled + log shipping
  │  └─ postgres.conf
  ├─ dashboards/
  │  └─ pgaudit-panels.json
  ├─ docs/
  │  ├─ rls-design.md
  │  ├─ role-model.md
  │  ├─ audit-playbook.md
  │  └─ report-week07.md
  ├─ vuln-branch-notes/          # intentionally vulnerable snippets
  └─ README.md
```

---

# Day 1 — **Model, Roles, and Baseline RLS**

### Morning (Build, ~4h)
- Design a minimal **multi‑tenant** model: `tenants`, `users` (belongs to tenant), `items` (tenant‑scoped), `orders` (tenant‑scoped, user‑owned).
- Create **roles**: `app_authenticator` (login only), `app_user` (no DDL, limited DML), `app_admin` (admin endpoints), `migration` (schema changes only).
- Lock **search_path** to `public, app` and revoke `CREATE` on `public`; create a dedicated `app` schema for tables.

```sql
-- db/roles.sql (snippet)
CREATE ROLE app_authenticator NOINHERIT LOGIN PASSWORD 'dev_only_change_me';
CREATE ROLE app_user NOINHERIT;
CREATE ROLE app_admin NOINHERIT;
CREATE ROLE migration NOLOGIN;

ALTER DATABASE appdb SET search_path = app, public;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;  -- no temp CREATE in public

GRANT USAGE ON SCHEMA app TO app_user, app_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
```
### Midday (Learn/Labs, ~3h)
- Read **RLS** overview; understand `ENABLE ROW LEVEL SECURITY`, `FOR ALL` vs per‑cmd policies, `USING` vs `WITH CHECK`.
- Decide **tenant key** type (UUID recommended). Plan `app.current_tenant` and `app.current_user` session settings.

### Afternoon (Drill/Test, ~3h)
- Create tables with `tenant_id` + ownership fields. Enable RLS and write **deny‑by‑default** policies.
- Write psql tests where you `SET LOCAL app.current_tenant` and prove cross‑tenant reads fail.

```sql
-- db/policies.sql (snippet)
ALTER TABLE app.items ENABLE ROW LEVEL SECURITY;

-- Only rows from current tenant are visible
CREATE POLICY items_tenant_isolation
  ON app.items
  USING (tenant_id = current_setting('app.current_tenant')::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
```
### Evening (Document/Share, ~2h)
- Write `docs/rls-design.md` with table diagrams and policy rationale.
- Commit `roles.sql`, `schema.sql`, `policies.sql`, and test transcripts.

### Why?
RLS is your **last line** against IDOR/BOLA: even if an app bug forgets to filter by tenant, the DB refuses cross‑tenant access.

### Real‑world mapping
- Multi‑tenant SaaS isolation; audit & compliance evidence for access segregation.

### Acceptance criteria
- RLS enabled on all tenant‑scoped tables; policies deny cross‑tenant access in psql tests.
- Roles and privileges minimize DDL and limit DML to needed tables.

---

# Day 2 — **User‑level Ownership & Security‑Definer Functions**

### Morning (Build, ~4h)
- Extend policies to include **user ownership** where relevant (e.g., order owner).
- Create **SECURITY DEFINER** functions for complex writes that require extra checks; **pin search_path** inside functions.

```sql
-- Owner policy (read/update only your own within your tenant)
CREATE POLICY orders_owner_read
  ON app.orders FOR SELECT
  USING (tenant_id = current_setting('app.current_tenant')::uuid
         AND owner_user_id = current_setting('app.current_user')::uuid);

CREATE POLICY orders_owner_update
  ON app.orders FOR UPDATE
  USING (tenant_id = current_setting('app.current_tenant')::uuid
         AND owner_user_id = current_setting('app.current_user')::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid
         AND owner_user_id = current_setting('app.current_user')::uuid);

-- Security definer with locked search_path
CREATE OR REPLACE FUNCTION app.create_order_safe(p_item uuid, p_qty int)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public AS $$
DECLARE oid uuid := gen_random_uuid();
BEGIN
  INSERT INTO app.orders(id, tenant_id, owner_user_id, item_id, qty)
  VALUES (oid, current_setting('app.current_tenant')::uuid,
               current_setting('app.current_user')::uuid, p_item, p_qty);
  RETURN oid;
END $$;
REVOKE ALL ON FUNCTION app.create_order_safe(uuid,int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.create_order_safe(uuid,int) TO app_user;
```
### Midday (Learn/Labs, ~3h)
- Study **SECURITY DEFINER pitfalls**; always set `search_path` explicitly to avoid function hijack.
- Review **immutable vs stable** functions and their impact on policy evaluation.

### Afternoon (Drill/Test, ~3h)
- Add tests: a user cannot update another user’s order even within same tenant.
- Attempt to bypass via crafted queries; confirm RLS/owner checks stop it.

### Evening (Document/Share, ~2h)
- Update `role-model.md` with who can execute which functions and why.
- Record psql sessions demonstrating denials & allowed operations.

### Acceptance criteria
- Owner‑level policies enforced; definer functions set `search_path` and expose minimal surface.
- Tests cover positive and negative ownership cases.

---

# Day 3 — **App Integration: Setting Session Context Per Request**

### Morning (Build, ~4h)
- In the app, on each request (after OIDC auth), start a transaction and `SET LOCAL` the context: `app.current_tenant`, `app.current_user`, and optionally `app.current_roles`.
- Wrap DB calls with a helper that **always** runs inside a transaction and sets context before queries.

```ts
// app/src/db.ts (Node + pg)
import { Pool } from "pg";
const pool = new Pool();

export async function withDbContext(ctx, fn){
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET LOCAL app.current_tenant = $1', [ctx.tenantId]);
    await client.query('SET LOCAL app.current_user = $1', [ctx.userId]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK'); throw e;
  } finally {
    client.release();
  }
}
```
### Midday (Learn/Labs, ~3h)
- Study how **prepared statements** and parameterized queries** work in your driver; ensure no string concatenation remains.
- Lock `search_path` at DB level; do not rely on per‑session defaults from untrusted clients.

### Afternoon (Drill/Test, ~3h)
- Write integration tests: cross‑tenant ID swap attempts fail even if a route bug omits tenant filter (DB stops it).
- Simulate missing context (no `SET LOCAL`) and show queries fail by policy.

### Evening (Document/Share, ~2h)
- Add a README section showing **sequence diagrams**: Request → Auth → Set Context → Query → RLS decisions.
- Add logs (CID) capturing tenant/user IDs alongside query summaries.

### Acceptance criteria
- All data access happens under `withDbContext`; unit/integration tests enforce it.
- Cross‑tenant app bugs cannot read/write other tenants due to RLS.

---

# Day 4 — **pgAudit + Log Shipping + Dashboards**

### Morning (Build, ~4h)
- Enable **pgAudit** in Postgres config; log classes READ, WRITE, ROLE, DDL. Route Postgres logs to **Loki/Elastic** with Promtail/Filebeat.
- Add a retention & privacy note (avoid logging PII values; prefer statement summaries).

```sql
-- db/pgaudit.sql (snippet)
CREATE EXTENSION IF NOT EXISTS pgaudit;
ALTER SYSTEM SET pgaudit.log = 'read, write, role, ddl';
ALTER SYSTEM SET pgaudit.log_parameter = off;  -- avoid sensitive values
SELECT pg_reload_conf();
```
### Midday (Learn/Labs, ~3h)
- Read pgAudit docs: statement vs object logging, parameter logging risks.
- Plan detection queries: off‑hours large SELECTs, `COPY TO STDOUT`, sequential scans of large tables.

### Afternoon (Drill/Test, ~3h)
- Generate benign activity and verify events appear in SIEM; index fields: db user, statement class, object, rows.
- Create dashboards: **Top read tables**, **COPY attempts**, **DDL events**, **failed auths**.

### Evening (Document/Share, ~2h)
- Write `audit-playbook.md`: alert runbooks for exfil patterns, who to page, and evidence to capture.
- Export dashboards JSON to `dashboards/pgaudit-panels.json`.

### Acceptance criteria
- pgAudit enabled and visible in dashboards; events for SELECT/INSERT/UPDATE/DELETE/ROLE are searchable.
- At least 3 alerts/panels created with screenshots and JSON exports.

---

# Day 5 — **Injection Lab: Parameterization vs Concat & What RLS Can/Cannot Do**

### Morning (Build, ~4h)
- Create a **vulnerable** route in a lab branch that concatenates a filter (e.g., `name LIKE '${q}%'`).
- Main branch: enforce **parameterized queries** only; deny dynamic `search_path` or `SET ROLE` from app.

### Midday (Learn/Labs, ~3h)
- Review **A03 Injection**: SQLi types, second‑order SQLi, function abuse. Understand how **RLS may still leak** if a policy function is exploitable.
- Plan payloads for sqlmap or custom tests; ensure rate limiting to avoid DoS.

### Afternoon (Drill/Test, ~3h)
- Exploit vuln branch with controlled payloads; capture evidence; then switch to main branch and prove **non‑repro**.
- Test that even with an injection in app layer, **cross‑tenant reads** are still blocked by RLS policies.

### Evening (Document/Share, ~2h)
- Write attack→fix→non‑repro notes showing exact statements and pgAudit evidence.
- Add Semgrep rule: forbid string concatenation to DB methods (`$client.query("..." + var)`).

### Acceptance criteria
- Main branch resists payloads (400/parameterized); pgAudit shows no risky statements.
- RLS prevents cross‑tenant reads even under attempted injection.

---

# Day 6 — **Backups, Migrations, Rotation & Restore Drill**

### Morning (Build, ~4h)
- Create **migration scripts** (Knex/Prisma/Flyway) for schema & policies; run idempotently.
- Add `pg_dump` daily task and a weekly full restore **drill** into a fresh DB (new name).

### Midday (Learn/Labs, ~3h)
- Study **logical vs physical** backups; know PITR basics; understand how RLS/policies/migrations interact with dumps.
- Plan **password rotation** for `app_authenticator` & `app_user` users; update secrets safely.

### Afternoon (Drill/Test, ~3h)
- Perform a restore into a clean DB; point the app to it and run tests.
- Rotate DB passwords/keys; ensure app recovers (pool test).

### Evening (Document/Share, ~2h)
- Document your **restore runbook** with timing metrics and pitfalls.
- Publish a signed release artifact containing migration version and checksums.

### Acceptance criteria
- Successful restore validated by tests; migration version matches; integrity checks pass.
- Credentials rotated; app shows no downtime beyond planned window.

---

# Day 7 — **Mini‑Project & Release: RLS + Audit Pack**

### Morning (Build, ~4h)
- Polish: README with **RLS policy table**, role graph, and session context diagram.
- Add scripts: `make seed`, `make psql`, `make restore`, `make rotate-secrets`.

### Midday (Learn/Labs, ~3h)
- Run a clean bring‑up; re‑execute all psql tests and app integration tests; collect pgAudit dashboards screenshots.
- Optional: add **COPY TO detection** alert and test it safely.

### Afternoon (Drill/Test, ~3h)
- Generate release artifacts (policies.sql, role grants, dashboards JSON, test transcripts).
- Tag **v0.7.0** and create a GitHub Release.

### Evening (Document/Share, ~2h)
- Publish `report-week07.md` mapping RLS & audit to **OWASP API1/A03/A09** with evidence.
- Open issues for Week 8 (rate/race/idempotency at DB level) and Week 10 (monitoring SLOs).

### Acceptance criteria
- Release includes schema/policies/roles, tests, dashboards, and report; CI green.
- RLS and pgAudit are reproducible from README with one command.


---

## How this week advances your cybersecurity path
- **AppSec**: DB‑level guardrails for IDOR/BOLA; security definer patterns without foot‑guns.
- **Blue/DFIR**: pgAudit + dashboards turn DB activity into evidence; exfil patterns are surfaced.
- **Platform**: Migrations, backup/restore drills, and rotation make you production‑credible.


---

## References / Study Hubs
- [PostgreSQL: Row‑Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL: Managing Roles & Privileges](https://www.postgresql.org/docs/current/user-manag.html)
- [Search Path & Security](https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATH)
- [pgAudit](https://github.com/pgaudit/pgaudit)
- [OWASP Top 10](https://owasp.org/Top10/) & [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/)

## Similar GitHub repos / inspiration
- [pgaudit/pgaudit](https://github.com/pgaudit/pgaudit)
- [Supabase (Postgres + RLS patterns)](https://github.com/supabase/supabase)
- [PostgREST (RLS‑friendly API)](https://github.com/PostgREST/postgrest)
- [knex/knex](https://github.com/knex/knex) / [prisma/prisma](https://github.com/prisma/prisma) (migrations)

## Rubric (Week 7)
- **Design**: RLS on all tenant/user tables; deny‑by‑default; explicit policies; locked search_path.
- **Least‑privilege**: roles limited to needed DML; no ad‑hoc DDL; authenticator role only logs in.
- **Integration**: per‑request `SET LOCAL` context; tests prove DB denies cross‑tenant access even if app misbehaves.
- **Telemetry**: pgAudit enabled; dashboards and alerts for exfil patterns; evidence captured.
- **Resilience**: migrations idempotent; restore drill documented; rotation performed; v0.7.0 release.

