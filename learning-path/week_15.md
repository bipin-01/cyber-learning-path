# Week 15 — **Database Security Mastery**: Safe Migrations • Encryption (Transit/At‑Rest/In‑App) • Secrets • Tenant Isolation (Extra‑Deep)

_Generated: October 18, 2025_

> **Theme:** Make your data layer production‑credible and breach‑resistant. You’ll implement **zero‑downtime migrations**, strong **encryption in transit** (mutual TLS optional), **encryption at rest** (disk & backups), and **application‑level encryption** (envelope with KMS) for sensitive columns. You’ll harden **secrets management & rotation**, practice **backup + PITR** restores, and choose a **tenant isolation strategy** (RLS vs schema‑per‑tenant vs database‑per‑tenant) with concrete role models. Maps to **OWASP A05 Security Misconfiguration**, **A02 Cryptographic Failures**, **A09 Logging/Monitoring**, and **API4 Unrestricted Resource Consumption**.

---

## Outcomes
- Run **safe, reversible migrations** using an expand→migrate→contract pattern with **online indexes** and **batched backfills**.
- Enforce **TLS** to Postgres/MySQL with **server cert verification** and (optional) **mTLS**; disable insecure ciphers.
- Enable **disk & backup encryption**; practice **PITR** (point‑in‑time restore) and automated **restore tests**.
- Add **application‑level encryption** (AES‑GCM via envelope with KMS/HSM) for PII/PHI secrets; decide deterministic vs probabilistic modes.
- Centralize **secrets management** (Vault/Secrets Manager); rotate DB creds & app keys with **zero downtime**.
- Choose and implement a **tenant isolation model** with least‑privilege roles and **policy‑enforced access**.
- Publish `week15-db-security` with configs, migration guardrails, encryption helpers, restore scripts, and a report.

## Repository layout (this week)

```
/week15-db-security
  ├─ db/
  │  ├─ migrations/
  │  │  ├─ 001_expand_add_nullable_col.sql
  │  │  ├─ 002_backfill_batched.sql
  │  │  ├─ 003_contract_set_not_null.sql
  │  │  └─ guardrails.sql                  # prevent dangerous DDL
  │  ├─ roles.sql                          # role & grants model
  │  ├─ ssl/
  │  │  ├─ server.crt  (lab only)
  │  │  ├─ server.key  (lab only)
  │  │  └─ rootCA.crt  (lab only)
  │  ├─ pg_hba.conf.example
  │  ├─ postgresql.conf.example
  │  └─ pitr/
  │     ├─ wal_archiving.sh
  │     └─ restore.sh
  ├─ app/
  │  ├─ src/
  │  │  ├─ crypto/
  │  │  │  ├─ envelope.ts                  # KMS envelope (AES‑GCM)
  │  │  │  └─ formats.md                   # deterministic vs probabilistic
  │  │  ├─ orm/
  │  │  │  └─ migration_hooks.ts           # expand/contract checks
  │  │  └─ secrets/
  │  │     └─ provider.ts                  # Vault/Secrets Manager client
  │  ├─ tests/
  │  │  ├─ migrations.test.ts
  │  │  ├─ crypto_roundtrip.test.ts
  │  │  └─ restore_pitr.test.ts
  │  └─ package.json
  ├─ docs/
  │  ├─ migrations_playbook.md
  │  ├─ encryption_in_transit.md
  │  ├─ encryption_at_rest.md
  │  ├─ envelope_crypto.md
  │  ├─ tenants_isolation.md
  │  ├─ secrets_rotation.md
  │  └─ report-week15.md
  └─ README.md
```

---

# Day 1 — **Safe Migrations: Expand → Backfill → Contract**

### Morning (Build, ~4h)
- Create migration guardrails: disallow **blocking DDL** on hot tables (e.g., `SET statement_timeout=5000; SET lock_timeout=2000;`).
- Add `guardrails.sql` to enforce **search_path**, `lock_timeout`, **`CREATE INDEX CONCURRENTLY`**, and **no `ALTER COLUMN TYPE`** without USING clause on large tables.

```sql
-- db/migrations/001_expand_add_nullable_col.sql
BEGIN;
SET LOCAL lock_timeout = '2s';
ALTER TABLE app.users ADD COLUMN phone_enc bytea; -- nullable
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_phone_enc ON app.users (phone_enc);
COMMIT;
```
### Midday (Learn/Labs, ~3h)
- Review **dangerous DDL**: adding NOT NULL w/o default on big tables; adding default that backfills synchronously; wide `ALTER TYPE`; dropping columns used by code.
- Decide your **tooling**: Flyway/Liquibase/Prisma/Alembic. Enable **pre‑migration checks** in CI.

### Afternoon (Drill/Test, ~3h)
- Write **batched backfill** using primary‑key windows with `ORDER BY id LIMIT 1000` and **sleep** between batches to keep load under SLOs.
- Add a **feature flag** so the app writes to **both** old & new columns during backfill (dual‑write).

```sql
-- db/migrations/002_backfill_batched.sql (pseudo, run via script)
UPDATE app.users SET phone_enc = encrypt_phone(phone_plain)
WHERE id > $start AND id <= $end AND phone_plain IS NOT NULL;
```
### Evening (Document/Share, ~2h)
- Document cutover & rollback procedures; add **canary** migration on staging; list validation queries.
- Commit `migrations_playbook.md` with a **checklist**.

### Acceptance criteria
- Expand/backfill/contract scripts exist with timeouts; index created concurrently; CI blocks dangerous DDL.

---

# Day 2 — **Encryption in Transit: TLS & (optional) mTLS**

### Morning (Build, ~4h)
- Enable Postgres **TLS**: generate a **lab CA**, sign server cert; set `ssl = on`, `ssl_min_protocol_version = 'TLSv1.2'`.
- Harden `pg_hba.conf`: prefer `hostssl`, **SCRAM‑SHA‑256**, and (optionally) `clientcert=verify-full` for mTLS.

```conf
# postgresql.conf.example (snippets)
ssl = on
ssl_min_protocol_version = 'TLSv1.2'
ssl_ciphers = 'HIGH:!aNULL:!MD5'

# pg_hba.conf.example (snippets)
hostssl all app_readwrite 0.0.0.0/0 scram-sha-256
hostssl all app_readonly  0.0.0.0/0 scram-sha-256
# mTLS (optional)
hostssl all app_gateway   10.0.0.0/24 cert clientcert=verify-full
```
### Midday (Learn/Labs, ~3h)
- Validate **server identity** from the client: use `sslmode=verify-full` and pin to **CA**; reject self‑signed w/o root.
- Decide which paths need **mTLS** (e.g., gateway↔DB, pgbouncer↔DB).

### Afternoon (Drill/Test, ~3h)
- Break TLS deliberately (wrong hostname, bad CA) and ensure clients refuse the connection.
- Add integration tests that verify `ssl_used = true` via `pg_stat_ssl` (where available).

### Evening (Document/Share, ~2h)
- Write `encryption_in_transit.md` with command lines & screenshots of failing vs passing connections.

### Acceptance criteria
- DB only accepts TLS clients; hostname verification enforced; (optional) mTLS validated for a service pair.

---

# Day 3 — **Encryption at Rest & Backups (PITR)**

### Morning (Build, ~4h)
- Enable **disk encryption** (local lab: LUKS/BitLocker; cloud: managed EBS/PD with KMS).
- Encrypt **backups**: `pg_basebackup` + **WAL archiving** to an encrypted bucket (KMS key).

```bash
# db/pitr/wal_archiving.sh (sketch)
export AWS_KMS_KEY_ID=alias/lab-db-backups
# configure archive_command in postgresql.conf to push WAL to s3://secure-bucket/wal/
# then:
pg_basebackup -D /backups/base -X stream -C -S slot_week15 -Fp -R
```
### Midday (Learn/Labs, ~3h)
- Design **PITR**: pick an RPO/RTO; ensure WAL retention covers it; version & checksum artifacts.
- Decide **key rotation** cadence for backup keys; test decrypt/restore with old & new keys.

### Afternoon (Drill/Test, ~3h)
- Run **restore.sh** to stand up a **point‑in‑time** clone; run application smoke tests against the clone.
- Automate a **weekly restore test** in CI (lab) that validates integrity (row counts, checksums).

### Evening (Document/Share, ~2h)
- Write `encryption_at_rest.md` with RPO/RTO table and restore screenshots/logs.

### Acceptance criteria
- Encrypted base backup + WAL; successful PITR clone; documented restore procedure; integrity checks pass.

---

# Day 4 — **Application‑Level Encryption (Envelope, AES‑GCM)**

### Morning (Build, ~4h)
- Implement an **envelope encryption** helper: generate random DEK (data‑encryption key), encrypt with **AES‑GCM**, wrap DEK with **KMS** (KEK), and store `{dek_wrapped, nonce, tag, ciphertext}` in the column.
- Support **deterministic** mode (for equality lookups) using a separate **stable salt/IV derivation**; warn about pattern leakage.

```ts
// app/src/crypto/envelope.ts (concept sketch)
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
export async function encryptGCM(plaintext, aad, kms){
  const dek = randomBytes(32); const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dek, iv); if (aad) cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]); const tag = cipher.getAuthTag();
  const dek_wrapped = await kms.wrapKey(dek); // KMS/HSM
  return { dek_wrapped, iv, tag, ct };
}
```
### Midday (Learn/Labs, ~3h)
- Choose **columns** for encryption (PII/Secrets) and create getters/setters in ORM to transparently encrypt/decrypt.
- Discuss **searchability trade‑offs**: deterministic encryption allows equality queries but leaks duplicates; probabilistic protects patterns but needs app‑side scan/index.

### Afternoon (Drill/Test, ~3h)
- Write **round‑trip tests** and **tamper tests** (modify tag/nonce → verify decryption fails).
- Benchmark read/write overhead and document SLO impact; add caching for hot decrypted values with TTL.

### Evening (Document/Share, ~2h)
- Write `envelope_crypto.md` with diagrams and a decision matrix (deterministic vs probabilistic).

### Acceptance criteria
- Envelope helper works; tests pass; chosen columns encrypted in app; trade‑offs documented.

---

# Day 5 — **Secrets Management & Rotation**

### Morning (Build, ~4h)
- Abstract **secrets provider** (`provider.ts`) to support **Vault** or **AWS Secrets Manager**; use **short‑lived** DB creds (STS/leases) where possible.
- Teach app to **hot‑reload** DB creds from the provider w/o restarts (connection pool rebind).

```ts
// app/src/secrets/provider.ts (concept)
export interface SecretsProvider { get(name:string): Promise<string>; rotate(name:string): Promise<void>; }
export class CacheLayer implements SecretsProvider { /* cache + ttl; fallback */ }
```
### Midday (Learn/Labs, ~3h)
- Define **rotation cadence**: DB creds monthly; app KEKs quarterly; backup keys semi‑annually; emergency rotate runbook.
- Ensure **least privilege**: separate **login roles** (no ownership) from **object owner** roles; avoid shared superusers.

### Afternoon (Drill/Test, ~3h)
- Execute a **live rotation** in lab: issue a new DB password/role, update secret, rebind pools; confirm no downtime.
- Add a **break‑glass** role with MFA/short TTL; log and alert all uses.

### Evening (Document/Share, ~2h)
- Write `secrets_rotation.md` (cadence, runbooks, fallbacks) and include sample Vault/ASM policies.

### Acceptance criteria
- App reads secrets from provider; rotation works without downtime; privileged roles constrained and audited.

---

# Day 6 — **Tenant Isolation: Patterns & Role Models**

### Morning (Build, ~4h)
- Compare **row‑per‑tenant (RLS)** vs **schema‑per‑tenant** vs **database‑per‑tenant**: performance, isolation, ops complexity.
- Implement **RLS** baseline with **stable session context** (Week 7) and **queryable keysets** for pagination under policy.

```sql
-- db/roles.sql (snippets)
CREATE ROLE app_owner NOLOGIN;
CREATE ROLE app_readwrite LOGIN PASSWORD '...';
CREATE ROLE app_readonly  LOGIN PASSWORD '...';
GRANT USAGE ON SCHEMA app TO app_readwrite, app_readonly;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA app TO app_readwrite;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_readonly;

-- RLS example
ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app.orders
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
```
### Midday (Learn/Labs, ~3h)
- Design **schema‑per‑tenant** variant: template schema + per‑tenant roles; script **provisioning** & **migrations** across schemas.
- Add **service accounts** per microservice with minimal grants.

### Afternoon (Drill/Test, ~3h)
- Load tests: compare RLS vs schema‑per‑tenant on your dataset; track **plan caching** and policy filter cost.
- Fuzz tenant id spoofing; ensure **connection bootstrap** sets `app.tenant_id` securely (from verified session).

### Evening (Document/Share, ~2h)
- Write `tenants_isolation.md` with selection criteria and migration path if you outgrow RLS.

### Acceptance criteria
- Role model and policies implemented; chosen isolation strategy justified with benchmarks and threat model.

---

# Day 7 — **Mini‑Project & Release: DB Hardening Pack**

### Morning (Build, ~4h)
- Automate a **blue‑green** migration demo: expand/backfill/contract on a non‑trivial table while app stays online (dual‑write).
- Run **TLS‑only** connectivity, **PITR** restore, and **secret rotation** in a scripted sequence; capture logs/screens.

### Midday (Learn/Labs, ~3h)
- Produce `report-week15.md` with before/after risks, controls, and SLO impact; include restore validation table.
- Open issues for next steps: transparent **column masking** in BI, **KMS key rotation** automation, **pgBouncer TLS**.

### Afternoon (Drill/Test, ~3h)
- Tag **v1.5.0-dbsec**; include configs, scripts, tests, and docs; verify a **clean bring‑up** reproduces results.
- Export **database role diagram** and **policy graph**.

### Evening (Document/Share, ~2h)
- Cross‑link to prior weeks: Week 7 (RLS), Week 8 (idempotency & limits), Week 12 (monitoring dashboards).

### Acceptance criteria
- Release includes migration guardrails, TLS configs, backups & PITR, envelope crypto helpers, secrets provider, isolation policies, and report; clean install works.


---

## How this week advances your cybersecurity path
- **Data resilience:** Migrations no longer threaten uptime; PITR + tested restores reduce blast radius.
- **Cryptographic safety:** Data is protected in transit, at rest, and for the most sensitive fields even **inside** the DB.
- **Least privilege:** Clear role models & tenant isolation block lateral movement and data bleed.


---

## References / Study Hubs
- PostgreSQL Docs: SSL/TLS, RLS, Concurrency, `CREATE INDEX CONCURRENTLY`
- Prisma/Alembic/Flyway/Liquibase migration guides (expand/contract patterns)
- NIST SP 800‑57 (key management), NIST SP 800‑38D (AES‑GCM)
- Vault / AWS Secrets Manager rotation patterns
- pgBackRest / WAL‑G for backups & PITR

## Similar GitHub repos / inspiration
- [tminglei/pg_trgm migration examples]
- [walg/wal-g](https://github.com/wal-g/wal-g)
- [pgbackrest/pgbackrest](https://github.com/pgbackrest/pgbackrest)
- [hashicorp/vault guides](https://github.com/hashicorp/vault-guides)

## Rubric (Week 15)
- **Migrations**: expand/backfill/contract with guardrails; no blocking DDL; CI checks present.
- **Transit**: TLS required; hostname verification; optional mTLS validated.
- **At Rest**: encrypted backups; PITR tested; restore documented with checksums.
- **In App**: envelope encryption helper + tests; selected columns encrypted; perf impact measured.
- **Secrets**: central provider; live rotation works; roles least‑privilege with auditing.
- **Tenants**: isolation pattern implemented & benchmarked; spoofing prevented.

