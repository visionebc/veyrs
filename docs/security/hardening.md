---
title: Hardening checklist
purpose: Give operators a checklist of security settings for a VEYRS installation, each item verifiable with a command and a stated expected result.
scope: Native (systemd, nginx, PostgreSQL, Redis) and Docker Compose installations of 0.39.1; network design outside the VEYRS hosts and the identity provider's own hardening are not covered.
version: 0.39.1
verified: 2026-11-17
status: Partial
sources: [backend/veyrs/config.py, backend/veyrs/main.py, backend/veyrs/cli.py, infrastructure/systemd/veyrs-api.service, infrastructure/nginx-veyrs-console.conf, docker/compose.yaml, docker/console.conf, docker/env.example, docker/initdb.d/10-app-role.sh, scripts/verify-release.sh, install.sh]
related: [security/security-architecture.md, security/risk-register.md, security/authentication.md, DEPLOYMENT.md, DISASTER_RECOVERY.md]
---

# Hardening checklist

How to use this page. Work top to bottom. Every item has a **Check** you can run and the **Expected** result. Commands assume a native install in `/opt/veyrs` (the default of `install.sh`), run as `root` on the application node, with the service environment loaded where noted. Replace the example host `veyrs.example.com`. Docker items are in [section 3](#3-docker-compose). The items marked *Partial* are checks the product cannot make for you, or where a known limitation applies (see the [risk register](risk-register.md)).

To load the application's environment without printing it:

```bash
cd /opt/veyrs && set -a && . ./.env && set +a
```

> [!WARNING]
> Never paste the output of `cat .env` into a ticket or chat. The checks below print key names, lengths or yes/no only.

## 1. Native installation

### 1.1 Secrets and configuration

| # | Item | Check | Expected |
|---|---|---|---|
| 1 | `.env` is private | `stat -c '%a %U:%G' /opt/veyrs/.env` | `600 root:root` (or the service account) |
| 2 | Production mode, debug off | `grep -E '^VEYRS_(ENVIRONMENT\|DEBUG)=' /opt/veyrs/.env` | `VEYRS_ENVIRONMENT=production`, `VEYRS_DEBUG=false` |
| 3 | Secret key is set and long | `[ "$(grep -E '^VEYRS_SECRET_KEY=' /opt/veyrs/.env \| cut -d= -f2- \| tr -d '"' \| wc -c)" -ge 33 ] && echo ok` | `ok` (production also refuses to start without it since 0.41.0) |
| 4 | Encryption key set explicitly | `grep -cE '^VEYRS_ENCRYPTION_KEY=.+' /opt/veyrs/.env` | `1` (production boot refuses an empty key, `backend/veyrs/config.py:222`) |
| 5 | Public URL is HTTPS | `grep -E '^VEYRS_PUBLIC_BASE_URL=https://' /opt/veyrs/.env` | one matching line |
| 6 | CORS origins are exactly your console origin | `grep '^VEYRS_CORS_ORIGINS=' /opt/veyrs/.env` | only your HTTPS origin(s); never `*`. The code default is a deployment-specific host name, so always set it. |
| 7 | Metrics token set | `grep -cE '^VEYRS_METRICS_TOKEN=.+' /opt/veyrs/.env` | `1` (otherwise `/metrics` answers 404 in production) |
| 8 | No test settings in production | `grep -c '^VEYRS_TEST_' /opt/veyrs/.env` | `0` (R-22) |
| 9 | Token lifetimes are deliberate | `grep -E '^VEYRS_(ACCESS_TOKEN_MINUTES\|REFRESH_TOKEN_DAYS)=' /opt/veyrs/.env` | access 15-30 minutes, refresh 14 days or less (defaults 30 and 14) |
| 10 | Built-in self-test passes | `cd /opt/veyrs && set -a && . ./.env && set +a && venv/bin/python -m veyrs check` | exit code 0 |
| 11 | AI external providers off unless intended | `grep -E '^VEYRS_AI_ALLOW_EXTERNAL=' /opt/veyrs/.env` | `false` (default) |

### 1.2 Secret storage

| # | Item | Check | Expected |
|---|---|---|---|
| 12 | Where credentials live | `cd /opt/veyrs && set -a && . ./.env && set +a && venv/bin/python -m veyrs secrets status` | the mode and the count per column; in `local` mode all credentials are `local`, in `vault` mode none |
| 13 | Prefer the external vault for shared or regulated deployments | the same command | mode `vault`, vault reachable. `mirror` is a migration step only. |
| 14 | Vault credential files are private | `stat -c '%a %U %n' "$VEYRS_VAULT_SECRET_ID_FILE" "$VEYRS_VAULT_TOKEN_FILE" 2>/dev/null` | `600`; a world-readable file is refused by the application (`backend/veyrs/security/secret_vault.py:156-162`) |
| 15 | Previous keys removed after a rekey | `grep -c '^VEYRS_ENCRYPTION_KEY_PREVIOUS=.\+' /opt/veyrs/.env` | `0` once `veyrs secrets rekey --apply` has finished |
| 16 | Backups are protected like the key | `stat -c '%a %U %n' /opt/veyrs/var/backups` | not world-readable. A backup contains the database and the key; encrypt it and store it off the host. |

### 1.3 Database

| # | Item | Check | Expected |
|---|---|---|---|
| 17 | The application role cannot bypass RLS | as the application database user: `psql "$VEYRS_DATABASE_URL" -Atc "select rolsuper, rolbypassrls from pg_roles where rolname = current_user"` (convert the SQLAlchemy URL scheme `postgresql+psycopg://` to `postgresql://` for `psql`) | `f\|f`. If either is `t`, tenant isolation is **not** enforced; since 0.41.0 the production API refuses to start. |
| 18 | RLS is forced on tenant tables | `psql "$DATABASE_URL" -Atc "select count(*) from pg_class where relkind='r' and relrowsecurity and relforcerowsecurity"` | `72` on 0.39.1 (derived from the model and the skip lists; a different number after an upgrade means `init-db` has not been re-run) |
| 19 | The bootstrap password is gone | `grep -c 'veyrs:veyrs@' /opt/veyrs/.env` | `0` (production boot refuses it) |
| 20 | PostgreSQL listens only where needed | `ss -ltn 'sport = :5432'` | loopback or the private database network only |
| 21 | Platform administrators are few | `psql "$DATABASE_URL" -Atc "select email from users where is_superuser and deleted_at is null"` | a short list you recognise |
| 22 | Platform administrators use MFA | `psql "$DATABASE_URL" -Atc "select email, mfa_enabled from users where is_superuser and deleted_at is null"` | `mfa_enabled = t` for each; or turn on `PUT /api/v1/mfa-policy {"require_mfa": true}` for their organization, which forces enrolment at the next sign-in |
| 23 | No immortal API keys | `psql "$DATABASE_URL" -Atc "select name, created_at from api_keys where revoked_at is null and expires_at is null"` | empty, or each one justified |

### 1.4 Service and network

| # | Item | Check | Expected |
|---|---|---|---|
| 24 | The API listens on loopback only | `ss -ltnp 'sport = :8000'` | local address `127.0.0.1:8000` |
| 25 | Trusted proxies are exactly your proxies | `systemctl cat veyrs-api \| grep -E 'FORWARDED\|forwarded'` and `grep '^VEYRS_FORWARDED_ALLOW_IPS=' /opt/veyrs/.env` | the nginx peer (`127.0.0.1`) **and** any load balancer in front of nginx, comma separated. Too few: every user is recorded and rate-limited as the proxy (10 logins per minute for everyone). Too many (`*`): a caller can forge their address. |
| 26 | systemd sandbox score | `systemd-analyze security veyrs-api.service` | exposure well below "UNSAFE"; the shipped unit runs as `root` (R-06), so consider a dedicated user |
| 27 | Only 443 is public | `ss -ltn` on the node and your firewall rules | no listener on 8000, 5432, 6379 reachable from outside |
| 28 | Redis is private | `ss -ltn 'sport = :6379'` and `redis-cli -u "$VEYRS_REDIS_URL" ping` | loopback or private network; ideally with a password (R-28) |
| 29 | Time is synchronised | `timedatectl show -p NTPSynchronized --value` | `yes` (TOTP and token expiry depend on it) |

### 1.5 TLS and HTTP headers

The shipped vhost listens on plain HTTP; a TLS terminating proxy in front is mandatory.

| # | Item | Check | Expected |
|---|---|---|---|
| 30 | HTTPS answers with HSTS | `curl -sI https://veyrs.example.com/ \| grep -i strict-transport-security` | `max-age=31536000; includeSubDomains` |
| 31 | Modern TLS only | `nmap --script ssl-enum-ciphers -p 443 veyrs.example.com` or `openssl s_client -tls1_1 -connect veyrs.example.com:443 </dev/null` | TLS 1.2 and 1.3 only (the proxy's responsibility) |
| 32 | Security headers on the API | `curl -sI https://veyrs.example.com/healthz` | `x-content-type-options: nosniff`, `x-frame-options: DENY`, `referrer-policy: no-referrer`, `content-security-policy`, `permissions-policy`, `cross-origin-opener-policy` |
| 33 | CSP on the console has no script `unsafe-inline` | `curl -sI https://veyrs.example.com/ \| grep -i content-security-policy` | `script-src 'self'` (and `style-src 'self' 'unsafe-inline'`, the one allowed inline source) |
| 34 | Metrics is not public | `curl -s -o /dev/null -w '%{http_code}\n' https://veyrs.example.com/metrics` | `404` or `200` (the console page); never Prometheus text |
| 35 | API docs are off | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/docs` | `404` in production |
| 36 | Anonymous API access is refused | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/v1/assets` | `401` |
| 37 | Server banner hidden | `curl -sI https://veyrs.example.com/ \| grep -i '^server:'` | no version (the service starts with `--no-server-header`; set `server_tokens off;` in nginx) |
| 38 | Request size | `nginx -T 2>/dev/null \| grep client_max_body_size` | `128m` on the API location at most |

### 1.6 Identity configuration

| # | Item | Check | Expected |
|---|---|---|---|
| 39 | LDAP uses TLS with verification | Administration, Directory: `use_ssl` or `start_tls` on, `verify_certificate` on | verification enabled (it can be turned off per organization, `backend/veyrs/services/ldap_auth.py:415-420`) |
| 40 | LDAP JIT provisioning intentional | Administration, Directory | off, or `default_role_slugs` empty |
| 41 | OIDC requires a second factor | Administration, Single sign-on: `require_mfa_amr` | on, if your IdP reports `amr` |
| 42 | RADIUS server is reachable only from the VEYRS node | firewall rules for UDP 1812 | restricted (RADIUS uses a shared secret and MD5) |
| 43 | At least one local break-glass administrator exists and is not delegated | `psql "$DATABASE_URL" -Atc "select count(*) from users where is_superuser and password_hash is not null and deleted_at is null"` | `1` or more (platform administrators always sign in locally) |

### 1.7 Supply chain and updates

| # | Item | Check | Expected |
|---|---|---|---|
| 44 | Release signature verified before install | `scripts/verify-release.sh <directory-with-release-assets>` | exit code `0`. `3` unsigned, `4` bad signature, `5` hash mismatch, `6` cannot verify. |
| 45 | Dependencies are checked for known vulnerabilities | see the commands below | no High or Critical advisory for a reachable package |
| 46 | Self-update hook is root-owned | `stat -c '%a %U %n' "$VEYRS_UPDATE_PRE_HOOK"` | not group- or other-writable |
| 47 | Air-gapped installs disable the update check | `grep '^VEYRS_UPDATE_URL=' /opt/veyrs/.env` | empty value |

Dependency check with `pip-audit` in a throwaway environment (any machine with Python 3.11+ and network access; it sends package names and versions only):

```bash
python3 -m venv /tmp/audit-venv
/tmp/audit-venv/bin/pip install pip-audit
/tmp/audit-venv/bin/pip-audit --no-deps -r /opt/veyrs/requirements.txt
rm -rf /tmp/audit-venv
```

The same check against the public OSV database without installing anything (requires `python3` and `curl`):

```bash
python3 - <<'PY' > /tmp/osv-query.json
import json, re
pins = [m.groups() for l in open('/opt/veyrs/requirements.txt')
        if (m := re.match(r'^([A-Za-z0-9_.\-]+)==(\S+)', l))]
print(json.dumps({"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
                              for n, v in pins]}))
PY
curl -s -X POST https://api.osv.dev/v1/querybatch \
  -H 'Content-Type: application/json' --data @/tmp/osv-query.json \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["results"]; print(sum(1 for x in r if x.get("vulns")), "packages with advisories")'
rm -f /tmp/osv-query.json
```

On 2026-11-17 this reported 10 packages with advisories (details and reachability in [R-01](risk-register.md#r-01-dependency-vulnerabilities-high-p1)).

### 1.8 Logging and monitoring

| # | Item | Check | Expected |
|---|---|---|---|
| 48 | Audit writes are not failing | `journalctl -u veyrs-api --since '24 hours ago' \| grep -c 'audit write failed'` | `0`; any hit means audit rows were lost (R-04) |
| 49 | Rate limiting uses Redis | `journalctl -u veyrs-api \| grep 'falling back to in-process'` | no recent hits (a hit means per-worker limits until Redis answers again; the worker retries every 30 s) |
| 50 | Failed sign-ins are reviewable | `GET /api/v1/auth-events?success=false&since=<ISO time>` with an `audit:read` token (platform administrators add `unattributed=true` for attempts that named no account). The table is row-level-secured since 0.41.0: as the application role, plain SQL sees nothing until a tenant is bound | reviewed daily |
| 51 | Logs are shipped off the host | your log pipeline | the JSON log lines (`correlation_id`, `actor`, `status`) arrive in your SIEM |

**Audit trails are append-only in the database** (since 0.41.0,
`backend/veyrs/schema_steps/step_auth.py`): a trigger refuses `UPDATE`,
`DELETE` and `TRUNCATE` on `audit_log`, `ai_audit_log` and `auth_events`.
Retention deletes run inside a transaction that sets
`SET LOCAL veyrs.audit_prune = 'on'`; foreign-key cascades of a hard-deleted
organization or user pass too. Check: `psql "$DATABASE_URL" -Atc "select
tgrelid::regclass from pg_trigger where tgname = 'veyrs_append_only'"` lists the
three tables. The application role owns these tables, and an owner can disable
a trigger; to take that power away from the API, run it as a separate login
role that is granted `SELECT, INSERT` on the three tables (and the usual
privileges elsewhere) but does not own them. That split is not shipped.

## 2. Reverse proxy in front of VEYRS

| # | Item | Check | Expected |
|---|---|---|---|
| 52 | Host header validated | `curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: bad/host' https://veyrs.example.com/healthz` | `400`. The pinned Starlette is affected by a Host-header path bypass (R-01), so the proxy must reject malformed `Host` values. |
| 53 | Proxy overwrites `X-Forwarded-For` | proxy configuration | sets the header from the real peer instead of appending to a client-supplied value, unless the previous hop is in `VEYRS_FORWARDED_ALLOW_IPS` |
| 54 | Large uploads allowed only where needed | `grep -R client_max_body_size /etc/nginx` | no larger than your largest legitimate scanner export |

## 3. Docker Compose

Commands run in the directory containing `docker/compose.yaml`; `docker/.env` is written by `./docker/veyrs-docker.sh init` and holds the secrets (mode 0600).

| # | Item | Check | Expected |
|---|---|---|---|
| D1 | `.env` is private | `stat -c '%a %U' docker/.env` | `600` |
| D2 | Production mode | `grep -E '^VEYRS_ENVIRONMENT=' docker/.env` | `production` (the shipped default is `development`, R-19, which serves `/docs` and skips the boot guards) |
| D3 | Public URL and CORS match your front proxy | `grep -E '^VEYRS_(PUBLIC_BASE_URL\|CORS_ORIGINS)=' docker/.env` | your HTTPS origin |
| D4 | Only the console publishes a port | `docker compose -f docker/compose.yaml ps --format '{{.Name}} {{.Ports}}'` | only the console service has a host port; the API, PostgreSQL and Redis have none |
| D5 | The console binds loopback unless you front it | `grep -E '^VEYRS_HTTP_BIND=' docker/.env` | `127.0.0.1:8080` or a deliberate address |
| D6 | Containers are hardened | `docker inspect --format '{{.Name}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}} sec={{.HostConfig.SecurityOpt}}' $(docker compose -f docker/compose.yaml ps -q)` | `ro=true`, `caps=[ALL]`, `sec=[no-new-privileges:true]` for the long-running services |
| D7 | API runs unprivileged | `docker compose -f docker/compose.yaml exec api id -u` | `10001` |
| D8 | The application role is not a superuser | `docker compose -f docker/compose.yaml exec postgres psql -U postgres -d veyrs -Atc "select rolname, rolsuper, rolbypassrls from pg_roles where rolname not like 'pg\_%'"` | the application role has `f` and `f` (`docker/initdb.d/10-app-role.sh`) |
| D9 | Trusted proxies are right | `docker compose -f docker/compose.yaml exec api printenv VEYRS_FORWARDED_ALLOW_IPS` | the console's address plus `VEYRS_FRONT_PROXY_IPS` if you set it (`docker/compose.yaml:339`) |
| D10 | Images are pinned by digest | `grep -nE 'image:.*@sha256' docker/compose.yaml` | PostgreSQL and Redis lines present |
| D11 | Metrics not exposed | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/metrics` | `404` (`docker/console.conf:140`) |
| D12 | CLI checks | `./docker/veyrs-docker.sh cli check` and `./docker/veyrs-docker.sh cli secrets status` | exit code 0 and the expected secret mode |

The container stack serves plain HTTP on port 8080 and sends no HSTS on purpose; put a TLS terminating proxy in front for anything beyond a local evaluation.

## 4. After a change

Re-run sections 1.1, 1.3 (items 17-18), 1.5 and 2 after every upgrade, re-run the dependency check weekly, and record the date and the person who ran it. The values marked "derived" above (for example the RLS table count) come from the code and the generated schema at 0.39.1, not from a measurement of your database; if your number differs, find out why before relying on tenant isolation.
