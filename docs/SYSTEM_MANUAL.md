# System manual

What runs, what it reads, what it exposes, and what to do when one of those
stops. This is the **operator's** reference.

It deliberately does not repeat the other manuals:

| You want to | Read |
|---|---|
| Install it from nothing | [INSTALL.md](../INSTALL.md) |
| Deploy an upgrade | [DEPLOYMENT.md](DEPLOYMENT.md) |
| Use the product, screen by screen | [USER_MANUAL.md](USER_MANUAL.md) |
| Administer a tenant from the console | [ADMIN_GUIDE.md](ADMIN_GUIDE.md) |
| Understand why it is built this way | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Query or operate the database | [DATABASE.md](DATABASE.md) |
| Wire an external system in | [INTEGRATIONS.md](INTEGRATIONS.md) |
| Recover from a disaster | [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) |

---

## 1. What a VEYRS installation is made of

```
                    ┌──────────── nginx ────────────┐
   browser ────────▶│ console (static)  ·  /api/v1 ─┼──▶ veyrs-api  (uvicorn, 4 workers)
   API client ─────▶│ TLS terminates here           │       │  127.0.0.1:8000
                    └───────────────────────────────┘       │
                                                            ├──▶ PostgreSQL 15
                                                            └──▶ Redis  (rate limits, locks)

   veyrs-agent  ──poll──▶ /api/v1/agents/…      (scanner runner; may live on another host)
   veyrs-intel-sync.timer ──hourly tick──▶ NVD · EPSS · KEV · CWE · SLA evaluation
   veyrs-digest.timer     ──hourly tick──▶ per-organization daily digest
```

Five moving parts. **Four processes and two timers**, all systemd:

| Unit | Type | What it is | Fails how |
|---|---|---|---|
| `veyrs-api.service` | long-running | The API and everything the console talks to | Console shows nothing; `/healthz` dead |
| `veyrs-agent.service` | long-running | Pulls scan jobs and runs the scanners | Scans stay queued; no error in the UI until the lease is reaped |
| `veyrs-intel-sync.timer` → `.service` | oneshot, hourly | Asks *which feeds are due*, then runs them + `run-sla` | Intelligence quietly ages; KEV is the one that hurts |
| `veyrs-digest.timer` → `.service` | oneshot, hourly | Asks *whose digest hour this is*, then sends | Nobody is told; nothing else breaks |
| nginx | long-running | TLS, static console, reverse proxy | Everything, from the outside |

> **Both timers fire hourly and neither one is a schedule.** The *cadence* lives
> in the database — `organizations.settings.intel_schedule` and
> `…settings.digest` — and `veyrs intel-due` / `veyrs digest` decide whether
> this hour is the one, per organization. Pinning `OnCalendar` to a specific
> hour would make a setting the console displays and the machine ignores.

Two systemd details that were each paid for once:

* `veyrs-intel-sync.service` sets `OOMPolicy=continue`. systemd's default is
  `stop`: when the kernel OOM-kills **any** process in the unit's cgroup, the
  rest of the unit is SIGTERMed. That is how an EPSS blow-up killed the wrapper
  shell mid-loop and `sync-kev` never ran for three nights. A stale EPSS is a
  degraded signal; a stale KEV is a missed emergency.
* `veyrs-agent.service` is deliberately **not** `ProtectHome`. `nuclei` reads
  its ~13,500 templates from `~/nuclei-templates`; locking `/root` turns every
  scan into a silent zero-template run that reports success.

### 1.1 The same installation, in containers

`docker/compose.yaml` is the second supported shape — single node, for
evaluation and development. Every unit above has a counterpart, and the
counterpart runs **the same code**, not a re-implementation of it:

| systemd unit | compose service | Profile | Notes |
|---|---|---|---|
| `veyrs-api.service` | `api` | default | uvicorn ×4. **No published port** |
| nginx | `console` | default | the only published port, `127.0.0.1:8080` by default |
| — | `init` | default | one-shot `init-db` + `bootstrap`, idempotent |
| `veyrs-intel-sync.timer` | `intel` | `workers` | runs `scripts/sync-intel.sh` — literally the same script |
| `veyrs-digest.timer` | `digest` | `workers` | runs `scripts/send-digest.sh` |
| `veyrs-agent.service` | `agent` | `agent` | nuclei 3.11.1, pinned and checksummed |

The two tick loops carry an **interval and no schedule**, exactly like the
timers they replace: `docker/tick.sh` asks hourly and the database answers
whether this hour is the one. The catch-up tick at container start is the
equivalent of `Persistent=true` — and it is safe for the same reason, because
the loop decides nothing.

Three differences from a host install are deliberate and worth knowing:

1. **The API container runs as uid 10001, not root.** The host unit runs as
   root and compensates with `ProtectSystem=strict` + `ReadWritePaths`. That is
   a documented limitation of the unit rather than a recommendation, and a
   container has no reason to inherit it.
2. **The nuclei corpus lives in a volume, not in the image.** Templates change
   daily; baked into a layer, a container up for a month would scan with a
   month-old corpus and say nothing about it. `docker/agent-entrypoint.sh`
   seeds it on first start and **refuses to start** if the corpus is empty —
   because a nuclei with no templates does not error, it reports a clean scan
   for every asset it is handed. Same failure the host unit avoids by not
   setting `ProtectHome`, arriving through a different door.
3. **The `workers` and `agent` profiles are off by default.**
   `veyrs-docker.sh status` says so from the machine itself, with the
   consequence spelled out — a node without `intel` keeps scoring confidently
   against intelligence that stopped refreshing, and that is invisible in the
   console.

Deployment detail and the full command set are in
[Deployment](/DEPLOYMENT.html); the container-specific variables live in
`docker/env.example`, which is the file `veyrs-docker.sh init` turns into a
0600 `.env`.

---

## 2. Configuration reference

Everything is environment-driven (12-factor). `/opt/veyrs/.env` is read at
process start — **changing it requires a restart**, and both timer units read it
through the same file.

All variables take the prefix `VEYRS_`. Unset means the default below.

> **`.env` is `0600` and contains two keys that are not rotatable in place.**
> See §2.2.

### 2.1 Identity and environment

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_APP_NAME` | `VEYRS` | Shown in the API title and `/healthz`. |
| `VEYRS_TAGLINE` | `Unified Cybersecurity Risk Management` | Cosmetic. |
| `VEYRS_VERSION` | current release | **Read by `/healthz`.** It is bumped in `pyproject.toml` *and* `config.Settings.version`; only the second one is served. |
| `VEYRS_ENVIRONMENT` | `development` | `development` \| `staging` \| `production`. Production refuses to boot with an unsafe config (§2.5), hides `/docs` and `/redoc`, and makes `/metrics` 404 without a token. |
| `VEYRS_DEBUG` | `false` | Must be off in production; enforced. |
| `VEYRS_DEFAULT_LOCALE` | `en` | `en` \| `es` \| `de` \| `fr` \| `it`. Per-request `Accept-Language` overrides it. |

### 2.2 Cryptography and sessions

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_SECRET_KEY` | *(ephemeral)* | Signs JWTs. **≥ 32 characters.** Unset means a fresh random key per process — every restart invalidates every session, and four workers disagree with each other. Fatal in production. |
| `VEYRS_ENCRYPTION_KEY` | *(derived)* | Fernet key for secrets at rest. Generate with `veyrs keygen`. **Required explicitly in production**: a derived key is tied to `SECRET_KEY`, so rotating the session secret would silently orphan every stored third-party credential. |
| `VEYRS_ACCESS_TOKEN_MINUTES` | `30` | Access-token lifetime. |
| `VEYRS_REFRESH_TOKEN_DAYS` | `14` | Refresh-token lifetime. |
| `VEYRS_JWT_ALGORITHM` | `HS256` | `HS256` \| `HS384` \| `HS512`. |
| `VEYRS_PASSWORD_MIN_LENGTH` | `12` | Enforced server-side on every password set. |

**Neither key can be rotated on its own.** `SECRET_KEY` is cheap — it logs
everyone out. `ENCRYPTION_KEY` is not: changing it does not invalidate the
ciphertext, it makes it undecryptable. Every stored credential must be decrypted
with the old key and re-encrypted with the new one, or re-entered by hand.

### 2.3 Storage

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_DATABASE_URL` | `postgresql+psycopg://veyrs:veyrs@127.0.0.1:5432/veyrs` | The `+psycopg` driver marker is required. Production refuses to boot while the bootstrap password is still in it. |
| `VEYRS_REDIS_URL` | `redis://127.0.0.1:6379/0` | Rate-limit counters and locks. **Redis down = `/readyz` 503**, and the rate limiter fails closed. |

### 2.4 API surface

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_API_PREFIX` | `/api/v1` | Also where `openapi.json` is served. |
| `VEYRS_CORS_ORIGINS` | the console origin | Comma-separated. The console is served from a different host than the API in most deployments; get this wrong and every browser call fails with no server-side error. |
| `VEYRS_RATE_LIMIT_PER_MINUTE` | `240` | General budget, per identity. |
| `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` | `10` | **Separate on purpose**: this is credential-stuffing defence and must bite long before the general limit. Raise it for offices that egress behind one NAT address, where 50 analysts signing in at 09:00 legitimately exceed it. |
| `VEYRS_TRUST_PROXY_HEADERS` | `false` | Honour `X-Forwarded-For`. Enable **only** behind a proxy you control — otherwise any caller can mint a fresh rate-limit identity per request. |
| `VEYRS_MAX_UPLOAD_MB` | `32` | Scan imports and documents. nginx's `client_max_body_size` must be ≥ this, or the rejection happens upstream with a less useful message. |
| `VEYRS_METRICS_TOKEN` | *(empty)* | Bearer token for `/metrics`. Empty = open in development, **404 in production**. The exposition maps every route template and the build version; it is not public data. |
| `VEYRS_PUBLIC_BASE_URL` | the console URL | Used to build links in notifications. Must be `https://` in production. |

> An unauthenticated `/metrics` request gets **404, not 401** — a probe learns
> nothing about whether the endpoint exists or the token was merely wrong. A
> `allow 10.0.0.0/24` in nginx is *not* the control it looks like when every
> request arrives from a reverse proxy inside that range.

### 2.5 Intelligence feeds

All optional. The platform degrades; it never breaks.

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_NVD_API_KEY` | *(empty)* | Without it NVD allows 5 requests / 30 s, so a large `lastModified` delta legitimately takes hours. This is why the unit has `TimeoutStartSec=infinity`. |
| `VEYRS_NVD_API_URL` | NVD CVE API 2.0 | Override for a mirror. |
| `VEYRS_EPSS_CSV_URL` | EPSS current scores | Gzipped CSV. |
| `VEYRS_KEV_JSON_URL` | CISA KEV feed | |
| `VEYRS_CWE_CATALOG_URL` | MITRE CWE XML (zip) | |
| `VEYRS_FEED_HTTP_TIMEOUT` | `60` | Seconds, per request. |

### 2.6 AI gateway

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_AI_ALLOW_EXTERNAL` | `false` | Off by default, and the per-tenant AI policy can only narrow it further. |
| `VEYRS_AI_ALLOW_LOCAL` | `true` | |
| `VEYRS_AI_LOCAL_BASE_URL` | local Ollama endpoint | OpenAI-compatible. |
| `VEYRS_AI_LOCAL_MODEL` | `qwen3:32b` | |
| `VEYRS_AI_MAX_DATA_CLASSIFICATION` | `internal` | `public` \| `internal` \| `confidential` \| `restricted`. The ceiling on what may leave the installation. Confidential data cannot reach an external provider under the default policy. |

### 2.7 Notifications (SMTP)

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_SMTP_HOST` | *(empty)* | Empty disables delivery. Notification rows are still written, so nothing is lost when it is configured later. |
| `VEYRS_SMTP_PORT` | `25` | |
| `VEYRS_SMTP_USER` / `VEYRS_SMTP_PASSWORD` | *(empty)* | |
| `VEYRS_SMTP_FROM` | the platform address | |
| `VEYRS_SMTP_STARTTLS` | `true` | |

### 2.8 The agent data plane

`veyrs-agent` reads its **own** environment file — `/etc/veyrs-agent/agent.env`,
`0600`, because the token reaches the data plane:

| Variable | Notes |
|---|---|
| `VEYRS_URL` | Where the agent polls. |
| `VEYRS_AGENT_TOKEN` | Its credential. One per agent; revoke in Administration → Agents. |
| `VEYRS_AGENT_ALLOW` | The target allowlist. **The agent refuses anything outside it** — this is what keeps a scanner from being pointed at a third party. |
| `VEYRS_AGENT_RESOLVERS` | DNS resolvers used for target resolution. |

### 2.9 What production refuses to start with

`Settings.assert_production_safe()` runs at import when
`VEYRS_ENVIRONMENT=production`, and raises on:

* `debug` on
* `database_url` still carrying the `veyrs:veyrs@` bootstrap password
* `public_base_url` not `https://`
* `encryption_key` not set explicitly

A refusal to boot is the point. Each of these is silent damage otherwise.

---

## 3. Command-line reference

```bash
cd /opt/veyrs
PYTHONPATH=backend venv/bin/python -m veyrs.cli <command>
```

Everything is idempotent: re-running never duplicates rows.

### Schema and setup

| Command | Does |
|---|---|
| `init-db` | Creates missing **tables**, reconciles columns, applies RLS policies, seeds built-in roles and the compliance catalogues. Safe — and required — on every deploy. |
| `sync-schema` | Adds columns, single-column indexes and foreign keys present in the models and missing from the database. **Does not create tables**: on a database missing a release's new tables it prints `0 columns … added` and exits 0. See [DATABASE.md §5](DATABASE.md#5-schema-management). |
| `keygen` | Prints a fresh Fernet key for `VEYRS_ENCRYPTION_KEY`. |
| `bootstrap` | Creates the first organization and its administrator. `--org <slug> --name <n> --email <e>`; prompts for the password. |
| `check` | Self-test: configuration, database, Redis, CVSS/EPSS/risk engines. **Run this first** when something is wrong. |

### Intelligence

| Command | Does |
|---|---|
| `sync-nvd` | Incremental CVE pull from NVD (by `lastModified`). |
| `sync-epss` | Refresh EPSS scores; appends to `epss_history`. |
| `sync-kev` | Refresh the CISA KEV catalogue. |
| `sync-cwe` | Refresh the MITRE CWE dictionary. |
| `intel-due` | Prints which feeds have reached their configured interval **right now**. This is what the hourly timer actually consults. |

### Operations

| Command | Does |
|---|---|
| `recompute-risk` | Re-runs the risk engine. `--org <slug>` to scope it. Run it after changing a risk profile. |
| `run-sla` | Evaluates SLA state and fires escalations. Already called by `sync-intel.sh`. |
| `digest` | Queues and delivers the daily digest for every organization whose configured hour this is. |
| `import-inventory` | Loads assets and their installed software from a JSON file. For a one-off; recurring inventory belongs in Administration → Asset sources. |

Wrapper scripts, which is what the timers run:

```
scripts/sync-intel.sh     intel-due → the due feeds → run-sla, per-feed isolated
scripts/send-digest.sh    one digest tick
scripts/backup.sh         database + secrets + documents
scripts/restore.sh        the tested counterpart
scripts/test.sh           the test suite (NEVER bare pytest — see §7)
scripts/gen-schema-doc.py regenerate docs/DATABASE_SCHEMA.md
```

---

## 4. Surfaces

| Surface | Path | Auth | Notes |
|---|---|---|---|
| API | `/api/v1/*` | `Authorization: Bearer <jwt>` or `X-API-Key: veyrs_…` | Every endpoint authorizes server-side. |
| OpenAPI schema | `/api/v1/openapi.json` | none | Always on. |
| Swagger / ReDoc | `/docs`, `/redoc` | none | **Disabled in production.** |
| Liveness | `/healthz` | none | `{status, app, version}`. Cheap; no I/O. |
| Readiness | `/readyz` | none | Checks PostgreSQL **and** Redis; `503` + `{"status":"degraded"}` if either is down. This is the probe a load balancer should use. |
| Metrics | `/metrics` | Bearer `VEYRS_METRICS_TOKEN` | Prometheus exposition. 404 when unauthenticated. |
| Console | `/` (static) | the API's own session | A static bundle; nginx serves it, the API never does. |

Functional modules, and where each is administered:

| Module | API tag | Administered in |
|---|---|---|
| Assets and inventory | `assets`, `cmdb` | Administration → Asset sources ([ADMIN_GUIDE](ADMIN_GUIDE.md)) |
| Vulnerabilities and findings | `findings`, `intel` | Threat Intel → Schedule |
| Scanners and imports | `agents`, `integrations` | Administration → Scanning |
| Remediation | `tickets`, `integrations` | Administration → Ticketing (internal queue **or** an ITSM connector) |
| Risk register | `risk register` | Administration → Risk register (on/off per tenant) |
| SLA and escalation | `policies` | SLA & Policies |
| Compliance | `compliance` | Compliance |
| Knowledge base and publishing | `knowledge` | Integrations → Documentation connector |
| AI gateway | `ai` | Administration → AI policy |
| Reporting | `reports` | Reporting |
| Identity | `auth`, `admin`, `team import` | Administration → Users / Teams |

---

## 5. Routine operation

### Deploying a release

Full procedure in [DEPLOYMENT.md](DEPLOYMENT.md). The short form, and the two
steps most often skipped:

```bash
git -C /opt/veyrs pull                       # or rsync the release
venv/bin/pip install -r requirements.txt
PYTHONPATH=backend venv/bin/python -m veyrs.cli init-db     # NOT sync-schema
systemctl restart veyrs-api
curl -s localhost:8000/healthz               # must report the NEW version
```

> `/healthz` reporting the previous version after a correct deploy means the
> bump landed in `pyproject.toml` only. The served number comes from
> `config.Settings.version`. Both, every time.

### Restarting

```bash
systemctl restart veyrs-api        # ~2 s; in-flight requests get 30 s to finish
systemctl restart veyrs-agent      # SIGINT; a running scan is abandoned and re-queued
systemctl restart nginx
```

Never wait on a restart with a bare `sleep`. Poll:

```bash
timeout 30 bash -c 'until curl -sfo /dev/null localhost:8000/healthz; do sleep 1; done' \
  && echo up || journalctl -u veyrs-api -n 40 --no-pager
```

### Logs

Everything goes to journald; nothing writes its own log file.

```bash
journalctl -u veyrs-api -f
journalctl -u veyrs-agent -n 100 --no-pager
journalctl -u veyrs-intel-sync --since yesterday     # the feed run, per feed
journalctl -u veyrs-digest --since today
```

Every request carries a correlation id (`X-Correlation-ID`, echoed back). It is
in the log line and in the error body — quote it when reporting a problem.

### Abandoned scan leases

An agent that dies mid-job leaves its lease held. Reap it:

```
POST /api/v1/agents/maintenance/reap
```

### Backups

```bash
/opt/veyrs/scripts/backup.sh
```

Database + `.env` secrets + uploaded documents. Two things about it that are not
optional:

* The dump **must** run as a role that bypasses RLS, or it fails partway through
  after writing a partial file. [DATABASE.md §7.1](DATABASE.md#71-backup-and-restore).
* The archive contains `VEYRS_ENCRYPTION_KEY`, because without it every stored
  third-party credential is unrecoverable ciphertext — which makes the archive
  as sensitive as the database. `0600`, and **off this host**.

A backup that has never been restored is a hypothesis. `scripts/restore.sh` is
the tested counterpart; [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) is the drill.

---

## 6. Troubleshooting

| Symptom | First check | Usual cause |
|---|---|---|
| Console loads, every call fails in the browser | browser console, not the server log | `VEYRS_CORS_ORIGINS` does not list the console's origin |
| `/readyz` 503, `/healthz` 200 | the `checks` object it returns | PostgreSQL or Redis down — the API itself is fine |
| `UndefinedTable` / `UndefinedColumn` 500 on new endpoints only | `init-db` in the deploy log | `sync-schema` was run instead of `init-db`, and exited 0 |
| `/healthz` names the previous version | `config.Settings.version` | version bumped in `pyproject.toml` only |
| Everyone logged out after a restart | `VEYRS_SECRET_KEY` | unset → a fresh random key per worker, per restart |
| Stored ITSM/AI credentials stopped decrypting | `VEYRS_ENCRYPTION_KEY` | rotated in place; see §2.2 |
| Login works, then everything is empty | `set_tenant` / the RLS binding | a commit ended the transaction-local tenant binding ([DATABASE.md §1.1](DATABASE.md#11-the-transaction-local-gotcha)) |
| Scans queue and never run | `journalctl -u veyrs-agent` | agent down, token revoked, or the target is outside `VEYRS_AGENT_ALLOW` |
| Scan "succeeds" with zero findings | the agent unit's sandboxing | `ProtectHome` locking `/root` → nuclei ran with no templates |
| KEV is days stale, EPSS is fine | `journalctl -u veyrs-intel-sync` | the unit was OOM-killed mid-loop; confirm `OOMPolicy=continue` |
| Nobody receives a digest | `veyrs digest` by hand | `VEYRS_SMTP_HOST` empty, or no organization's configured hour has come round |
| `429` under normal office load | `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` | the whole office egresses from one NAT address |
| `/metrics` 404 | `VEYRS_METRICS_TOKEN` | production with no token set — by design |
| `pg_dump` fails partway | the role it ran as | RLS is `FORCE`d; the owner is not exempt |

Start with `veyrs check`. It self-tests configuration, storage and the engines
in that order, and it names the layer that failed.

---

## 7. Tests

```bash
./scripts/test.sh                       # the whole suite
./scripts/test.sh tests/test_phase46_risk_register.py
```

**Never run bare `pytest`.** `conftest.py` aborts with *"no test database
configured"* on purpose — without that guard the suite would run against the
configured database, which in a deployment is production.

Two documentation guards run with everything else and will fail a release that
lets a manual drift:

* `tests/test_docs_are_current.py::test_the_generated_schema_reference_matches_the_models`
  — regenerate with `python3 scripts/gen-schema-doc.py`.
* `…::test_every_setting_the_process_reads_is_documented` — a new field on
  `config.Settings` must appear in §2 of this file, and a variable documented
  here that the code does not read fails the mirror test.

---

## 8. Security posture in one page

* **Two layers of tenant isolation**, application and PostgreSQL RLS, neither
  trusting the other. [DATABASE.md §1](DATABASE.md#1-the-tenancy-model).
* **Every endpoint authorizes server-side.** Nothing is enforced only in the UI;
  `test_every_route_is_protected` walks the route table and proves it.
* **Passwords are Argon2id**, never reversible. Third-party credentials are
  Fernet-encrypted at rest and never returned by any endpoint.
* **The AI gateway cannot exceed the caller.** Every capability maps to a
  permission the user already holds; secrets and PII are stripped before a model
  sees a prompt; the model proposes structured output and VEYRS compiles the
  query itself.
* **The agent refuses targets outside its allowlist**, so a compromised console
  cannot turn a scanner on a third party.
* **Append-only trails.** `audit_log`, `auth_events` and `ai_audit_log` have no
  update or delete path in the application.

Threats and their mitigations: [THREAT_MODEL.md](THREAT_MODEL.md).
Reporting a vulnerability: [SECURITY.md](SECURITY.md).
