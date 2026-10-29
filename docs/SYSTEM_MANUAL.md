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

### 2.2.1 Secret storage: local Fernet or an external vault

Which columns hold reversible third-party credentials, and in what form, is in
[SECURITY.md §Secrets at rest](SECURITY.md#secrets-at-rest). These settings
decide **where** they live. They are environment-only on purpose: the vault's
own credentials cannot be stored in the database encrypted by the very key the
vault exists to take off the host.

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_SECRET_BACKEND` | `local` | `local`: Fernet in the database, the vault is never contacted. `mirror`: write to the vault **and** keep a local copy; read the vault first, fall back to the copy (a migration step — the copies are still on this host). `vault`: the vault holds the only copy; a read that fails is an error, never an empty credential. |
| `VEYRS_VAULT_ADDR` | *(empty)* | `https://vault.example.com:8200`. HashiCorp Vault or OpenBao. **Must be `https://` in production.** |
| `VEYRS_VAULT_MOUNT` | `veyrs` | A KV **version 2** mount. Values live at `<mount>/data/secrets/<uuid>`, field `value`. One mount (or namespace) per VEYRS installation — `veyrs secrets gc` treats every unreferenced key under `secrets/` as an orphan. |
| `VEYRS_VAULT_AUTH` | `approle` | `approle` \| `token`. |
| `VEYRS_VAULT_ROLE_ID` | *(empty)* | AppRole role-id (an identifier, not a secret). |
| `VEYRS_VAULT_SECRET_ID_FILE` | *(empty)* | Path to a file holding the AppRole secret-id. `0600`, owned by the service account. A world-readable file is **refused**; group-readable logs a warning. |
| `VEYRS_VAULT_TOKEN_FILE` | *(empty)* | With `VEYRS_VAULT_AUTH=token`: path to a file holding a token (typically a vault agent sink). Re-read every 5 minutes, so a rotated token is picked up without a restart. Same permission rule. |
| `VEYRS_VAULT_CA_FILE` | *(empty)* | PEM bundle to verify the vault's certificate, if it is not signed by a public CA. |
| `VEYRS_VAULT_NAMESPACE` | *(empty)* | Sent as `X-Vault-Namespace` (Vault Enterprise / OpenBao namespaces). |
| `VEYRS_VAULT_TIMEOUT` | `5.0` | Seconds per vault request. |

Only the vault **token** is cached, per process, and an AppRole login is
repeated at two thirds of its lease. Credential values are fetched on every use
so the vault's audit log records every read.

The minimum vault policy for the AppRole (`veyrs` mount):

```hcl
path "veyrs/data/secrets/*"     { capabilities = ["create", "update", "read"] }
path "veyrs/metadata/secrets/*" { capabilities = ["read", "delete"] }   # gc
path "veyrs/metadata/secrets"   { capabilities = ["list"] }             # gc, status
```

Operating it — switching modes, migrating, rolling back, collecting orphans —
is [ADMIN_GUIDE.md §Secret storage](ADMIN_GUIDE.md#secret-storage-local-or-an-external-vault).

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
| `VEYRS_EPSS_HISTORY_DAYS` | `365` | Days of daily EPSS snapshots kept in `epss_history`, counted back from the **newest** snapshot, so a stalled feed never erases its own history. A scored day is ~370,000 rows, about 80 MB: 365 days is roughly 30 GB, 90 days about 7 GB. `0` keeps everything. `sync-epss` prunes after each successful ingest. In the Docker stack, set it in `docker/.env`. |

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
* `secret_backend` `mirror` or `vault` with an incomplete vault block: no
  `vault_addr`, a non-`https` `vault_addr`, no `vault_role_id` /
  `vault_secret_id_file` (AppRole) or `vault_token_file` (token), or a named
  file that does not exist

A refusal to boot is the point. Each of these is silent damage otherwise.

### 2.10 Software updates

Read by the API's update check (Administration → Software update) and by the
root `veyrs-updater.service` (same `.env`). Full flow in
[DEPLOYMENT.md](DEPLOYMENT.md#in-product-update-native-installs).

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_UPDATE_URL` | the GitHub "latest release" API of the public repository | **Empty disables every network check** — the setting for an air-gapped installation. A failed check is shown, never raised; results are cached for an hour. |
| `VEYRS_UPDATE_DOWNLOAD_BASE` | the public release downloads | The updater fetches `<base>/v<X.Y.Z>/<asset>`. A mirror is fine: the signature, not the URL, is what is trusted. |
| `VEYRS_UPDATE_LOCAL_DIR` | *(empty = off)* | A directory the updater installs a release **from** (a USB disk, an NFS share): `<dir>/v<X.Y.Z>/`, `<dir>/veyrs-<X.Y.Z>/` or the files directly in `<dir>/`. Not under `/home` or `/root`, which the API cannot read. |
| `VEYRS_UPDATE_UPLOAD_DIR` | `<install>/var/update-uploads` | Where releases uploaded through the console are staged, one `v<X.Y.Z>/` each. |
| `VEYRS_UPDATE_SPOOL` | `/var/lib/veyrs/update-requests` | The API only **writes a request** here. `veyrs-updater.path` watches this path — change both together. |
| `VEYRS_UPDATE_STATUS_DIR` | `/var/lib/veyrs/update-status` | One JSON (steps, outcome) and one log per updater run; the console shows the last ten. |
| `VEYRS_UPDATE_PRE_HOOK` | *(empty)* | Absolute path of an executable the updater runs **before** installing, e.g. `/opt/veyrs/scripts/backup.sh`. Root-owned, not group/other-writable, no arguments. |
| `VEYRS_UPDATE_SKIP_BACKUP` | `false` | Without a hook the updater **refuses**; set this to update without one, deliberately. |
| `VEYRS_INSTALL_MODE` | *(detected)* | `git` \| `docker` \| `native`. The container image sets `docker`. A `.git` in the install root always means `git`: that tree is managed by its git deploy and is never self-updated. |

#### Updating from a local copy (no GitHub)

From 0.34.0 the root updater installs a release from three sources. The
request names a source **keyword**, never a path; the updater decides the
directory:

| Source | Where | Typical use |
|---|---|---|
| `release` | `VEYRS_UPDATE_DOWNLOAD_BASE` (GitHub) | a host with Internet |
| `upload` | files uploaded in Administration → Software update, staged in `VEYRS_UPDATE_UPLOAD_DIR` | an operator with the files on a laptop |
| `local` | `VEYRS_UPDATE_LOCAL_DIR` | a USB disk or a share mounted on the host |

Copy **every** file of the release: `SHA256SUMS`, `SHA256SUMS.sig`,
`veyrs-setup.sh`, `veyrs-<X.Y.Z>-src.tar.gz` and
`veyrs-<X.Y.Z>-wheels-x86_64.tar.gz`. The last one holds the Python packages
of `requirements.txt` as wheels for CPython 3.11, 3.12 and 3.13 on x86_64
Linux. With it the install runs `pip --no-index` and needs no PyPI; without
it the update downloads the packages from PyPI.

The console checks every local copy with the installation's release key and
shows "verified" before anything can be applied. That check is advisory. The
root updater copies the files into its own `0700` work directory and refuses
links and incomplete copies. It verifies the copy again, and only that
verification counts.

A host still on 0.33.x has no local source. Update it once with the installer:

```bash
sudo bash veyrs-setup.sh --source /media/usb/veyrs-0.34.0-src.tar.gz
# picks up veyrs-0.34.0-wheels-x86_64.tar.gz beside it (or pass --wheels FILE)
```

### 2.11 Installed software and network access

Two read-only pages under Administration, for platform administrators only (the
versions of everything installed, and the internal hosts an installation depends
on, are reconnaissance data):

- **Installed software** (`GET /api/v1/admin/system/software`): the node's OS,
  kernel and Python; PostgreSQL and Redis as the servers report themselves; and
  nginx, `pg_dump`, OpenSSL, OpenSSH (`ssh-keygen` verifies release signatures),
  curl and git. Each shows the version the binary reports and the one the
  package manager records, which is the version an advisory names. Scanner
  versions (nuclei, ZAP) are the ones each registered agent declared: the API
  does not run scanners (nuclei aborts under the API's `MemoryDenyWriteExecute`,
  and the sandbox is not loosened to read a version). It also lists
  every Python package in the API's interpreter, with **direct** (declared in
  `pyproject.toml`) and the pin in `requirements.txt`. A package that differs from
  its pin, is not in the lock, or is pinned but missing counts as **drift**. It
  describes the node that answered; behind the proxy that is the primary.
- **Network access** (`GET /api/v1/admin/system/network`): every destination VEYRS
  contacts, grouped by when (run time, updates, external AI, install time, scan
  agent). Each row has its port, what uses it, whether it is required, the
  `VEYRS_*` setting that moves or disables it, and what to do on a host that
  cannot reach it. Rows are resolved against the live settings (a feed pointed at
  a mirror shows the mirror), followed by this installation's own services
  (database, Redis, mail relay, vault, local AI) and the **enabled** connectors of
  the organization. The list lives in `services/network_requirements.py`;
  `tests/test_phase53_system_inventory.py` fails if a host appears in the shipped
  code without a row there, or if the Download page does not name it.

The console itself loads nothing from the internet (no CDN, web font or
analytics), and a test holds that too.


### 2.12 Two-factor sign-in

Each person turns it on under **My account** (click your name, top right). The
three methods:

| Method | What the person needs | What the installation needs |
|---|---|---|
| Authenticator app (TOTP) | any RFC 6238 app; the QR code is drawn by the server | nothing |
| E-mail code | access to the account's e-mail address | a mail relay: `VEYRS_SMTP_HOST` and its port, user and sender settings |
| Telegram code | to open the bot, press **Start**, and give their chat id | `VEYRS_TELEGRAM_BOT_TOKEN` |

Nothing is enabled until the person types back a code, which is the proof that
the app works or the message arrived. Activation hands out **ten recovery
codes**, once. Each one signs in once, typed where the six-digit code goes.

E-mail and Telegram codes are sent only after the password was verified. They
are six digits, stored hashed in Redis for `VEYRS_MFA_CODE_TTL` seconds, and
work once. Five wrong guesses burn the code, and every wrong guess also counts
against the account's lockout. Sending is limited to one code per 30 s and six
per 15 minutes. If the relay, the bot or Redis cannot be reached, the sign-in
**fails closed**: it never falls back to the password alone.

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_TELEGRAM_BOT_TOKEN` | *(empty)* | From @BotFather. Empty = Telegram codes are not offered. A secret: `.env` stays 0600 |
| `VEYRS_TELEGRAM_BOT_USERNAME` | *(empty)* | Shown to people enrolling, without the `@` |
| `VEYRS_TELEGRAM_API_URL` | `https://api.telegram.org` | Only for a Bot API proxy |
| `VEYRS_MFA_CODE_TTL` | `300` | Seconds, 60 to 900 |
| `VEYRS_NOTIFY_EMAIL_ENABLED` | `true` | `false` keeps notification e-mail queued (`pending`, attempts untouched) while SMTP still carries sign-in codes. For turning on a relay without releasing an old backlog |

Host commands, for the cases the console cannot cover (the installation-wide
pages need a platform administrator: `veyrs platform-admin --email <account>`):

```bash
veyrs mfa-test  --method telegram --to <chat id>      # one test message, no account changes
veyrs mfa-setup --email <account> --method telegram --chat-id <id> --recovery-file /root/rc.txt
veyrs mfa-reset --email <account> --reason "lost phone and recovery codes"
```

`mfa-setup` turns the second factor on **for** someone, typically the first
administrator. The proof is the transport accepting the message for that
destination, so a wrong chat id fails before anything changes. The recovery
codes go to a `0600` file, never to the terminal. `mfa-reset` is the last way
back in, and it is audited.

### 2.13 RADIUS sign-in (AAA)

Per organization, under **Administration → RADIUS** (`settings:admin`). Order of
checks at sign-in: local password, then the directory (if enabled), then
RADIUS. A platform superuser is never delegated.

| Setting | Notes |
|---|---|
| Servers | up to four `host` or `host:port` (default 1812/udp), tried in order **on timeout only**; a reject is an answer |
| Shared secret | at least 16 characters, encrypted at rest, never returned |
| Timeout / retries | 1-120 s / 0-3. Push approval (FortiToken Mobile, Duo) holds the answer: use 60 s |
| NAS-Identifier | sent in every request (default `veyrs`) |
| Role attribute + map | `Class` or `Filter-Id` value → role slug; empty = roles are managed in VEYRS |

On the RADIUS server, register **every app node** (its source address) as a
client with that secret, and enable Message-Authenticator. VEYRS requires it on
every answer, and FreeRADIUS before 3.2.5 needs
`require_message_authenticator = yes` in the client block to send it. The
accounts must already exist in VEYRS: their username (or e-mail) is the
`User-Name`.

An Access-Challenge becomes `401 {"error":"mfa_required","method":"radius",
"message":…,"radius_challenge":…}`. The client resends `mfa_code` with that
`radius_challenge` (random, 180 s, single use, bound to the account; kept in
Redis). PAP over UDP hides the password with MD5 and the secret only: keep
RADIUS on a management network. RadSec (TLS) is not implemented.

### 2.14 Single sign-on (OpenID Connect)

Per organization, under **Administration → Single sign-on**. Off until
configured. At the identity provider, create a **confidential** OIDC client
(authorization code, PKCE allowed) with:

| At the provider | Value |
|---|---|
| Redirect URI | `https://<console host>/api/v1/auth/oidc/callback` (the console pre-fills it; it must match exactly) |
| Scopes | `openid email profile` (+ the scope that releases the groups claim, if you map groups to roles) |
| Claims | a verified `email`; optionally `groups`; `amr` if you require multi-factor |

Then enter the issuer URL, client id and client secret in VEYRS, press **Check
the provider** (discovery, signing keys, PKCE), and turn it on. People type
their organization and press **Sign in with SSO**. Accounts are matched by
e-mail (just-in-time creation is optional). Platform administrators keep their
local password. The provider is the authority for the second factor: VEYRS
does not ask for its own after SSO.

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
| `sync-schema` | Adds columns, single-column indexes and foreign keys present in the models and missing from the database, and widens a `VARCHAR` whose model is now longer or `TEXT`. **Does not create tables**: on a database missing a release's new tables it prints `0 columns … added` and exits 0. See [DATABASE.md §5](DATABASE.md#5-schema-management). |
| `keygen` | Prints a fresh Fernet key for `VEYRS_ENCRYPTION_KEY`. |
| `bootstrap` | Creates the first organization and its administrator. `--org <slug> --name <n> --email <e>`; prompts for the password. |
| `check` | Self-test: configuration, database, Redis, CVSS/EPSS/risk engines. **Run this first** when something is wrong. |

### Intelligence

| Command | Does |
|---|---|
| `sync-nvd` | Incremental CVE pull from NVD (by `lastModified`). |
| `sync-epss` | Refresh EPSS scores; appends to `epss_history`, then trims it to `VEYRS_EPSS_HISTORY_DAYS`. |
| `prune-epss-history` | Trim `epss_history` now. `--days N` overrides the setting for this run, `--dry-run` only counts. Deletes one scored day per transaction. The freed space is reused by PostgreSQL, not returned to the filesystem (that needs `VACUUM FULL`, which locks the table). |
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
| `secrets status` | `veyrs secrets status`: the secret backend, whether the vault answers, is unsealed and accepts our credentials, and how many stored credentials of every organization are `local` / `mirror` / `vault` / `empty`, per column. Exit 1 if the configured vault is unusable. |
| `secrets migrate` | `veyrs secrets migrate --to local\|mirror\|vault [--apply] [--org SLUG]`: re-stores every registered credential in the target form. **Dry run by default** (values are read, nothing is written). A row that cannot be read is reported and left as it was — never blanked. Moving to `local` pulls the values back out of the vault. |
| `secrets gc` | `veyrs secrets gc [--apply] [--min-age-minutes 60]`: lists vault entries under the mount that no row references (a replaced credential leaves one behind) and, with `--apply`, deletes them. Also reports rows whose vault entry is missing. |

Wrapper scripts, which is what the timers run:

```
scripts/sync-intel.sh     intel-due → the due feeds → run-sla, per-feed isolated
scripts/send-digest.sh    one digest tick
scripts/backup.sh         database + secrets + documents
scripts/restore.sh        the tested counterpart
scripts/verify-release.sh check a release directory: SHA256SUMS.sig, then every SHA-256
scripts/veyrs-updater.sh  the root half of the in-product update (veyrs-updater.service)
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
| Connectors, LDAP or MFA sign-ins fail; API answers `503 secret_storage_unavailable` | `veyrs secrets status` | `VEYRS_SECRET_BACKEND=vault` and the vault is down, sealed, or refusing the AppRole; see §2.2.1 |
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
