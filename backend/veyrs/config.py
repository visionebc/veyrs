"""VEYRS runtime configuration.

Everything is environment-driven (12-factor); `.env` is read for local runs.
Secrets never carry a usable default - an unset VEYRS_SECRET_KEY in a non-debug
process is a hard startup failure rather than a silent fallback.
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VEYRS_", env_file=".env", extra="ignore", case_sensitive=False
    )

    # --- identity
    app_name: str = "VEYRS"
    tagline: str = "Unified Cybersecurity Risk Management"
    version: str = "0.35.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False

    # --- crypto / sessions
    secret_key: str = Field(default="")
    #: Fernet key for reversible secrets at rest (see security/secrets.py).
    #: Empty => derived from secret_key, which is fine for dev and refused in prod.
    encryption_key: str = Field(default="")
    #: Where reversible secrets live (security/secret_vault.py). `local` keeps
    #: them in the database under the Fernet key above and never contacts a
    #: vault; `mirror` writes both and reads the vault first; `vault` keeps the
    #: vault as the only copy. The vault's own settings below are deliberately
    #: environment-only: storing them in the database, encrypted by the very key
    #: this exists to take off the host, would protect nothing.
    secret_backend: Literal["local", "mirror", "vault"] = "local"
    vault_addr: str = ""
    vault_mount: str = "veyrs"
    vault_auth: Literal["approle", "token"] = "approle"
    vault_role_id: str = ""
    #: Paths to 0600 files, never the values: an environment variable is
    #: readable in /proc/<pid>/environ and in every `docker inspect`.
    vault_secret_id_file: str = ""
    vault_token_file: str = ""
    vault_ca_file: str = ""
    vault_namespace: str = ""
    vault_timeout: float = 5.0
    access_token_minutes: int = 30
    refresh_token_days: int = 14
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    password_min_length: int = 12

    # --- storage
    database_url: str = "postgresql+psycopg://veyrs:veyrs@127.0.0.1:5432/veyrs"
    redis_url: str = "redis://127.0.0.1:6379/0"

    # --- api surface
    api_prefix: str = "/api/v1"
    cors_origins: str = "https://veyrs-docs.example.com"
    rate_limit_per_minute: int = 240
    #: Strict budget for /auth/* , keyed per source IP. Deliberately separate:
    #: this is credential-stuffing defence and must bite long before the
    #: general limit. Raise it for offices that egress behind one NAT address,
    #: where 50 analysts signing in at 09:00 legitimately exceed the default.
    auth_rate_limit_per_minute: int = 10
    #: Honour X-Forwarded-For. Only enable when a proxy you control sets it;
    #: otherwise any caller can mint a fresh rate-limit identity per request.
    trust_proxy_headers: bool = False
    max_upload_mb: int = 32
    #: Bearer token required to read /metrics. Unset means the endpoint is open
    #: in development and refused outright in production - the exposition maps
    #: the whole API surface, so it is not public data.
    metrics_token: str = ""

    # --- intelligence feeds (all optional; the platform degrades, never breaks)
    nvd_api_key: str = ""
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    epss_csv_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    kev_json_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    cwe_catalog_url: str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    feed_http_timeout: int = 60
    #: Days of daily EPSS snapshots kept in `epss_history`, counted back from
    #: the newest scored day (not from today). A scored day is ~370,000 rows,
    #: about 80 MB: unpruned, the table grew ~30 GB a year. 0 keeps everything.
    epss_history_days: int = Field(default=365, ge=0)

    # --- AI gateway
    ai_allow_external: bool = False
    ai_allow_local: bool = True
    ai_local_base_url: str = "http://10.50.0.50:11434"
    ai_local_model: str = "qwen3:32b"
    ai_max_data_classification: Literal["public", "internal", "confidential", "restricted"] = (
        "internal"
    )

    # --- notifications
    smtp_host: str = ""
    smtp_port: int = 25
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "veyrs@example.com"
    smtp_starttls: bool = True
    public_base_url: str = "https://veyrs-docs.example.com"
    #: False holds every e-mail NOTIFICATION in the queue (it stays `pending`)
    #: while SMTP still carries two-factor codes. For turning on sign-in codes
    #: without releasing a backlog of old notifications in the same minute.
    notify_email_enabled: bool = True

    # --- two-factor delivery (security/mfa_delivery.py)
    #: A Telegram bot token (from @BotFather). Empty = Telegram codes are not offered.
    telegram_bot_token: str = ""
    telegram_api_url: str = "https://api.telegram.org"
    #: Shown in the console so people know which bot to open (e.g. VeyrsBot).
    telegram_bot_username: str = ""
    #: Lifetime of an e-mail / Telegram code, in seconds.
    mfa_code_ttl: int = Field(default=300, ge=60, le=900)

    # --- i18n
    default_locale: Literal["en", "es", "de", "fr", "it"] = "en"

    # --- software updates (services/updates.py, scripts/veyrs-updater.sh)
    #: Where the "is there a newer release?" check asks. EMPTY disables every
    #: network check -- the setting for an air-gapped installation.
    update_url: str = "https://api.github.com/repos/visionebc/veyrs/releases/latest"
    #: Base the root updater downloads release assets from (`<base>/v<X.Y.Z>/<asset>`).
    update_download_base: str = "https://github.com/visionebc/veyrs/releases/download"
    #: The API only WRITES a request here; the root `veyrs-updater.path` unit acts on it.
    update_spool: str = "/var/lib/veyrs/update-requests"
    #: A directory the root updater may install a release FROM (a USB disk, an
    #: NFS share): <dir>/v<X.Y.Z>/, <dir>/veyrs-<X.Y.Z>/ or the files in <dir>/.
    #: Empty = off. Not under /home or /root: the API cannot read those.
    update_local_dir: str = ""
    #: Where console uploads are staged. Empty = <install>/var/update-uploads,
    #: the one directory the API may write.
    update_upload_dir: str = ""
    #: Where the updater leaves one JSON per run (steps, outcome) for the console.
    update_status_dir: str = "/var/lib/veyrs/update-status"
    #: Command the updater runs before touching anything (e.g. scripts/backup.sh).
    #: Without it, or `update_skip_backup`, the updater refuses to update.
    update_pre_hook: str = ""
    update_skip_backup: bool = False
    #: `git` | `docker` | `native`; empty = detected. A `.git` in the install
    #: root always wins: that tree is managed by a git deploy, never self-updated.
    install_mode: str = ""

    @field_validator("secret_key")
    @classmethod
    def _require_secret(cls, value: str) -> str:
        if value:
            if len(value) < 32:
                raise ValueError("VEYRS_SECRET_KEY must be at least 32 characters")
            return value
        # Ephemeral key: fine for tests, fatal for anything that must survive a
        # restart. `validate()` below refuses to let production boot like this.
        return secrets.token_urlsafe(48)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def vault_problems(self, *, production: bool = False) -> list[str]:
        """What stops the configured secret backend from working, or [].

        Empty in `local` mode whatever the VEYRS_VAULT_* values say: local mode
        never contacts a vault, so a half-written vault block is not a fault yet.
        In `mirror` and `vault` mode an incomplete block is a credential nobody
        can store -- refused at boot in production rather than at the first
        connector save, which is where it would otherwise surface.
        """
        if self.secret_backend == "local":
            return []
        mode = f"secret_backend={self.secret_backend}"
        problems: list[str] = []
        addr = (self.vault_addr or "").strip()
        if not addr:
            problems.append(f"{mode} needs vault_addr")
        elif not addr.startswith(("https://", "http://")):
            problems.append("vault_addr must be an http(s) URL")
        elif production and not addr.startswith("https://"):
            # The token and every credential cross this link in clear otherwise.
            problems.append("vault_addr must be https in production")
        if not (self.vault_mount or "").strip("/"):
            problems.append(f"{mode} needs vault_mount")
        if self.vault_auth == "approle":
            if not self.vault_role_id:
                problems.append(f"{mode} with vault_auth=approle needs vault_role_id")
            if not self.vault_secret_id_file:
                problems.append(f"{mode} with vault_auth=approle needs vault_secret_id_file")
        elif not self.vault_token_file:
            problems.append(f"{mode} with vault_auth=token needs vault_token_file")
        if production:
            import os

            for name in ("vault_secret_id_file", "vault_token_file", "vault_ca_file"):
                path = getattr(self, name)
                if not path:
                    continue
                if name == "vault_token_file" and self.vault_auth != "token":
                    continue
                if name == "vault_secret_id_file" and self.vault_auth != "approle":
                    continue
                if not os.path.isfile(path):
                    problems.append(f"{name} {path} does not exist")
        return problems

    def assert_production_safe(self) -> None:
        problems = []
        if self.debug:
            problems.append("debug must be off in production")
        if "veyrs:veyrs@" in self.database_url:
            problems.append("database_url still carries the bootstrap password")
        if not self.public_base_url.startswith("https://"):
            problems.append("public_base_url must be https")
        if not self.encryption_key:
            # Derived keys are tied to secret_key: rotating the session secret
            # would silently orphan every stored third-party credential.
            problems.append("encryption_key must be set explicitly (run: veyrs keygen)")
        problems.extend(self.vault_problems(production=True))
        if problems:
            raise RuntimeError("unsafe production configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
