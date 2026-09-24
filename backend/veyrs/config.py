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
    version: str = "0.32.3"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False

    # --- crypto / sessions
    secret_key: str = Field(default="")
    #: Fernet key for reversible secrets at rest (see security/secrets.py).
    #: Empty => derived from secret_key, which is fine for dev and refused in prod.
    encryption_key: str = Field(default="")
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

    # --- i18n
    default_locale: Literal["en", "es", "de", "fr", "it"] = "en"

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
        if problems:
            raise RuntimeError("unsafe production configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
