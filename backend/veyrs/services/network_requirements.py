"""Every network destination VEYRS needs -- Administration > Network access.

A firewall team asks one question before an installation goes live: "which
addresses must this host reach, on which port, and what breaks if we say no?"
This module is the single answer, in three parts:

* ``REGISTRY`` -- the fixed destinations the product itself contacts, grouped
  by WHEN they are contacted (at run time, by the updater, by the installer,
  by the scan agent). Each row says what uses it, whether it is required, the
  setting that moves or disables it, and what to do on a host that cannot
  reach it. The run-time rows are resolved against the live settings, so a
  feed pointed at an internal mirror shows the mirror, not the default.
* ``platform_endpoints()`` -- the destinations THIS installation's settings
  add: database, Redis, mail relay, secret vault, local AI endpoint.
* ``configured_endpoints()`` -- what the operator configured inside the
  organization: ticketing, scanner and asset-source connectors, AI providers
  and the directory. Only enabled ones: a disabled connector contacts nothing.

`tests/test_phase53_system_inventory.py` scans the source for URL literals and
fails if a host appears in the code that is neither in ``REGISTRY`` nor in
``DOCUMENTATION_ONLY``: a new outbound call cannot ship without a row here.

The console loads nothing from the internet (no CDN, no web fonts, no
analytics); a test holds that too, so a browser needs to reach the VEYRS
host name and nothing else.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..config import settings

GROUPS: tuple[tuple[str, str], ...] = (
    ("intelligence", "Threat intelligence feeds (run time)"),
    ("updates", "Software updates (run time)"),
    ("ai", "External AI providers (run time, off by default)"),
    ("mfa", "Two-factor delivery (run time, only if configured)"),
    ("install", "Installation and upgrade (install time only)"),
    ("agent", "Scan agent (only on a node that runs veyrs-agent)"),
)


@dataclass(frozen=True)
class Destination:
    key: str
    group: str
    hosts: tuple[str, ...]
    purpose: str
    used_by: str
    need: str                       # required | recommended | optional
    offline: str                    # what to do on a host that cannot reach it
    port: int = 443
    protocol: str = "HTTPS"
    setting: str | None = None      # VEYRS_* variable that moves or disables it
    default_url: str | None = None  # the URL in the code, for the record
    note: str | None = None
    #: ``settings`` attribute holding the URL actually used, when there is one.
    attr: str | None = field(default=None, compare=False)


REGISTRY: tuple[Destination, ...] = (
    # ---------------------------------------------------- intelligence ---
    Destination(
        "nvd", "intelligence", ("services.nvd.nist.gov",),
        "CVE records, CVSS vectors and CPE applicability (NVD API 2.0)",
        "veyrs-intel-sync.timer -> veyrs sync-nvd (hourly tick; runs when the feed is due)",
        "recommended",
        "Download the NVD 2.0 JSON elsewhere and POST it to /api/v1/intel/feeds/nvd. "
        "Without it, findings are matched against the CVEs already in the database only.",
        setting="VEYRS_NVD_API_URL", attr="nvd_api_url",
        default_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        note="Without VEYRS_NVD_API_KEY the NVD rate limit is 5 requests per 30 s; the sync is slower, not broken.",
    ),
    Destination(
        "epss", "intelligence", ("epss.empiricalsecurity.com",),
        "Daily EPSS exploitation-probability scores (the URL redirects to a dated file on the same host)",
        "veyrs-intel-sync.timer -> veyrs sync-epss",
        "recommended",
        "Download the CSV elsewhere and POST it to /api/v1/intel/feeds/epss. "
        "Without it, risk scores keep their last EPSS value.",
        setting="VEYRS_EPSS_CSV_URL", attr="epss_csv_url",
        default_url="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    ),
    Destination(
        "kev", "intelligence", ("www.cisa.gov",),
        "CISA Known Exploited Vulnerabilities catalog",
        "veyrs-intel-sync.timer -> veyrs sync-kev",
        "recommended",
        "Download the JSON elsewhere and POST it to /api/v1/intel/feeds/kev. "
        "Without it, no finding is flagged as known-exploited and KEV due dates are not applied.",
        setting="VEYRS_KEV_JSON_URL", attr="kev_json_url",
        default_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    Destination(
        "cwe", "intelligence", ("cwe.mitre.org",),
        "MITRE CWE catalog (weakness names and descriptions)",
        "veyrs-intel-sync.timer -> veyrs sync-cwe (rarely: the catalog changes a few times a year)",
        "optional",
        "Point VEYRS_CWE_CATALOG_URL at an internal copy of cwec_latest.xml.zip. "
        "Without it, CWE ids are shown without their names.",
        setting="VEYRS_CWE_CATALOG_URL", attr="cwe_catalog_url",
        default_url="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    ),
    # --------------------------------------------------------- updates ---
    Destination(
        "update-check", "updates", ("api.github.com",),
        "\"Is there a newer release?\" -- the Software update tab asks once an hour at most",
        "API (Administration > Software update)",
        "optional",
        "Set VEYRS_UPDATE_URL= (empty) to switch the check off; nothing else depends on it.",
        setting="VEYRS_UPDATE_URL", attr="update_url",
        default_url="https://api.github.com/repos/visionebc/veyrs/releases/latest",
    ),
    Destination(
        "update-download", "updates", ("github.com", "release-assets.githubusercontent.com"),
        "Release assets (SHA256SUMS, its signature, veyrs-setup.sh, the source tarball). "
        "github.com answers with a redirect to release-assets.githubusercontent.com: allow both.",
        "veyrs-updater.service (root, native installs only)",
        "optional",
        "Copy the release files to the host and update from them; see Software update.",
        setting="VEYRS_UPDATE_DOWNLOAD_BASE", attr="update_download_base",
        default_url="https://github.com/visionebc/veyrs/releases/download",
    ),
    # -------------------------------------------------------------- ai ---
    Destination(
        "ai-openai", "ai", ("api.openai.com",),
        "OpenAI models, when an AI provider of kind openai is enabled",
        "API (AI gateway)", "optional",
        "Use a local provider (Ollama or any OpenAI-compatible server on your network).",
        default_url="https://api.openai.com",
        note="Contacted only if VEYRS_AI_ALLOW_EXTERNAL=true AND the organization's AI policy allows external providers.",
    ),
    Destination(
        "ai-anthropic", "ai", ("api.anthropic.com",),
        "Anthropic models, when an AI provider of kind anthropic is enabled",
        "API (AI gateway)", "optional",
        "Use a local provider.",
        default_url="https://api.anthropic.com",
        note="Contacted only if VEYRS_AI_ALLOW_EXTERNAL=true AND the organization's AI policy allows external providers.",
    ),
    Destination(
        "ai-gemini", "ai", ("generativelanguage.googleapis.com",),
        "Google Gemini models, when an AI provider of kind gemini is enabled",
        "API (AI gateway)", "optional",
        "Use a local provider.",
        default_url="https://generativelanguage.googleapis.com",
        note="Contacted only if VEYRS_AI_ALLOW_EXTERNAL=true AND the organization's AI policy allows external providers.",
    ),
    # ------------------------------------------------------------- mfa ---
    Destination(
        "mfa-telegram", "mfa", ("api.telegram.org",),
        "Two-factor codes sent by a Telegram bot",
        "API (sign-in and two-factor enrolment)", "optional",
        "Use the authenticator app or e-mail codes. Accounts already on Telegram need a "
        "recovery code or `veyrs mfa-reset` while Telegram is unreachable.",
        setting="VEYRS_TELEGRAM_API_URL", attr="telegram_api_url",
        default_url="https://api.telegram.org",
        note="Contacted only when VEYRS_TELEGRAM_BOT_TOKEN is set. E-mail codes use the "
             "mail relay listed under this installation's own services.",
    ),
    # --------------------------------------------------------- install ---
    Destination(
        "install-release", "install", ("github.com", "release-assets.githubusercontent.com", "api.github.com"),
        "veyrs-setup.sh downloads the signed release; api.github.com only when --version is not given",
        "veyrs-setup.sh", "required",
        "Use the offline bundle (--source and --images): the installer then downloads nothing from GitHub.",
        default_url="https://github.com/visionebc/veyrs/releases/download",
    ),
    Destination(
        "install-pypi", "install", ("pypi.org", "files.pythonhosted.org"),
        "Python packages from requirements.txt (native installs: install.sh runs pip)",
        "install.sh (native mode), and every native update", "required",
        "The release's wheelhouse (veyrs-<version>-wheels-x86_64.tar.gz, used by --source/--wheels and by "
        "local updates), a pip mirror (PIP_INDEX_URL), or the Docker mode with the offline image bundle.",
        note="Not contacted in Docker mode: the packages are inside the image.",
    ),
    Destination(
        "install-os", "install", ("your distribution's package mirrors",),
        "Operating-system packages (PostgreSQL, Redis, nginx, curl, OpenSSH client, Docker on SUSE)",
        "install.sh / veyrs-setup.sh through apt, dnf or zypper", "required",
        "A local mirror or the distribution's installation media, as for any other package.",
        note="The host names are the ones in /etc/apt, /etc/yum.repos.d or /etc/zypp/repos.d, not VEYRS's.",
    ),
    Destination(
        "install-pgdg", "install", ("download.postgresql.org",),
        "PostgreSQL 15 repository on Red Hat family systems (Rocky, Alma, RHEL)",
        "install.sh (native mode, Red Hat family only)", "required",
        "Install PostgreSQL 15 from a local mirror first; install.sh then uses it.",
        default_url="https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm",
    ),
    Destination(
        "install-docker", "install", ("download.docker.com",),
        "Docker Engine and Compose on Debian, Ubuntu and Red Hat family systems (SUSE uses its own repositories)",
        "veyrs-setup.sh (Docker mode)", "required",
        "Install Docker Engine beforehand; the installer uses the one it finds.",
        default_url="https://download.docker.com/linux",
    ),
    Destination(
        "install-ghcr", "install", ("ghcr.io", "pkg-containers.githubusercontent.com"),
        "VEYRS container images (VEYRS_IMAGE_SOURCE=registry)",
        "veyrs-setup.sh / veyrs-docker (Docker mode)", "optional",
        "VEYRS_IMAGE_SOURCE=local with the offline image bundle (veyrs-images-<version>-amd64.tar.gz).",
    ),
    Destination(
        "install-dockerhub", "install", ("registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"),
        "Base images (python, nginx, postgres, redis) when images are built or pulled",
        "veyrs-setup.sh / veyrs-docker (Docker mode: build, or registry with the bundled database)", "optional",
        "The offline image bundle carries api, console, postgres and redis: nothing is pulled.",
    ),
    # ----------------------------------------------------------- agent ---
    Destination(
        "agent-console", "agent", ("the VEYRS host name (VEYRS_URL)",),
        "The agent polls for jobs and uploads results; it never accepts inbound connections",
        "veyrs-agent.service", "required",
        "None: an agent that cannot reach VEYRS cannot receive work.",
        note="Configured in /etc/veyrs-agent/agent.env.",
    ),
    Destination(
        "agent-targets", "agent", ("every target in the scan scope",),
        "The scan itself: nuclei and ZAP connect to the targets an operator schedules",
        "veyrs-agent.service", "required",
        "Scope the firewall rule to the networks you scan.",
    ),
    Destination(
        "agent-nuclei-update", "agent", ("github.com", "api.github.com"),
        "nuclei checks for engine and template updates when it runs, unless told not to "
        "(third-party behaviour, documented by ProjectDiscovery, not measured by VEYRS)",
        "nuclei, run by veyrs-agent", "optional",
        "Install templates from a local copy (nuclei -update-template-dir) and set "
        "disable-update-check: true in the agent host's nuclei config.yaml.",
        default_url="https://github.com/projectdiscovery/nuclei/releases/download",
    ),
)

#: Hosts that appear in the source only as documentation or examples -- links
#: in comments, docstrings, reference tables, sample values. VEYRS never
#: connects to them. The guard test accepts a code host only if it is here
#: or in REGISTRY.
DOCUMENTATION_ONLY: frozenset[str] = frozenset({
    "www.first.org",          # CVSS specification references in engines/cvss
    "github.com",             # links in comments / Dockerfile labels (also in REGISTRY)
    "www.nist.gov",           # framework reference (data/frameworks.py)
    "nvd.nist.gov",           # "request an API key" link printed by install.sh
    "www.iso.org", "www.cisecurity.org",
    "json.schemastore.org",
    "cloud.tenable.com",      # default base URL of the tenable_io connector: see configured_endpoints()
    "acme.atlassian.net", "site.atlassian.net", "yourteam.atlassian.net",  # examples in help text
    "raw.githubusercontent.com", "uploads.github.com",  # publish scripts (maintainer side)
    "veyrs-docs.example.com", "veyrs.example.com",  # defaults/doc links of the reference deployment
})


def _host_port(url: str | None, default_port: int = 443) -> tuple[str | None, int | None]:
    if not url:
        return None, None
    try:
        parts = urlsplit(url.replace("+psycopg", ""))
        if not parts.hostname:
            return None, None
        port = parts.port or {"https": 443, "http": 80, "postgresql": 5432,
                              "redis": 6379, "rediss": 6380, "ldaps": 636, "ldap": 389}.get(parts.scheme, default_port)
        return parts.hostname, port
    except ValueError:
        return None, None


def registry() -> list[dict]:
    """REGISTRY resolved against the live settings."""
    rows = []
    for d in REGISTRY:
        row = asdict(d)
        row["hosts"] = list(d.hosts)
        row.pop("attr", None)
        row["effective_url"] = None
        row["disabled"] = False
        if d.attr:
            url = str(getattr(settings, d.attr, "") or "")
            row["effective_url"] = url or None
            if not url.strip():
                row["disabled"] = True
            else:
                host, port = _host_port(url)
                if host and host not in d.hosts:
                    # Pointed at a mirror: the mirror IS the destination now.
                    row["hosts"] = [host]
                    row["port"] = port or d.port
                    row["moved"] = True
        if d.group == "ai":
            row["disabled"] = not settings.ai_allow_external
        if d.key == "mfa-telegram":
            row["disabled"] = not settings.telegram_bot_token
        rows.append(row)
    return rows


def platform_endpoints() -> list[dict]:
    """What this installation's own settings point at (mostly inside your network)."""
    rows: list[dict] = []

    def add(key: str, name: str, url_or_host: str | None, port: int | None, purpose: str,
            need: str, setting: str) -> None:
        if not url_or_host:
            return
        rows.append({"key": key, "name": name, "host": url_or_host, "port": port,
                     "purpose": purpose, "need": need, "setting": setting})

    host, port = _host_port(settings.database_url, 5432)
    add("database", "PostgreSQL", host, port, "all state", "required", "VEYRS_DATABASE_URL")
    host, port = _host_port(settings.redis_url, 6379)
    add("redis", "Redis", host, port, "rate limits, caches, job coordination", "required", "VEYRS_REDIS_URL")
    if settings.smtp_host:
        add("smtp", "Mail relay", settings.smtp_host, settings.smtp_port,
            "two-factor codes by e-mail" + (", notifications and digests" if settings.notify_email_enabled
                                             else " (notification e-mail is held)"),
            "optional", "VEYRS_SMTP_HOST / VEYRS_SMTP_PORT")
    if settings.secret_backend != "local" and settings.vault_addr:
        host, port = _host_port(settings.vault_addr, 8200)
        add("vault", "Secret vault", host, port, f"connector credentials (backend {settings.secret_backend})",
            "required", "VEYRS_VAULT_ADDR")
    if settings.ai_allow_local and settings.ai_local_base_url:
        host, port = _host_port(settings.ai_local_base_url, 11434)
        add("ai-local", "Local AI endpoint", host, port, "AI gateway default local model",
            "optional", "VEYRS_AI_LOCAL_BASE_URL")
    return rows


def configured_endpoints(session: Any, organization_id: uuid.UUID) -> list[dict]:
    """Enabled connectors of ONE organization. The session must be bound to it (RLS)."""
    from sqlalchemy import select

    from ..models.ai import AiProvider
    from ..models.cmdb import AssetSource
    from ..models.integration import ScannerConnector
    from ..models.ticketing import ItsmConnector

    rows: list[dict] = []
    defaults = {"tenable_io": "https://cloud.tenable.com", "openai": "https://api.openai.com",
                "anthropic": "https://api.anthropic.com", "gemini": "https://generativelanguage.googleapis.com"}

    def add(kind: str, name: str, driver: str, url: str | None, purpose: str) -> None:
        host, port = _host_port(url)
        rows.append({"kind": kind, "name": name, "driver": driver, "host": host, "port": port,
                     "purpose": purpose, "url_missing": host is None})

    for c in session.scalars(select(ItsmConnector).where(
            ItsmConnector.organization_id == organization_id, ItsmConnector.is_enabled.is_(True))):
        add("Ticketing", c.name, c.system, c.base_url, "tickets are created and synchronised there")
    for c in session.scalars(select(ScannerConnector).where(
            ScannerConnector.organization_id == organization_id, ScannerConnector.is_enabled.is_(True))):
        add("Scanner", c.name, c.driver, c.base_url or defaults.get(c.driver), "scan results are pulled from it")
    for c in session.scalars(select(AssetSource).where(
            AssetSource.organization_id == organization_id, AssetSource.is_enabled.is_(True))):
        if c.driver == "file":
            continue  # uploaded by hand: contacts nothing
        add("Asset source", c.name, c.driver, c.base_url, "assets are read from it")
    for p in session.scalars(select(AiProvider).where(
            AiProvider.organization_id == organization_id, AiProvider.is_enabled.is_(True))):
        if p.kind == "deterministic":
            continue  # built in: contacts nothing
        add("AI provider", p.name, p.kind, p.base_url or defaults.get(p.kind),
            "external AI model" if p.is_external else "AI model on your network")
    try:
        from . import oidc_auth

        ocfg = oidc_auth.config(session, organization_id)
        if ocfg.get("enabled") and ocfg.get("issuer"):
            add("Single sign-on", "OpenID Connect provider", "oidc", ocfg["issuer"],
                "discovery, signing keys and the code exchange (the browser goes there too)")
    except Exception:  # noqa: BLE001 - the SSO tab reports its own problems
        pass
    try:
        from . import radius_auth

        rcfg = radius_auth.config(session, organization_id)
        if rcfg.get("enabled"):
            for server in rcfg.get("servers") or []:
                host, port = radius_auth._split(server)
                rows.append({"kind": "RADIUS", "name": "RADIUS (UDP)", "driver": "radius",
                             "host": host, "port": port,
                             "purpose": "sign-in and its second factor (Access-Challenge)",
                             "url_missing": False})
    except Exception:  # noqa: BLE001 - the RADIUS tab reports its own problems
        pass
    try:
        from . import ldap_auth

        cfg = ldap_auth.config(session, organization_id)
        if cfg.get("enabled") and cfg.get("host"):
            rows.append({"kind": "Directory", "name": "LDAP / Active Directory", "driver": "ldap",
                         "host": str(cfg["host"]), "port": int(cfg.get("port") or 636),
                         "purpose": "sign-in and team import", "url_missing": False})
    except Exception:  # noqa: BLE001 - the page lists what it can; the directory has its own tab
        pass
    return rows


def overview(session: Any, organization_id: uuid.UUID) -> dict:
    return {
        "groups": [{"key": k, "label": label} for k, label in GROUPS],
        "destinations": registry(),
        "platform": platform_endpoints(),
        "configured": configured_endpoints(session, organization_id),
        "browser": ("The console loads nothing from the internet: no CDN, web font or analytics. "
                    "A browser only needs to reach the VEYRS host name."),
        "inbound": ("Inbound, users and agents reach VEYRS on 443 (or the port in VEYRS_HTTP_BIND); "
                    "VEYRS needs no other inbound port."),
    }
