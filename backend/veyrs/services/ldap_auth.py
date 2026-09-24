"""Directory authentication: LDAP and Active Directory.

VEYRS owns accounts. It does not want to own passwords for an estate that
already has a directory, because every password it stores is one more place a
leaver keeps working after HR closed their account. This module lets a tenant
delegate the credential check to LDAP/AD while VEYRS keeps what it is actually
authoritative about: roles, team scope and the audit trail.

Bind mode: service account + search. There is only one.
-----------------------------------------------------
Two shapes are common. The one implemented here binds as a read-only service
account, searches for the person by their account name, and then re-binds as
the DN it found using the password that was typed. The other -- *direct bind*,
where the username is pasted into a template like ``DOMAIN\\{user}`` and bound
straight away -- needs no service account, and that is its whole advantage.

Direct bind was refused because it cannot read anything. No ``mail``, no
``displayName``, no ``memberOf``. A platform that cannot read group membership
cannot map a directory group to a VEYRS role, and one that cannot read an
address cannot provision an account that notifications will ever reach. It
would authenticate people into an estate it could tell you nothing about, and
the operator would then maintain every attribute by hand -- which is the work
they turned on a directory to stop doing.

What is deliberately NOT delegated
----------------------------------
``is_superuser``. A local platform superuser is never authenticated against the
directory, at any point, under any configuration. The entire failure mode this
module has to survive is *a bad directory configuration*: a wrong base DN, an
expired service-account password, a firewall rule added on a Friday. If the one
account that can open Administration -> Directory and fix it also depends on
the directory, the deployment locks its own operator out of the repair.

Authorization stays local for the same class of reason. A directory says who
someone is; it does not get to say what they may do in VEYRS. Group mapping
(``group_role_map``) is an explicit, operator-written translation from a group
the directory knows to a role VEYRS knows -- never an implicit trust that a
name matching a role slug should grant it.

Provisioning is OFF by default
------------------------------
With ``jit_provisioning`` on, the first successful directory login creates the
VEYRS account. That is genuinely useful and it is genuinely dangerous: every
person in the domain -- contractors, service desks, the intern -- can then sign
in to the platform that holds the estate's unpatched vulnerabilities. So it
ships off, and when it is on, ``default_role_slugs`` decides what a newly
created person gets. That default is empty, which is an account that can log in
and read nothing, on purpose.

The library is imported lazily
------------------------------
``ldap3`` is only imported inside the two functions that actually talk to a
directory. Reading and writing the configuration, redacting it for display and
validating it are pure Python. That means an upgrade which lands this code
before the dependency is installed still boots, still serves every other route,
and reports one clear error on the Directory page instead of failing at import
and taking the whole API with it.
"""
from __future__ import annotations

import datetime as dt
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.tenancy import Organization
from ..security import secrets

log = logging.getLogger("veyrs.ldap")

#: Key under ``organizations.settings``, alongside ``scanning`` (phase 34).
SETTINGS_KEY = "ldap"

#: Default when the key is absent. Off: a platform does not start delegating
#: authentication because it was upgraded.
DEFAULT_ENABLED = False

#: Attribute placeholder accepted in ``user_filter``.
FILTER_PLACEHOLDER = "{username}"

#: Shipped filter. Matches Active Directory's account name, and excludes
#: computer accounts -- ``objectClass=user`` alone matches every workstation in
#: the domain, and a workstation that can bind is an account that can log in.
DEFAULT_USER_FILTER = "(&(objectClass=user)(objectCategory=person)({attr}={username}))"

#: OpenLDAP equivalent, offered in the console as the other preset.
POSIX_USER_FILTER = "(&(objectClass=inetOrgPerson)({attr}={username}))"

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "host": "",
    "port": 636,
    "use_ssl": True,
    "start_tls": False,
    "verify_certificate": True,
    "timeout_seconds": 8,
    "bind_dn": "",
    "base_dn": "",
    "user_filter": DEFAULT_USER_FILTER,
    "attr_username": "sAMAccountName",
    "attr_email": "mail",
    "attr_full_name": "displayName",
    "attr_member_of": "memberOf",
    "group_role_map": {},
    # --- group enumeration, for importing teams. Read-only and separate from
    # authentication on purpose: a deployment may want the group list without
    # ever letting the directory decide who may sign in, and the reverse.
    "group_base_dn": "",          # empty = base_dn
    "group_filter": "(objectClass=group)",
    "attr_group_name": "cn",
    "attr_group_description": "description",
    "attr_group_mail": "mail",
    "jit_provisioning": False,
    "default_role_slugs": [],
    "sync_roles_on_login": True,
}

#: Never leaves the process in a response body.
SECRET_FIELD = "bind_password_enc"


class LdapError(RuntimeError):
    """Configuration is unusable, or the directory could not be reached.

    Distinct from "those credentials are wrong", which is not an error here --
    it is a ``None`` return. Conflating the two turns an unreachable server into
    a wave of "invalid credentials" and sends the operator hunting for a
    password problem that does not exist.
    """


#: Ceiling on one group enumeration. A directory with more groups than this is
#: real; discovering it inside a request that then writes a team per row is
#: not. The cap reports itself rather than truncating in silence.
MAX_GROUPS = 500
MAX_GROUP_MEMBERS = 2000


class LdapNotInstalled(LdapError):
    """`ldap3` is not installed on this node."""


@dataclass
class LdapIdentity:
    """One person, as the directory describes them."""

    dn: str
    username: str
    email: str | None = None
    full_name: str | None = None
    groups: list[str] = field(default_factory=list)


# --- configuration --------------------------------------------------------


def _block(organization: Organization | None) -> dict[str, Any]:
    settings = (organization.settings or {}) if organization is not None else {}
    block = settings.get(SETTINGS_KEY)
    return dict(block) if isinstance(block, dict) else {}


def config(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The full configuration INCLUDING the encrypted bind password.

    Internal use only -- `authenticate` and `test_connection` need to decrypt
    it. Anything that answers an HTTP request wants `state()`.
    """
    organization = session.get(Organization, organization_id)
    merged = dict(DEFAULTS)
    merged.update(_block(organization))
    return merged


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The configuration as the console may see it: no password, ever.

    The stored value is Fernet ciphertext, so echoing it back would not leak
    the password directly -- but it would leak that the ciphertext exists and
    hand an attacker with read access to one response something to replay into
    the PUT. `bind_password_set` answers the only question the UI actually has.
    """
    merged = config(session, organization_id)
    merged.pop(SECRET_FIELD, None)
    merged["bind_password_set"] = bool(_block(session.get(Organization, organization_id)).get(SECRET_FIELD))
    merged["explicit"] = "enabled" in _block(session.get(Organization, organization_id))
    merged["library_available"] = library_available()
    return merged


def library_available() -> bool:
    """Whether `ldap3` can be imported on this node."""
    try:
        import ldap3  # noqa: F401
    except ImportError:
        return False
    return True


def is_enabled(session: Session, organization_id: uuid.UUID) -> bool:
    """Enabled AND actually configured.

    A half-filled form is not a directory. Returning True for `enabled` with an
    empty host would send every login through a code path that can only fail,
    and the operator would read the result as "LDAP is broken" rather than
    "LDAP was never finished".
    """
    cfg = config(session, organization_id)
    return bool(cfg.get("enabled")) and bool(cfg.get("host")) and bool(cfg.get("base_dn"))


def enabled_organization_ids(session: Session) -> list[uuid.UUID]:
    """Every tenant with a usable directory. Used to resolve JIT provisioning."""
    rows = session.execute(select(Organization)).scalars().all()
    out = []
    for org in rows:
        cfg = dict(DEFAULTS)
        cfg.update(_block(org))
        if cfg.get("enabled") and cfg.get("host") and cfg.get("base_dn"):
            out.append(org.id)
    return out


def validate(payload: dict[str, Any]) -> list[str]:
    """Everything wrong with a proposed configuration, as plain sentences.

    Returned rather than raised so the console can show all of them at once.
    An operator fixing a directory one 422 at a time is an operator who gives
    up on the fourth round trip.
    """
    problems: list[str] = []
    enabled = bool(payload.get("enabled"))

    host = (payload.get("host") or "").strip()
    if enabled and not host:
        problems.append("a directory host is required to enable directory authentication")
    if host and re.search(r"[\s/\\]", host):
        problems.append("the host must be a hostname or IP address, not a URL")

    port = payload.get("port", 636)
    if not isinstance(port, int) or not (1 <= port <= 65535):
        problems.append("port must be between 1 and 65535")

    if payload.get("use_ssl") and payload.get("start_tls"):
        problems.append(
            "use LDAPS or StartTLS, not both: StartTLS upgrades a plaintext "
            "connection, and there is nothing to upgrade inside an SSL one"
        )
    if enabled and not payload.get("use_ssl") and not payload.get("start_tls"):
        # A warning phrased as a problem on purpose. A bind sends the password
        # in the clear; that is worth one deliberate confirmation.
        problems.append(
            "refusing to enable an unencrypted directory connection: a simple "
            "bind sends the password in cleartext. Enable LDAPS (port 636) or "
            "StartTLS (port 389)"
        )

    base_dn = (payload.get("base_dn") or "").strip()
    if enabled and not base_dn:
        problems.append("a search base DN is required")
    if base_dn and "=" not in base_dn:
        problems.append("the base DN does not look like a DN (expected something like DC=corp,DC=local)")

    bind_dn = (payload.get("bind_dn") or "").strip()
    if enabled and not bind_dn:
        problems.append(
            "a service-account DN is required: VEYRS searches for the person "
            "before binding as them, and an anonymous search returns nothing on "
            "a default Active Directory"
        )

    user_filter = payload.get("user_filter") or ""
    if FILTER_PLACEHOLDER not in user_filter:
        problems.append(f"the user filter must contain {FILTER_PLACEHOLDER}")
    if user_filter.count("(") != user_filter.count(")"):
        problems.append("the user filter has unbalanced parentheses")

    timeout = payload.get("timeout_seconds", 8)
    if not isinstance(timeout, int) or not (1 <= timeout <= 60):
        problems.append("the timeout must be between 1 and 60 seconds")

    mapping = payload.get("group_role_map") or {}
    if not isinstance(mapping, dict):
        problems.append("the group mapping must be an object of group -> role slug")
    elif len(mapping) > 100:
        problems.append("at most 100 group mappings")

    if payload.get("jit_provisioning") and not payload.get("enabled"):
        problems.append("just-in-time provisioning requires directory authentication to be enabled")

    return problems


def set_config(
    session: Session,
    organization_id: uuid.UUID,
    payload: dict[str, Any],
    *,
    bind_password: str | None = None,
    clear_bind_password: bool = False,
    actor_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Write the configuration. Returns the redacted state.

    `bind_password` is optional and absent means *leave the stored one alone*.
    A form that has to re-send the password on every save is a form that will
    eventually be saved with the masked placeholder in it, and the operator
    will discover this the next time somebody tries to log in.
    """
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError("organization not found")

    block = _block(organization)
    existing_secret = block.get(SECRET_FIELD)

    merged = dict(DEFAULTS)
    merged.update(block)
    for key in DEFAULTS:
        if key in payload:
            merged[key] = payload[key]

    problems = validate(merged)
    if problems:
        raise ValueError("; ".join(problems))

    merged["group_role_map"] = {
        str(k).strip().lower(): str(v).strip()
        for k, v in (merged.get("group_role_map") or {}).items()
        if str(k).strip() and str(v).strip()
    }
    merged["default_role_slugs"] = sorted({
        str(s).strip() for s in (merged.get("default_role_slugs") or []) if str(s).strip()
    })

    if clear_bind_password:
        merged[SECRET_FIELD] = None
    elif bind_password:
        merged[SECRET_FIELD] = secrets.encrypt(bind_password)
    elif existing_secret:
        merged[SECRET_FIELD] = existing_secret

    merged["changed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    merged["changed_by_id"] = str(actor_id) if actor_id else None

    # Reassign rather than mutate: SQLAlchemy does not track in-place mutation
    # of a plain dict inside JSONB, and an in-place update is a write that
    # silently does not happen (the lesson `scanning.set_enabled` records).
    settings = dict(organization.settings or {})
    settings[SETTINGS_KEY] = merged
    organization.settings = settings
    session.flush()
    return state(session, organization_id)


# --- talking to the directory ---------------------------------------------


def _escape(value: str) -> str:
    """RFC 4515 escaping for a value going into a search filter.

    Without this, an identifier of `*` matches every account in the base DN and
    the first entry returned is whoever the directory felt like listing. The
    typed identifier is attacker-controlled by definition -- it is the one field
    on the sign-in page that anyone on the network can fill in.
    """
    from ldap3.utils.conv import escape_filter_chars

    return escape_filter_chars(value)


def _build_filter(cfg: dict[str, Any], identifier: str) -> str:
    template = cfg.get("user_filter") or DEFAULT_USER_FILTER
    return (
        template
        .replace("{attr}", cfg.get("attr_username") or "sAMAccountName")
        .replace(FILTER_PLACEHOLDER, _escape(identifier))
    )


def _connect(cfg: dict[str, Any], *, user: str | None, password: str | None):
    """Bind and return an open connection. Raises `LdapError` on anything else."""
    try:
        import ssl

        from ldap3 import ALL, SIMPLE, Connection, Server, Tls
        from ldap3.core.exceptions import LDAPException
    except ImportError as exc:  # pragma: no cover - depends on the node
        raise LdapNotInstalled(
            "the `ldap3` package is not installed on this node, so directory "
            "authentication cannot run; install it and restart the API"
        ) from exc

    timeout = int(cfg.get("timeout_seconds") or 8)
    tls = None
    if cfg.get("use_ssl") or cfg.get("start_tls"):
        tls = Tls(
            validate=ssl.CERT_REQUIRED if cfg.get("verify_certificate", True) else ssl.CERT_NONE
        )

    server = Server(
        cfg["host"],
        port=int(cfg.get("port") or 636),
        use_ssl=bool(cfg.get("use_ssl")),
        get_info=ALL,
        connect_timeout=timeout,
        tls=tls,
    )
    try:
        conn = Connection(
            server,
            user=user or None,
            password=password or None,
            authentication=SIMPLE if user else None,
            auto_bind=False,
            receive_timeout=timeout,
            raise_exceptions=False,
        )
        if not conn.open():
            raise LdapError(f"cannot reach the directory at {cfg['host']}:{cfg.get('port')}")
        if cfg.get("start_tls") and not conn.start_tls():
            raise LdapError(f"StartTLS was refused: {conn.result}")
        if not conn.bind():
            # Deliberately NOT an LdapError when this is the person's own
            # re-bind: the caller decides. Here it means the SERVICE account
            # failed, which is a configuration fault and not a user's problem.
            raise LdapError(f"bind failed: {conn.result.get('description') if conn.result else 'unknown'}")
        return conn
    except LDAPException as exc:
        raise LdapError(f"directory error: {exc}") from exc


def _first(entry: Any, attribute: str) -> str | None:
    """One attribute value as a string, whatever shape ldap3 returned it in."""
    if not attribute:
        return None
    try:
        raw = entry[attribute].value
    except (KeyError, LookupError, TypeError):
        return None
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(raw).strip() or None


def _all(entry: Any, attribute: str) -> list[str]:
    if not attribute:
        return []
    try:
        raw = entry[attribute].values
    except (KeyError, LookupError, TypeError):
        return []
    out = []
    for item in raw or []:
        if isinstance(item, bytes):
            item = item.decode("utf-8", "replace")
        item = str(item).strip()
        if item:
            out.append(item)
    return out


def find(session: Session, organization_id: uuid.UUID, identifier: str) -> LdapIdentity | None:
    """Look somebody up WITHOUT checking their password.

    Split out from `authenticate` so `test_connection` can prove a filter finds
    the right person without needing that person's password, which is the thing
    an operator actually wants to verify while configuring this.
    """
    cfg = config(session, organization_id)
    if not cfg.get("host") or not cfg.get("base_dn"):
        raise LdapError("the directory is not configured")

    bind_password = secrets.try_decrypt(cfg.get(SECRET_FIELD))
    conn = _connect(cfg, user=cfg.get("bind_dn"), password=bind_password)
    try:
        from ldap3 import SUBTREE

        attributes = [
            a for a in (
                cfg.get("attr_username"),
                cfg.get("attr_email"),
                cfg.get("attr_full_name"),
                cfg.get("attr_member_of"),
            ) if a
        ]
        ok = conn.search(
            search_base=cfg["base_dn"],
            search_filter=_build_filter(cfg, identifier),
            search_scope=SUBTREE,
            attributes=attributes,
            size_limit=2,
        )
        if not ok or not conn.entries:
            return None
        if len(conn.entries) > 1:
            # Two entries for one account name is a broken directory or a
            # filter that is too loose. Picking the first would authenticate
            # somebody as whichever row the server happened to return first.
            raise LdapError(
                f"the filter matched {len(conn.entries)} entries for that "
                "identifier; narrow the search base or the user filter"
            )
        entry = conn.entries[0]
        return LdapIdentity(
            dn=str(entry.entry_dn),
            username=(_first(entry, cfg.get("attr_username")) or identifier).lower(),
            email=(_first(entry, cfg.get("attr_email")) or "").lower() or None,
            full_name=_first(entry, cfg.get("attr_full_name")),
            groups=_all(entry, cfg.get("attr_member_of")),
        )
    finally:
        try:
            conn.unbind()
        except Exception:  # pragma: no cover - best effort teardown
            pass


@dataclass(frozen=True)
class LdapGroup:
    """One directory group, as a candidate team."""

    dn: str
    name: str
    description: str | None = None
    email: str | None = None
    #: Usernames, NOT DNs. Resolved by asking the directory which accounts are
    #: in the group and reading each one's login attribute -- the same
    #: attribute VEYRS stores in `users.username`, so the two can be matched
    #: without guessing. Empty when membership was not requested.
    member_usernames: tuple[str, ...] = ()
    truncated: bool = False


def groups(
    session: Session, organization_id: uuid.UUID, *, with_members: bool = False
) -> list[LdapGroup]:
    """Every group under the configured group base. Writes nothing.

    Deliberately NOT filtered by `group_role_map`: that map says which groups
    grant a ROLE, and a team is not a role. An estate routinely has teams
    nobody signs in as.
    """
    cfg = config(session, organization_id)
    if not cfg.get("host") or not cfg.get("base_dn"):
        raise LdapError("the directory is not configured")

    base = (cfg.get("group_base_dn") or "").strip() or cfg["base_dn"]
    name_attr = cfg.get("attr_group_name") or "cn"
    desc_attr = cfg.get("attr_group_description") or "description"
    mail_attr = cfg.get("attr_group_mail") or "mail"
    user_attr = cfg.get("attr_username") or "sAMAccountName"

    bind_password = secrets.try_decrypt(cfg.get(SECRET_FIELD))
    conn = _connect(cfg, user=cfg.get("bind_dn"), password=bind_password)
    try:
        from ldap3 import SUBTREE

        ok = conn.search(
            search_base=base,
            search_filter=cfg.get("group_filter") or "(objectClass=group)",
            search_scope=SUBTREE,
            attributes=[a for a in (name_attr, desc_attr, mail_attr) if a],
            size_limit=MAX_GROUPS + 1,
        )
        if not ok:
            raise LdapError(
                f"the group search was refused: "
                f"{conn.result.get('description') if conn.result else 'unknown'}"
            )
        entries = list(conn.entries)
        truncated = len(entries) > MAX_GROUPS
        out: list[LdapGroup] = []
        for entry in entries[:MAX_GROUPS]:
            dn = str(entry.entry_dn)
            name = _first(entry, name_attr) or _group_cn(dn)
            if not name:
                continue
            members: tuple[str, ...] = ()
            if with_members:
                members = tuple(_members_of(conn, cfg, dn, user_attr))
            out.append(LdapGroup(
                dn=dn,
                name=name,
                description=_first(entry, desc_attr),
                email=(_first(entry, mail_attr) or "").lower() or None,
                member_usernames=members,
                truncated=truncated,
            ))
        return out
    finally:
        try:
            conn.unbind()
        except Exception:  # pragma: no cover - best effort teardown
            pass


def _group_cn(dn: str) -> str | None:
    match = re.match(r"^\s*cn\s*=\s*([^,]+)", dn, flags=re.IGNORECASE)
    return match.group(1).strip() if match else None


def _members_of(conn: Any, cfg: dict[str, Any], group_dn: str,
                user_attr: str) -> list[str]:
    """Who is in this group, asked of the directory rather than parsed out of it.

    Reading the group's own `member` attribute gives DNs, and turning a DN back
    into a VEYRS account means guessing which part of it is the login name.
    Searching for accounts whose `memberOf` is this group returns the login
    attribute itself -- the same one `users.username` holds.
    """
    from ldap3 import SUBTREE

    try:
        ok = conn.search(
            search_base=cfg["base_dn"],
            search_filter=f"(memberOf={_escape(group_dn)})",
            search_scope=SUBTREE,
            attributes=[user_attr],
            size_limit=MAX_GROUP_MEMBERS,
        )
    except Exception as exc:  # pragma: no cover - server-dependent
        log.warning("ldap: member search failed for %s: %s", group_dn, exc)
        return []
    if not ok:
        return []
    out: list[str] = []
    for entry in conn.entries:
        name = _first(entry, user_attr)
        if name and name.lower() not in out:
            out.append(name.lower())
    return out


def authenticate(
    session: Session, organization_id: uuid.UUID, identifier: str, password: str
) -> LdapIdentity | None:
    """Search, then re-bind as the person found. `None` = wrong credentials.

    An empty password is refused before it reaches the wire. RFC 4513 says a
    simple bind with an empty password is an *unauthenticated* bind, and most
    servers answer it with success -- so passing one through would turn "the
    user left the password box empty" into a valid login.
    """
    if not password:
        return None

    identity = find(session, organization_id, identifier)
    if identity is None:
        return None

    cfg = config(session, organization_id)
    try:
        conn = _connect(cfg, user=identity.dn, password=password)
    except LdapError:
        # `_connect` raises on a failed bind, and at this point a failed bind is
        # the ordinary "wrong password" answer rather than a fault. Reachability
        # was already proven by the search that produced `identity`.
        return None
    try:
        return identity
    finally:
        try:
            conn.unbind()
        except Exception:  # pragma: no cover
            pass


def test_connection(
    session: Session, organization_id: uuid.UUID, *, sample_identifier: str | None = None
) -> dict[str, Any]:
    """Step-by-step diagnosis for the Directory page.

    Every step is reported with its own outcome instead of collapsing into one
    boolean, because "it does not work" has at least five distinct causes here
    -- unreachable, TLS rejected, service account wrong, base DN wrong, filter
    wrong -- and they need five different fixes.
    """
    steps: list[dict[str, Any]] = []

    def step(name: str, ok: bool, detail: str = "") -> None:
        steps.append({"step": name, "ok": ok, "detail": detail})

    cfg = config(session, organization_id)
    if not library_available():
        step("library", False, "the `ldap3` package is not installed on this node")
        return {"ok": False, "steps": steps}
    step("library", True, "ldap3 available")

    problems = validate(cfg)
    if problems:
        step("configuration", False, "; ".join(problems))
        return {"ok": False, "steps": steps}
    step("configuration", True, "settings are internally consistent")

    bind_password = secrets.try_decrypt(cfg.get(SECRET_FIELD))
    if cfg.get(SECRET_FIELD) and bind_password is None:
        # Ciphertext that will not decrypt: the encryption key was rotated
        # under a stored value. Saying "bind failed" here would send the
        # operator to reset a service-account password that is perfectly fine.
        step("bind", False,
             "the stored service-account password cannot be decrypted with the "
             "current VEYRS_ENCRYPTION_KEY; re-enter it")
        return {"ok": False, "steps": steps}

    try:
        conn = _connect(cfg, user=cfg.get("bind_dn"), password=bind_password)
    except LdapError as exc:
        step("bind", False, str(exc))
        return {"ok": False, "steps": steps}
    step("bind", True, f"bound as {cfg.get('bind_dn')}")

    try:
        from ldap3 import SUBTREE

        ok = conn.search(
            search_base=cfg["base_dn"],
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=[],
            size_limit=1,
        )
        if not ok and not conn.entries:
            step("search base", False,
                 f"the base DN returned nothing: {conn.result.get('description') if conn.result else ''}")
            return {"ok": False, "steps": steps}
        step("search base", True, f"{cfg['base_dn']} is readable")
    finally:
        try:
            conn.unbind()
        except Exception:  # pragma: no cover
            pass

    if sample_identifier:
        try:
            identity = find(session, organization_id, sample_identifier)
        except LdapError as exc:
            step("user lookup", False, str(exc))
            return {"ok": False, "steps": steps}
        if identity is None:
            step("user lookup", False, f"the filter found nobody matching '{sample_identifier}'")
            return {"ok": False, "steps": steps}
        step("user lookup", True,
             f"found {identity.dn} (email {identity.email or 'not set'}, "
             f"{len(identity.groups)} groups)")

    return {"ok": True, "steps": steps}


# --- mapping the directory onto VEYRS -------------------------------------


def _group_keys(group: str) -> set[str]:
    """The forms a group may be written as in `group_role_map`.

    An operator reads `CN=SOC Analysts,OU=Groups,DC=corp,DC=local` off a screen
    and types `SOC Analysts`, because that is the name the group has. Matching
    only on the full DN makes a correct-looking mapping do nothing, silently,
    and the symptom is a person who logs in with no roles.
    """
    keys = {group.strip().lower()}
    match = re.match(r"^\s*cn\s*=\s*([^,]+)", group, flags=re.IGNORECASE)
    if match:
        keys.add(match.group(1).strip().lower())
    return {k for k in keys if k}


def roles_for(cfg: dict[str, Any], identity: LdapIdentity) -> list[str]:
    """Role slugs this identity's groups map to, plus the configured defaults.

    A group that maps to nothing contributes nothing. There is no fallback that
    grants a role because a group's name resembles it: an accidental match on
    something like `org-admin` is not a mistake anyone would catch by reading
    the screen afterwards.
    """
    mapping = cfg.get("group_role_map") or {}
    slugs = {str(s) for s in (cfg.get("default_role_slugs") or [])}
    for group in identity.groups:
        for key in _group_keys(group):
            if key in mapping:
                slugs.add(str(mapping[key]))
    return sorted(s for s in slugs if s)
