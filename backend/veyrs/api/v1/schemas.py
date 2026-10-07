"""Request/response models for the v1 API.

Rules applied throughout:
  * Response models never expose password hashes, key hashes or MFA secrets.
  * Every list endpoint returns the same `Page` envelope so the UI has one
    pagination implementation.
  * IDs are UUIDs as strings; the client never needs to know the DB dialect.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any, Generic, TypeVar

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.functional_validators import AfterValidator

T = TypeVar("T")


def _validate_email(value: str) -> str:
    """Syntax-validate an address WITHOUT rejecting internal TLDs.

    pydantic's stock `EmailStr` refuses special-use names (`.test`, `.local`,
    `.internal`, `.corp`). VEYRS is deployed on-premise inside corporate
    networks where `soc@acme.corp` is a perfectly real mailbox, so blocking it
    would be a defect, not a hardening measure. Deliverability is never checked
    (that would mean a DNS lookup on a user-supplied string - an SSRF-adjacent
    primitive we refuse to build).
    """
    from email_validator import EmailNotValidError, validate_email

    try:
        info = validate_email(value, check_deliverability=False, test_environment=True)
    except EmailNotValidError as exc:
        raise ValueError(str(exc)) from exc
    return info.normalized.lower()


EmailStr = Annotated[str, AfterValidator(_validate_email)]


#: What a username may contain. Letters, digits, and the four separators every
#: directory in practice allows in `sAMAccountName` / `uid`.
#:
#: `@` is deliberately absent. The login lookup is `email == x OR username == x`
#: over one tenant, so a username shaped like an address would let its owner sit
#: in front of somebody else's account -- and the collision is unresolvable once
#: both rows exist. Refusing the character is the only place that stays cheap.
#:
#: A bare `.` or `-` is refused as the first character so a username cannot be
#: mistaken for a flag or a relative path when it reaches a shell or an LDAP
#: filter.
USERNAME_RE = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,149}$"


def _validate_username(value: str) -> str:
    """Normalise to lowercase and refuse anything the regex does not allow.

    Lowercase because directories are case-insensitive about account names and
    VEYRS is not: without folding, `JSmith` and `jsmith` are two rows that the
    unique constraint is perfectly happy to hold at once, and which of them a
    login lands on is a coin flip.
    """
    import re

    candidate = (value or "").strip().lower()
    if not re.match(USERNAME_RE, candidate):
        raise ValueError(
            "a username must be 2-150 characters, start with a letter or digit, "
            "and contain only letters, digits, dot, underscore or hyphen; '@' is "
            "not allowed because it would be ambiguous with an email address"
        )
    return candidate


Username = Annotated[str, AfterValidator(_validate_username)]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    """One page of results.

    `limit`/`offset` are the canonical wire fields; `page`/`size` are derived and
    returned as well, because half the API is paginated with `?page=&size=` and a
    client should not have to convert between the two representations.

    Use `Page.of(...)` rather than the constructor when the route takes
    page/size. Ten list endpoints were building `Page(page=..., size=...)` --
    fields the model does not declare -- so the extras were dropped, `limit` and
    `offset` came out missing, and every one of those endpoints raised a
    ValidationError at response time. `of()` exists so the conversion is written
    once instead of at each call site.
    """

    items: list[T]
    total: int
    limit: int
    offset: int
    page: int = 1
    size: int = 50

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total

    @classmethod
    def of(cls, items: list[T], total: int, page: int, size: int) -> "Page[T]":
        return cls(items=items, total=total, limit=size, offset=(page - 1) * size,
                   page=page, size=size)


class PageParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
    sort: str | None = None
    order: str = Field(default="desc", pattern="^(asc|desc)$")


# --- auth -----------------------------------------------------------------


class LoginRequest(BaseModel):
    """Credentials. The identifier may be a username OR an email address.

    `email` is kept, and kept working, because it is the field every existing
    client sends -- the console before this release, the CLI, the agent
    enrolment helper and roughly a hundred tests. Replacing it outright would
    have been a silent breaking change on the one endpoint whose failure mode
    is "nobody can sign in".
    """

    identifier: str | None = Field(
        default=None,
        min_length=1,
        max_length=320,
        description="Username or email address.",
    )
    # Deliberately NOT `EmailStr` any more. It is now one of two ways to name an
    # account, and an old client that posts `email: "jsmith"` should get the
    # same answer as a new one that posts `identifier: "jsmith"` rather than a
    # 422 about address syntax.
    email: str | None = Field(default=None, max_length=320)
    password: str = Field(min_length=1, max_length=512)
    organization: str | None = Field(
        default=None,
        # The console has always sent `organization_slug` while this field was
        # declared `organization`, so pydantic dropped it and the Organization
        # box on the sign-in page has never done anything. Latent with one
        # tenant; the moment an address exists in two, the backend answers
        # `409 organization_required` and the console cannot satisfy it, ever.
        # Both spellings are accepted rather than picking a winner and breaking
        # whichever clients use the other.
        validation_alias=AliasChoices("organization", "organization_slug"),
        description="Organization slug. Required when the identifier exists in several tenants.",
    )
    mfa_code: str | None = Field(default=None, max_length=12)

    @model_validator(mode="after")
    def _require_an_identifier(self) -> "LoginRequest":
        if not (self.identifier or "").strip() and not (self.email or "").strip():
            raise ValueError("provide `identifier` (a username or an email address)")
        return self

    @property
    def login_identifier(self) -> str:
        """What was typed, folded to lowercase. `identifier` wins over `email`.

        A client that sends both is a client mid-migration; taking the new field
        means the migration finishes the moment it is deployed rather than when
        the old one is finally deleted.
        """
        raw = (self.identifier or "").strip() or (self.email or "").strip()
        return raw.lower()


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_at: dt.datetime
    organization_id: uuid.UUID
    user_id: uuid.UUID
    permissions: list[str]


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=512)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=12, max_length=512)


class MfaEnrollResponse(BaseModel):
    """Returned ONCE, at enrolment. Carries the shared secret in clear.

    `mfa_enabled` stays False until /auth/mfa/activate proves the operator can
    actually generate codes -- enrolling without that proof is how people lock
    themselves out of their own account.
    """
    secret: str
    provisioning_uri: str
    digits: int
    period: int


class MfaActivate(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class MfaDisable(BaseModel):
    password: str = Field(min_length=1, max_length=512)
    code: str = Field(min_length=6, max_length=12)


class UserScopeUpdate(BaseModel):
    """Rewrite which teams a user's role grants are narrowed to.

    `team_ids: []` restores estate-wide visibility, and that is a privilege
    *grant*, not a relaxation of a setting -- which is why the route needs
    `role:admin` rather than `user:write`.
    """

    team_ids: list[uuid.UUID] = []


class ScanningUpdate(BaseModel):
    """Turn this tenant's active scanning on or off.

    `reason` is not decoration: "who stopped scanning production, and why" is
    the question this switch will be asked six months from now, and the audit
    entry is only as useful as the sentence stored with it.
    """

    active_scanning_enabled: bool
    reason: str | None = None
    #: Cancel jobs already queued. A job that can never be claimed is not
    #: queued, it is stuck -- and a queue depth counting work nobody will run
    #: is a number the dashboard reports wrongly. Ignored when enabling.
    cancel_queued_jobs: bool = True


class RiskRegisterUpdate(BaseModel):
    """Turn this tenant's risk register on or off.

    Nothing is deleted either way. `reason` is not decoration: "who turned
    off the risk register, and why" is a question an auditor asks in exactly
    those words, and the audit entry is only as useful as the sentence
    stored with it.
    """

    risk_register_enabled: bool
    reason: str | None = None


class TicketingUpdate(BaseModel):
    """Choose which system owns remediation work for this tenant.

    `connector_id` is required for `external` and refused for `internal`, and
    the service validates it rather than the schema: "external with no
    connector" is a state in which every creation path refuses, so it has to
    fail with a sentence naming the fix, not with a pydantic field error.

    `reason` is not decoration, for the same reason it is not on the scanning
    switch: "who moved our ticketing into Jira, and why" is the question this
    setting will be asked in the next audit.
    """

    mode: str
    connector_id: uuid.UUID | None = None
    reason: str | None = None


class LdapSettingsUpdate(BaseModel):
    """Directory (LDAP / Active Directory) configuration for this tenant.

    Every field is optional and `exclude_unset` is what the route acts on, so a
    console that predates a field cannot blank it by omission -- the lesson the
    preferences PATCH recorded in v0.24.0, applied to a form with eighteen
    boxes where the same mistake would be far harder to notice.
    """

    enabled: bool | None = None
    host: str | None = Field(default=None, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    use_ssl: bool | None = None
    start_tls: bool | None = None
    verify_certificate: bool | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=60)
    bind_dn: str | None = Field(default=None, max_length=512)
    #: Write-only. Absent leaves the stored one alone; a form that had to
    #: re-send it every time would eventually save the masked placeholder, and
    #: nobody would find out until the next person tried to sign in.
    bind_password: str | None = Field(default=None, max_length=512)
    #: Explicit erase, because `bind_password: null` has to keep meaning
    #: "not mentioned" for the rule above to hold.
    clear_bind_password: bool = False
    base_dn: str | None = Field(default=None, max_length=512)
    user_filter: str | None = Field(default=None, max_length=1024)
    attr_username: str | None = Field(default=None, max_length=64)
    attr_email: str | None = Field(default=None, max_length=64)
    attr_full_name: str | None = Field(default=None, max_length=64)
    attr_member_of: str | None = Field(default=None, max_length=64)
    #: `{directory group: VEYRS role slug}`. The group may be written as a full
    #: DN or as the bare CN -- `ldap_auth._group_keys` accepts both, because an
    #: operator reads the CN off a screen and a mapping that silently matches
    #: nothing presents as "this person logged in with no roles".
    group_role_map: dict[str, str] | None = None
    jit_provisioning: bool | None = None
    default_role_slugs: list[str] | None = None
    sync_roles_on_login: bool | None = None

    @field_validator("group_role_map")
    @classmethod
    def _limit_mapping(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is not None and len(value) > 100:
            raise ValueError("at most 100 group mappings")
        return value


class LdapTestRequest(BaseModel):
    """Optionally name somebody to look up, to prove the filter finds them.

    No password: the useful check while configuring a directory is "does my
    filter return the right entry", and asking an administrator to type a
    colleague's password to find that out is not a check anybody should build.
    """

    sample_identifier: str | None = Field(default=None, max_length=320)


class MeResponse(ORMModel):
    id: uuid.UUID
    email: str
    username: str | None = None
    full_name: str
    locale: str
    job_title: str | None
    organization_id: uuid.UUID
    is_superuser: bool
    mfa_enabled: bool
    last_login_at: dt.datetime | None
    permissions: list[str] = []
    roles: list[str] = []
    teams: list[str] = []
    # What this identity may see. `teams` above is membership ("whose queue"),
    # `scope` is authorization ("what you may read") -- they are different
    # things and showing only the first is how a segregated user believes an
    # empty dashboard. See `security.scope`.
    scope: dict[str, Any] = {}
    # Console preferences, shipped on the identity itself rather than behind a
    # second call. The console reads `/auth/me` once at boot; a separate
    # request would let the first dashboard render under the estate scope and
    # then jump to the remembered one, which reads as a glitch and, for the
    # half second it lasts, shows figures the operator did not ask for.
    preferences: dict[str, Any] = {}
    # Whether this tenant lets VEYRS probe anything (`services.scanning`).
    # Here rather than behind `GET /scanning` because that route needs
    # `settings:read`, which only the wildcard `org-admin` carries: a console
    # that drove its menu from it would work for the one persona that did not
    # need it and 403 for the other nine. It is tenant state, not a permission,
    # and it is already read-open by design.
    active_scanning: bool = True
    #: 'internal' (the VEYRS queue) or 'external' (Jira / ServiceNow). Defaults
    #: to internal so an older client, or a failure to read it, shows the queue
    #: VEYRS itself owns rather than no remediation surface at all.
    ticketing_mode: str = "internal"
    #: False means external mode is selected but its connector is missing or
    #: disabled: every creation path refuses. The console says so instead of
    #: drawing an empty screen.
    ticketing_usable: bool = True
    #: Whether this tenant keeps a risk register (`services.risk_register_mode`).
    #: Defaults to True for the same reason the service does: the module is
    #: new, there is no previous behaviour to preserve, and a client too old
    #: to know the field simply does not draw the section.
    risk_register_enabled: bool = True


class UserPreferencesPatch(BaseModel):
    """Merge by field: only what is sent is changed.

    Three deliberate choices:

    * **PATCH, not PUT.** A console that predates a preference key would wipe
      it on every save under replace semantics, and the person losing the
      setting would have no way to connect the two events.
    * **`extra="forbid"`.** The alternative -- an open JSONB the client fills
      -- makes a user row an unbounded store that anyone holding a session may
      write to. Unknown keys are a 422, which is also how a typo surfaces
      instead of being silently persisted and never read again.
    * **`None` is a value, not an absence.** It is how the operator says
      "whole estate"; `exclude_unset` keeps that apart from "did not mention
      this key", which must leave the stored value alone.
    """

    model_config = ConfigDict(extra="forbid")

    dashboard_team_id: uuid.UUID | None = None


# --- organizations --------------------------------------------------------


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=2, max_length=80, pattern="^[a-z0-9][a-z0-9-]*$")
    invoicing_code: str | None = Field(default=None, max_length=40)
    default_locale: str = Field(default="en", pattern="^(en|es|de|fr|it)$")
    timezone: str = "UTC"


class OrganizationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    invoicing_code: str | None = Field(default=None, max_length=40)
    default_locale: str | None = Field(default=None, pattern="^(en|es|de|fr|it)$")
    timezone: str | None = None
    is_active: bool | None = None
    settings: dict[str, Any] | None = None


class OrganizationOut(ORMModel):
    id: uuid.UUID
    name: str
    slug: str
    invoicing_code: str | None
    default_locale: str
    timezone: str
    is_active: bool
    created_at: dt.datetime


# --- users ----------------------------------------------------------------


class UserCreate(BaseModel):
    email: EmailStr
    # Optional, and staying optional: an operator who never wanted usernames
    # must not be forced to invent one for every account.
    username: Username | None = None
    full_name: str = Field(min_length=2, max_length=200)
    password: str | None = Field(default=None, min_length=12, max_length=512)
    job_title: str | None = Field(default=None, max_length=160)
    locale: str = Field(default="en", pattern="^(en|es|de|fr|it)$")
    role_slugs: list[str] = []
    team_ids: list[uuid.UUID] = []
    # Narrow every granted role to these teams. Empty = estate-wide, which is
    # what every existing grant is. Membership (`team_ids`) and authorization
    # (`scope_team_ids`) are set separately on purpose: joining a team must not
    # be able to widen what you may read. See `security.scope`.
    scope_team_ids: list[uuid.UUID] = []

    @field_validator("role_slugs")
    @classmethod
    def _limit_roles(cls, value: list[str]) -> list[str]:
        if len(value) > 12:
            raise ValueError("a user cannot hold more than 12 roles")
        return value


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=200)
    # `None` clears the username, `""` is refused by the validator, and an
    # absent key leaves it alone -- the three states have to stay distinct or
    # every unrelated PATCH from a console that predates this field would wipe
    # the one thing somebody uses to sign in. Same reasoning as the preferences
    # PATCH in v0.24.0.
    username: Username | None = None
    job_title: str | None = Field(default=None, max_length=160)
    locale: str | None = Field(default=None, pattern="^(en|es|de|fr|it)$")
    is_active: bool | None = None
    role_slugs: list[str] | None = None


class UserOut(ORMModel):
    id: uuid.UUID
    email: str
    username: str | None = None
    # Present so an administrator can tell a directory account from a local one
    # without opening the database -- which is the first question asked when
    # somebody reports "my password stopped working".
    ldap_dn: str | None = None
    full_name: str
    job_title: str | None
    locale: str
    is_active: bool
    is_superuser: bool
    mfa_enabled: bool
    last_login_at: dt.datetime | None
    created_at: dt.datetime
    roles: list[str] = []


# --- teams / departments --------------------------------------------------


class TeamCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    slug: str = Field(min_length=2, max_length=80, pattern="^[a-z0-9][a-z0-9-]*$")
    description: str | None = None
    email: EmailStr | None = None
    department_id: uuid.UUID | None = None
    manager_id: uuid.UUID | None = None
    escalation_chain: dict[str, Any] = {}


class TeamUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = None
    email: EmailStr | None = None
    department_id: uuid.UUID | None = None
    manager_id: uuid.UUID | None = None
    escalation_chain: dict[str, Any] | None = None


class TeamOut(ORMModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    email: str | None
    department_id: uuid.UUID | None
    manager_id: uuid.UUID | None
    escalation_chain: dict[str, Any]
    created_at: dt.datetime
    member_count: int = 0


class DepartmentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    description: str | None = None
    manager_id: uuid.UUID | None = None


class DepartmentOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str | None
    manager_id: uuid.UUID | None
    created_at: dt.datetime


# --- roles / api keys -----------------------------------------------------


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: str = Field(min_length=2, max_length=80, pattern="^[a-z0-9][a-z0-9-]*$")
    description: str | None = None
    permissions: list[str] = []


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = None
    permissions: list[str] | None = None


class RoleOut(ORMModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    is_builtin: bool
    permissions: list[str]
    organization_id: uuid.UUID | None


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    scopes: list[str] = []
    expires_in_days: int | None = Field(default=365, ge=1, le=3650)


class ApiKeyOut(ORMModel):
    id: uuid.UUID
    name: str
    prefix: str
    scopes: list[str]
    expires_at: dt.datetime | None
    last_used_at: dt.datetime | None
    revoked_at: dt.datetime | None
    created_at: dt.datetime


class ApiKeyCreated(ApiKeyOut):
    api_key: str = Field(description="Shown exactly once. VEYRS stores only its hash.")


# --- audit ----------------------------------------------------------------


class AuditOut(ORMModel):
    id: uuid.UUID
    created_at: dt.datetime
    actor_label: str
    action: str
    object_type: str
    object_id: str | None
    object_label: str | None
    changes: dict[str, Any]
    correlation_id: str | None
    ip_address: str | None


# --- CVSS calculator ------------------------------------------------------


class CvssScoreRequest(BaseModel):
    vector: str = Field(min_length=3, max_length=400)
    version: str | None = Field(default=None, pattern="^(2\\.0|3\\.0|3\\.1|4\\.0)$")


class CvssGenerateRequest(BaseModel):
    version: str = Field(pattern="^(2\\.0|3\\.0|3\\.1|4\\.0)$")
    metrics: dict[str, str]


class CvssCompareRequest(BaseModel):
    vectors: list[str] = Field(min_length=1, max_length=12)
