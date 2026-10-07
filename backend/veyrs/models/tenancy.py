"""Organizations, users, teams, departments, roles and permissions.

RBAC shape: User --(UserRole, optionally scoped to a Team)--> Role --> Permission
Permissions are strings of the form `<resource>:<action>` (e.g. `asset:write`),
declared once in `veyrs.security.permissions` so the API and the seeder cannot
drift apart. ABAC is prepared but not enforced: `Role.attributes` and
`User.attributes` carry the JSONB the future policy engine will read.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, SoftDeleteMixin, TenantMixin, TimestampMixin, uuid_pk


class Organization(Base, TimestampMixin, SoftDeleteMixin):
    """A tenant. The root of every authorization decision in VEYRS."""

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    # free-text link to an external billing/CRM identity (fleet convention)
    invoicing_code: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    default_locale: Mapped[str] = mapped_column(String(5), default="en", nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # tenant-level guardrails read by the AI gateway and the risk engine
    settings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="organization")
    teams: Mapped[list["Team"]] = relationship(back_populates="organization")


class Department(Base, TenantMixin, TimestampMixin):
    __tablename__ = "departments"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    # escalation target when a team in this department breaches SLA
    manager_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class Team(Base, TenantMixin, TimestampMixin):
    """The unit work is assigned to. Owns an escalation chain and a mailbox."""

    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    department_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("departments.id", ondelete="SET NULL"), default=None
    )
    manager_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    email: Mapped[str | None] = mapped_column(String(255), default=None)
    # for the escalation engine: ordered list of {level, after_minutes, target}
    escalation_chain: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="teams")


class User(Base, TenantMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("organization_id", "email"),
        # Unique PER TENANT, not globally: `jsmith` in two organizations is two
        # different people, exactly as two `jsmith@` addresses already are. A
        # global constraint would let the first tenant to claim a common name
        # deny it to every other one.
        #
        # Postgres treats NULLs as distinct in a UNIQUE constraint, so every
        # account that never set a username coexists happily -- which is what
        # keeps this column addable to an estate that already has users.
        #
        # NAMED EXPLICITLY. The convention in models/base.py is
        # `uq_%(table_name)s_%(column_0_name)s`, which keys on the FIRST column
        # only -- so this constraint and the email one above both render as
        # `uq_users_organization_id`. An unnamed second per-tenant constraint on
        # any table is therefore silently unbuildable, and `sync-schema` reported
        # it as "0 constraints added" rather than as a collision.
        UniqueConstraint("organization_id", "username",
                         name="uq_users_organization_id_username"),
        Index("ix_users_org_active", "organization_id", "is_active"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    # Second login identifier, stored lowercase. Optional: an estate that has
    # only ever signed in with an address must keep working untouched.
    #
    # `@` is REFUSED by the schema validator (api/v1/schemas.USERNAME_RE) and
    # that refusal is what makes the login lookup safe to write as
    # `email == x OR username == x`. Allow one user to take `bob@corp.com` as a
    # username and they can sit in front of another user's address; the
    # ambiguity is not resolvable after the fact, so it is never created.
    username: Mapped[str | None] = mapped_column(String(150), default=None)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    # NULL for federated-only accounts (OIDC/SAML): there is no local password
    # to brute force, which is the point.
    password_hash: Mapped[str | None] = mapped_column(String(255), default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # platform superuser: crosses tenants. Deliberately rare and audited.
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    locale: Mapped[str] = mapped_column(String(5), default="en", nullable=False)
    job_title: Mapped[str | None] = mapped_column(String(160), default=None)
    department_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("departments.id", ondelete="SET NULL"), default=None
    )
    # external identity provider linkage
    oidc_subject: Mapped[str | None] = mapped_column(String(255), default=None, index=True)
    # Distinguished Name of the directory entry this account authenticates
    # against (`services/ldap_auth.py`). Written on the first successful
    # directory login and re-read on every one after it.
    #
    # It exists so a rename in AD does not orphan the VEYRS account: the DN is
    # what the directory considers stable, and matching on `sAMAccountName`
    # alone means an account renamed from `jsmith` to `jsmith2` silently
    # becomes a DIFFERENT person here, inheriting nothing and -- with JIT on --
    # quietly creating a second row for one human.
    ldap_dn: Mapped[str | None] = mapped_column(String(512), default=None, index=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Fernet ciphertext (security/secrets.py), never a hash: TOTP needs the
    # secret back to recompute the code. Enrolled but not yet activated is a
    # legitimate state -- the secret exists while mfa_enabled is still False.
    mfa_secret: Mapped[str | None] = mapped_column(String(255), default=None)
    # Time step of the last accepted code. Makes a captured code single-use;
    # see security/mfa.verify().
    mfa_last_step: Mapped[int | None] = mapped_column(BigInteger, default=None)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # Console preferences this person set for themselves (dashboard scope, so
    # far). Deliberately NOT folded into `attributes`: that column is reserved
    # for the policy engine above, and a value the user may write about
    # themselves must not share a namespace with one an authorization decision
    # will later read. The keys are whitelisted in `api/v1/auth.PREFERENCE_KEYS`
    # so a session cannot turn a user row into a blob store.
    preferences: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="users")

    @property
    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > dt.datetime.now(dt.timezone.utc))


class TeamMember(Base, TenantMixin, TimestampMixin):
    __tablename__ = "team_members"
    __table_args__ = (UniqueConstraint("team_id", "user_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    team_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_in_team: Mapped[str] = mapped_column(String(40), default="member", nullable=False)


class Role(Base, TimestampMixin):
    """Roles are per-organization, except the built-ins (organization_id NULL)."""

    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        default=None, index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    permissions: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class UserRole(Base, TenantMixin, TimestampMixin):
    """Role grant, optionally narrowed to one team (the ABAC seam)."""

    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_id", "team_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("teams.id", ondelete="CASCADE"), default=None
    )
    # Who granted this: `manual` (a person, through the API or console) or
    # `directory` (derived from an LDAP group by `services/ldap_auth.roles_for`).
    #
    # Provenance is what makes group synchronisation safe to run on every login.
    # Without it there are only two behaviours and both are wrong: replace every
    # grant, and an administrator's hand-made exception is silently deleted the
    # next time that person signs in; or only ever add, and somebody removed
    # from a directory group keeps the role they were removed from, forever --
    # which is the offboarding failure the directory was adopted to fix.
    #
    # Default `manual` so every grant that existed before this column did is
    # treated as a human decision and never touched by a sync.
    origin: Mapped[str] = mapped_column(String(16), default="manual", nullable=False)


class ApiKey(Base, TenantMixin, TimestampMixin):
    """Service-account credential. Only the hash is stored; prefix aids lookup."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False, unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    scopes: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    @property
    def is_usable(self) -> bool:
        now = dt.datetime.now(dt.timezone.utc)
        if self.revoked_at:
            return False
        return not (self.expires_at and self.expires_at <= now)


class RefreshToken(Base, TenantMixin, TimestampMixin):
    """Rotating refresh tokens - reuse of a rotated token revokes the family."""

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    family_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(255), default=None)
    ip_address: Mapped[str | None] = mapped_column(String(64), default=None)
