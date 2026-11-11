"""Rotating VEYRS_ENCRYPTION_KEY without stranding a stored credential.

The properties are the feature:

* `VEYRS_ENCRYPTION_KEY_PREVIOUS` DECRYPTS but never encrypts;
* `secrets rekey` re-seals every local copy (plain `v1:` and the local half of
  a `vm1:` mirror value) under the current key, keeps the vault reference, and
  leaves a `vault:` value alone;
* after `--apply` the previous key can be dropped and every value still opens;
* a second run converts nothing; a row no key opens is reported and left as it was;
* production refuses a "previous" list that repeats the current key.
"""
from __future__ import annotations

import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from veyrs.config import Settings, settings
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Organization
from veyrs.models.ai import AiProvider
from veyrs.models.ticketing import ItsmConnector
from veyrs.models.tenancy import User
from veyrs.security import secrets as secretstore
from veyrs.services import secret_storage

OLD = Fernet.generate_key().decode()
NEW = Fernet.generate_key().decode()
VALUES = {"ai": "sk-rekey-1", "itsm": '{"token": "desk-rekey"}', "mfa": "JBSWY3DPEHPK3PXP", "ldap": "bind-rekey"}


@pytest.fixture()
def keys(monkeypatch):
    monkeypatch.setattr(settings, "secret_backend", "local")

    def use(current: str, previous: str = "") -> None:
        monkeypatch.setattr(settings, "encryption_key", current)
        monkeypatch.setattr(settings, "encryption_key_previous", previous)
        secretstore.forget_keys()

    yield use
    monkeypatch.undo()
    secretstore.forget_keys()


def _seed(org_id):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        provider = AiProvider(organization_id=org_id, slug=f"rk-{uuid.uuid4().hex[:6]}",
                              name="Rekey LLM", kind="openai", model="acme-1", is_external=True,
                              api_key_enc=secretstore.encrypt(VALUES["ai"]))
        connector = ItsmConnector(organization_id=org_id, slug=f"rk-{uuid.uuid4().hex[:6]}",
                                  name="Rekey Desk", system="webhook",
                                  credentials_enc=secretstore.encrypt(VALUES["itsm"]))
        session.add_all([provider, connector])
        user = session.execute(select(User).where(User.organization_id == org_id)).scalars().first()
        user.mfa_secret = secretstore.encrypt(VALUES["mfa"])
        org = session.get(Organization, org_id)
        blob = dict(org.settings or {})
        blob["ldap"] = {"host": "ldap.example.com", "bind_password_enc": secretstore.encrypt(VALUES["ldap"])}
        org.settings = blob
        session.commit()
        return provider.id, connector.id, user.id


def _raw(org_id, ids):
    provider_id, connector_id, user_id = ids
    with SessionLocal() as session:
        set_tenant(session, org_id)
        return {
            "ai": session.get(AiProvider, provider_id).api_key_enc,
            "itsm": session.get(ItsmConnector, connector_id).credentials_enc,
            "mfa": session.get(User, user_id).mfa_secret,
            "ldap": session.get(Organization, org_id).settings["ldap"]["bind_password_enc"],
        }


def _opens_with(key: str, stored: str) -> bool:
    _keep, token = secretstore._local_part(stored)
    try:
        Fernet(key.encode()).decrypt(token.encode())
        return True
    except Exception:
        return False


QUIET = {"out": lambda _s: None}


# ---------------------------------------------------------------------------
# the key ring
# ---------------------------------------------------------------------------
def test_previous_key_decrypts_but_never_encrypts(keys):
    keys(OLD)
    sealed_old = secretstore.encrypt("hello")
    keys(NEW, OLD)
    assert secretstore.decrypt(sealed_old) == "hello"
    sealed_new = secretstore.encrypt("world")
    assert _opens_with(NEW, sealed_new) and not _opens_with(OLD, sealed_new)


def test_without_the_previous_key_an_old_value_is_refused_loudly(keys):
    keys(OLD)
    sealed_old = secretstore.encrypt("hello")
    keys(NEW)
    with pytest.raises(secretstore.SecretError):
        secretstore.decrypt(sealed_old)


def test_an_invalid_previous_key_is_named(keys):
    keys(NEW)
    sealed = secretstore.encrypt("x")
    keys(NEW, "not-a-fernet-key")
    with pytest.raises(secretstore.SecretError, match="PREVIOUS"):
        secretstore.decrypt(sealed)


def test_reseal_keeps_the_mirror_vault_reference(keys):
    keys(OLD)
    ref = uuid.uuid4().hex
    stored = f"{secretstore.MIRROR_PREFIX}{ref}:" + Fernet(OLD.encode()).encrypt(b"m").decode()
    keys(NEW, OLD)
    assert not secretstore.sealed_with_current_key(stored)
    resealed = secretstore.reseal(stored)
    assert resealed.startswith(f"{secretstore.MIRROR_PREFIX}{ref}:")
    assert secretstore.sealed_with_current_key(resealed)
    assert _opens_with(NEW, resealed) and not _opens_with(OLD, resealed)


def test_a_vault_value_has_no_local_copy_to_reseal(keys):
    keys(NEW, OLD)
    with pytest.raises(secretstore.SecretError):
        secretstore.reseal("vault:" + uuid.uuid4().hex)


# ---------------------------------------------------------------------------
# rekey against the real (RLS-forced) database
# ---------------------------------------------------------------------------
def test_rekey_dry_run_changes_nothing(keys, org_a):
    org_id, slug, _ = org_a
    keys(OLD)
    ids = _seed(org_id)
    before = _raw(org_id, ids)
    keys(NEW, OLD)
    with SessionLocal() as session:
        report = secret_storage.rekey(session, apply=False, slugs=[slug], **QUIET)
    assert report["converted"] == 4 and not report["failed"], report
    assert _raw(org_id, ids) == before


def test_rekey_apply_then_the_previous_key_can_go(keys, org_a):
    org_id, slug, _ = org_a
    keys(OLD)
    ids = _seed(org_id)
    keys(NEW, OLD)
    with SessionLocal() as session:
        report = secret_storage.rekey(session, apply=True, slugs=[slug], **QUIET)
    assert report["converted"] == 4 and not report["failed"], report
    raw = _raw(org_id, ids)
    assert all(v.startswith("v1:") for v in raw.values()), raw
    assert all(_opens_with(NEW, v) and not _opens_with(OLD, v) for v in raw.values())

    keys(NEW)                                   # PREVIOUS removed
    for name, value in raw.items():
        assert secretstore.decrypt(value) == VALUES[name]
    with SessionLocal() as session:
        again = secret_storage.rekey(session, apply=True, slugs=[slug], **QUIET)
    assert again["converted"] == 0 and again["unchanged"] == 4 and not again["failed"]


def test_a_row_no_key_opens_is_reported_and_left_alone(keys, org_a):
    org_id, slug, _ = org_a
    stranger = Fernet.generate_key().decode()
    keys(stranger)
    ids = _seed(org_id)
    before = _raw(org_id, ids)
    keys(NEW, OLD)
    with SessionLocal() as session:
        report = secret_storage.rekey(session, apply=True, slugs=[slug], **QUIET)
    assert len(report["failed"]) == 4 and report["converted"] == 0
    assert _raw(org_id, ids) == before


def test_the_cli_is_wired(keys, capsys):
    from veyrs import cli

    keys(NEW, OLD)
    assert cli.main(["secrets", "rekey", "--org", "no-such-org"]) == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out and "0 organization(s)" in out


def test_production_refuses_a_previous_list_with_the_current_key():
    cfg = Settings(_env_file=None, environment="production", secret_key="x" * 40,
                   public_base_url="https://veyrs.example.com",
                   database_url="postgresql+psycopg://app:pw@db/veyrs",
                   encryption_key=NEW, encryption_key_previous=f"{OLD},{NEW}")
    with pytest.raises(RuntimeError, match="encryption_key_previous"):
        cfg.assert_production_safe()
