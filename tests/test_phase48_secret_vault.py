"""Phase 48 - stored credentials in an external vault (HashiCorp Vault / OpenBao KV v2).

The properties here are the feature:

* `local` is what every install that does nothing keeps: `v1:` values and NO
  vault traffic, even when a vault is configured;
* `vault` keeps the only copy off the host, and a read that fails RAISES --
  an empty credential sent to a directory locks the service account out;
* `mirror` is a stepping stone: both copies, vault first, local fallback;
* `decrypt` follows the stored prefix, not the current mode, so switching the
  mode back never strands a row;
* only the vault TOKEN is cached; values are fetched on every read so the
  vault's audit log stays truthful;
* migration never blanks and never deletes; gc deletes only what no row uses;
* the status page names no token and no secret-id, and is admin/estate-wide only.

The vault is an in-process fake that implements exactly the endpoints VEYRS
calls, and records every request so behaviour (not just results) is asserted.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from sqlalchemy import select

from veyrs.config import Settings, settings
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Base, Organization
from veyrs.models.ai import AiProvider
from veyrs.models.ticketing import ItsmConnector
from veyrs.models.tenancy import User
from veyrs.security import secret_vault
from veyrs.security import secrets as secretstore
from veyrs.services import ldap_auth, secret_storage

from conftest import login

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROLE_ID = "role-" + uuid.uuid4().hex
SECRET_ID = "sid-" + uuid.uuid4().hex


# ---------------------------------------------------------------------------
# the fake vault
# ---------------------------------------------------------------------------
class FakeVault:
    def __init__(self, mount: str = "veyrs"):
        self.mount = mount
        self.store: dict[str, dict] = {}        # key -> {"value":..., "created": dt}
        self.tokens: set[str] = set()
        self.requests: list[tuple[str, str]] = []
        self.sealed = False
        self.logins = 0
        self.lock = threading.Lock()
        vault = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def _send(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                if raw:
                    self.wfile.write(raw)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}") if n else {}

            def _handle(self, method):
                path = self.path.split("?", 1)[0]
                with vault.lock:
                    vault.requests.append((method, path))
                if path == "/v1/sys/health":
                    code = 503 if vault.sealed else 200
                    return self._send(code, {"initialized": True, "sealed": vault.sealed})
                if path == "/v1/auth/approle/login" and method == "POST":
                    body = self._body()
                    if body.get("role_id") != ROLE_ID or body.get("secret_id") != SECRET_ID:
                        return self._send(400, {"errors": ["invalid role or secret ID"]})
                    vault.logins += 1
                    tok = "hvs." + uuid.uuid4().hex
                    vault.tokens.add(tok)
                    return self._send(200, {"auth": {"client_token": tok,
                                                     "lease_duration": 3600,
                                                     "renewable": True}})
                if vault.sealed:
                    return self._send(503, {"errors": ["Vault is sealed"]})
                if self.headers.get("X-Vault-Token") not in vault.tokens:
                    return self._send(403, {"errors": ["permission denied"]})
                if path == "/v1/auth/token/lookup-self":
                    return self._send(200, {"data": {"ttl": 3000}})
                data_prefix = f"/v1/{vault.mount}/data/secrets/"
                meta_prefix = f"/v1/{vault.mount}/metadata/secrets"
                if path.startswith(data_prefix):
                    key = path[len(data_prefix):]
                    if method == "POST":
                        value = self._body()["data"]["value"]
                        with vault.lock:
                            prev = vault.store.get(key)
                            vault.store[key] = {
                                "value": value,
                                "created": prev["created"] if prev else dt.datetime.now(dt.timezone.utc),
                            }
                        return self._send(200, {"data": {"version": 1}})
                    if method == "GET":
                        entry = vault.store.get(key)
                        if not entry:
                            return self._send(404, {"errors": []})
                        return self._send(200, {"data": {"data": {"value": entry["value"]},
                                                         "metadata": {"version": 1}}})
                if path == meta_prefix and method == "LIST":
                    if not vault.store:
                        return self._send(404, {"errors": []})
                    return self._send(200, {"data": {"keys": sorted(vault.store)}})
                if path.startswith(meta_prefix + "/"):
                    key = path[len(meta_prefix) + 1:]
                    if method == "DELETE":
                        vault.store.pop(key, None)
                        return self._send(204)
                    if method == "GET":
                        entry = vault.store.get(key)
                        if not entry:
                            return self._send(404, {"errors": []})
                        stamp = entry["created"].strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"
                        return self._send(200, {"data": {"created_time": stamp}})
                return self._send(404, {"errors": ["no handler"]})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def do_DELETE(self):
                self._handle("DELETE")

            def do_LIST(self):
                self._handle("LIST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addr = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def count(self, method: str, fragment: str) -> int:
        return sum(1 for m, p in self.requests if m == method and fragment in p)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture()
def fake_vault(tmp_path, monkeypatch):
    vault = FakeVault()
    sid = tmp_path / "secret-id"
    sid.write_text(SECRET_ID + "\n")
    os.chmod(sid, 0o600)
    monkeypatch.setattr(settings, "vault_addr", vault.addr)
    monkeypatch.setattr(settings, "vault_mount", "veyrs")
    monkeypatch.setattr(settings, "vault_auth", "approle")
    monkeypatch.setattr(settings, "vault_role_id", ROLE_ID)
    monkeypatch.setattr(settings, "vault_secret_id_file", str(sid))
    monkeypatch.setattr(settings, "vault_token_file", "")
    monkeypatch.setattr(settings, "vault_ca_file", "")
    monkeypatch.setattr(settings, "vault_namespace", "")
    monkeypatch.setattr(settings, "vault_timeout", 3.0)
    monkeypatch.setattr(settings, "secret_backend", "local")
    secret_vault.forget_tokens()
    yield vault
    secret_vault.forget_tokens()
    vault.close()


def _mode(monkeypatch, mode):
    monkeypatch.setattr(settings, "secret_backend", mode)


def _vault_down(monkeypatch):
    # A port nothing listens on: a real connection refusal, not a fake error.
    monkeypatch.setattr(settings, "vault_addr", "http://127.0.0.1:9")
    secret_vault.forget_tokens()


# ---------------------------------------------------------------------------
# round trips
# ---------------------------------------------------------------------------
def test_local_mode_is_unchanged_and_never_contacts_the_vault(fake_vault, monkeypatch):
    stored = secretstore.encrypt("ldap-bind-pw")
    assert stored.startswith("v1:")
    assert secretstore.decrypt(stored) == "ldap-bind-pw"
    assert fake_vault.requests == []


def test_vault_mode_round_trip_keeps_only_a_reference(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("sk-live-123")
    assert re.fullmatch(r"vault:[0-9a-f-]{36}", stored)
    assert "sk-live-123" not in stored
    key = stored.split(":", 1)[1]
    assert fake_vault.store[key]["value"] == "sk-live-123"
    assert secretstore.decrypt(stored) == "sk-live-123"


def test_mirror_mode_round_trip_carries_both_copies(fake_vault, monkeypatch):
    _mode(monkeypatch, "mirror")
    stored = secretstore.encrypt("jira-token")
    assert stored.startswith("vm1:")
    key = secretstore.vault_key(stored)
    assert fake_vault.store[key]["value"] == "jira-token"
    assert secretstore.decrypt(stored) == "jira-token"
    assert fake_vault.count("GET", f"/data/secrets/{key}") == 1


def test_values_are_fetched_every_time_and_the_token_is_reused(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("value-x")
    key = stored.split(":", 1)[1]
    for _ in range(3):
        assert secretstore.decrypt(stored) == "value-x"
    assert fake_vault.count("GET", f"/data/secrets/{key}") == 3
    assert fake_vault.logins == 1


def test_an_expired_token_is_replaced_once(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("value-y")
    fake_vault.tokens.clear()                 # revoked under us
    assert secretstore.decrypt(stored) == "value-y"
    assert fake_vault.logins == 2


def test_mirror_falls_back_to_the_local_copy_when_the_vault_is_down(fake_vault, monkeypatch):
    _mode(monkeypatch, "mirror")
    stored = secretstore.encrypt("still-works")
    _vault_down(monkeypatch)
    assert secretstore.decrypt(stored) == "still-works"


def test_mirror_write_degrades_to_local_when_the_vault_is_down(fake_vault, monkeypatch):
    _mode(monkeypatch, "mirror")
    _vault_down(monkeypatch)
    stored = secretstore.encrypt("kept-locally")
    assert stored.startswith("v1:")
    assert secretstore.decrypt(stored) == "kept-locally"


def test_vault_mode_read_failure_raises_never_empty(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("must-not-vanish")
    _vault_down(monkeypatch)
    with pytest.raises(secretstore.SecretError):
        secretstore.decrypt(stored)


def test_vault_mode_missing_entry_raises(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("gone")
    fake_vault.store.clear()
    with pytest.raises(secretstore.SecretError):
        secretstore.decrypt(stored)


def test_vault_mode_sealed_vault_raises(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("sealed-away")
    fake_vault.sealed = True
    with pytest.raises(secretstore.SecretError):
        secretstore.decrypt(stored)


def test_vault_mode_write_failure_raises_rather_than_storing_locally(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    _vault_down(monkeypatch)
    with pytest.raises(secretstore.SecretError):
        secretstore.encrypt("no-silent-local-copy")


def test_try_decrypt_is_still_best_effort_for_display(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("masked")
    _vault_down(monkeypatch)
    assert secretstore.try_decrypt(stored) is None


def test_a_vault_value_stays_readable_after_switching_back_to_local(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("follow-the-prefix")
    _mode(monkeypatch, "local")
    assert secretstore.decrypt(stored) == "follow-the-prefix"


def test_a_vault_value_without_vault_config_names_the_fix(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("stranded")
    _mode(monkeypatch, "local")
    monkeypatch.setattr(settings, "vault_addr", "")
    with pytest.raises(secretstore.SecretError) as caught:
        secretstore.decrypt(stored)
    assert "VEYRS_VAULT_ADDR" in str(caught.value)
    assert "migrate --to local" in str(caught.value)


def test_local_mode_reads_a_mirror_value_from_its_local_copy(fake_vault, monkeypatch):
    _mode(monkeypatch, "mirror")
    stored = secretstore.encrypt("mirror-in-local")
    fake_vault.requests.clear()
    _mode(monkeypatch, "local")
    assert secretstore.decrypt(stored) == "mirror-in-local"
    assert fake_vault.requests == []


def test_a_hand_edited_reference_cannot_address_another_vault_path(fake_vault, monkeypatch):
    with pytest.raises(secretstore.SecretError):
        secretstore.decrypt("vault:../../sys/raw/core")
    assert not any("sys/raw" in p for _m, p in fake_vault.requests)


def test_a_world_readable_secret_id_file_is_refused(fake_vault, monkeypatch):
    os.chmod(settings.vault_secret_id_file, 0o644)
    _mode(monkeypatch, "vault")
    with pytest.raises(secretstore.SecretError) as caught:
        secretstore.encrypt("x")
    assert "chmod 600" in str(caught.value)
    assert fake_vault.logins == 0


def test_token_auth_reads_the_token_file(fake_vault, monkeypatch, tmp_path):
    tok = "hvs." + uuid.uuid4().hex
    fake_vault.tokens.add(tok)
    path = tmp_path / "token"
    path.write_text(tok)
    os.chmod(path, 0o600)
    monkeypatch.setattr(settings, "vault_auth", "token")
    monkeypatch.setattr(settings, "vault_token_file", str(path))
    secret_vault.forget_tokens()
    _mode(monkeypatch, "vault")
    stored = secretstore.encrypt("via-token")
    assert secretstore.decrypt(stored) == "via-token"
    assert fake_vault.logins == 0


# ---------------------------------------------------------------------------
# production safety
# ---------------------------------------------------------------------------
def _prod(**overrides):
    base = dict(
        environment="production", debug=False,
        database_url="postgresql+psycopg://veyrs:CHANGE-ME-not-the-bootstrap@db.example.com/veyrs",
        public_base_url="https://veyrs.example.com",
        encryption_key=secretstore.generate_key(),
        secret_key="x" * 40,
    )
    base.update(overrides)
    return Settings(_env_file=None, **base)


def test_local_mode_needs_no_vault_settings_in_production():
    _prod(secret_backend="local").assert_production_safe()


@pytest.mark.parametrize("mode", ["mirror", "vault"])
def test_production_refuses_an_incomplete_vault_configuration(mode):
    with pytest.raises(RuntimeError, match="vault_addr"):
        _prod(secret_backend=mode).assert_production_safe()
    with pytest.raises(RuntimeError, match="vault_role_id"):
        _prod(secret_backend=mode, vault_addr="https://vault.example.com:8200",
              vault_secret_id_file="/nonexistent").assert_production_safe()


def test_production_refuses_plain_http_to_the_vault(tmp_path):
    sid = tmp_path / "sid"
    sid.write_text("x")
    with pytest.raises(RuntimeError, match="https"):
        _prod(secret_backend="vault", vault_addr="http://vault.example.com:8200",
              vault_role_id="r", vault_secret_id_file=str(sid)).assert_production_safe()


def test_production_refuses_a_missing_secret_id_file():
    with pytest.raises(RuntimeError, match="does not exist"):
        _prod(secret_backend="vault", vault_addr="https://vault.example.com:8200",
              vault_role_id="r",
              vault_secret_id_file="/nonexistent/secret-id").assert_production_safe()


def test_production_accepts_a_complete_vault_configuration(tmp_path):
    sid = tmp_path / "sid"
    sid.write_text("x")
    _prod(secret_backend="vault", vault_addr="https://vault.example.com:8200",
          vault_role_id="r", vault_secret_id_file=str(sid)).assert_production_safe()
    _prod(secret_backend="mirror", vault_addr="https://vault.example.com:8200",
          vault_auth="token", vault_token_file=str(sid)).assert_production_safe()


# ---------------------------------------------------------------------------
# the registry is complete
# ---------------------------------------------------------------------------
def test_every_encrypted_column_is_registered():
    registered = {(c.table, c.column) for c in secret_storage.COLUMNS}
    found = {(t.name, c.name) for t in Base.metadata.tables.values()
             for c in t.columns if c.name.endswith("_enc")}
    found.add(("users", "mfa_secret"))
    assert found <= registered, f"not registered: {sorted(found - registered)}"
    assert secret_storage.LDAP_SECRET_FIELD == ldap_auth.SECRET_FIELD
    assert secret_storage.LDAP_SETTINGS_KEY == ldap_auth.SETTINGS_KEY


def test_every_ciphertext_column_can_hold_the_longest_format(fake_vault, monkeypatch):
    """`users.mfa_secret` is VARCHAR(255); the rest are TEXT. A mirror value of a
    32-character TOTP secret is the longest thing any of them will hold."""
    _mode(monkeypatch, "mirror")
    longest = secretstore.encrypt("A" * 32)
    for col in secret_storage.COLUMNS:
        column = Base.metadata.tables[col.table].c[col.column]
        length = getattr(column.type, "length", None)
        assert length is None or length >= len(longest), col.label


def test_every_writer_goes_through_the_envelope():
    """No module may build `v1:` strings itself or call Fernet directly."""
    offenders = []
    for path in (ROOT / "backend" / "veyrs").rglob("*.py"):
        if path.name in ("secrets.py", "secret_vault.py"):
            continue
        text = path.read_text(encoding="utf-8")
        if "Fernet(" in text or '"v1:"' in text:
            offenders.append(str(path))
    assert not offenders


# ---------------------------------------------------------------------------
# migrate / status / gc against the real (RLS-forced) database
# ---------------------------------------------------------------------------
def _seed(org_id, values: dict[str, str]):
    """One AI provider, one ITSM connector, one MFA secret and an LDAP password."""
    with SessionLocal() as session:
        set_tenant(session, org_id)
        provider = AiProvider(organization_id=org_id, slug=f"p-{uuid.uuid4().hex[:6]}",
                              name="Acme LLM", kind="openai", model="acme-1",
                              is_external=True,
                              api_key_enc=secretstore.encrypt(values["ai"]))
        connector = ItsmConnector(organization_id=org_id, slug=f"c-{uuid.uuid4().hex[:6]}",
                                  name="Acme Desk", system="webhook",
                                  credentials_enc=secretstore.encrypt(values["itsm"]))
        session.add_all([provider, connector])
        user = session.execute(select(User).where(User.organization_id == org_id)).scalars().first()
        user.mfa_secret = secretstore.encrypt(values["mfa"])
        org = session.get(Organization, org_id)
        blob = dict(org.settings or {})
        blob["ldap"] = {"host": "ldap.example.com", "bind_password_enc": secretstore.encrypt(values["ldap"])}
        org.settings = blob
        session.commit()
        return provider.id, connector.id, user.id


def _read_back(org_id, ids):
    provider_id, connector_id, user_id = ids
    with SessionLocal() as session:
        set_tenant(session, org_id)
        raw = {
            "ai": session.get(AiProvider, provider_id).api_key_enc,
            "itsm": session.get(ItsmConnector, connector_id).credentials_enc,
            "mfa": session.get(User, user_id).mfa_secret,
            "ldap": session.get(Organization, org_id).settings["ldap"]["bind_password_enc"],
        }
    return raw


VALUES = {"ai": "sk-acme-1", "itsm": '{"token": "desk-2"}', "mfa": "JBSWY3DPEHPK3PXP", "ldap": "bind-3"}


def test_migrate_dry_run_changes_nothing(fake_vault, monkeypatch, org_a):
    org_id, slug, _ = org_a
    ids = _seed(org_id, VALUES)
    before = _read_back(org_id, ids)
    with SessionLocal() as session:
        report = secret_storage.migrate(session, "vault", apply=False, slugs=[slug], out=lambda _s: None)
    assert report["converted"] == 4 and not report["failed"]
    assert _read_back(org_id, ids) == before
    assert fake_vault.store == {}
    assert fake_vault.count("POST", "/data/secrets/") == 0


def test_migrate_round_trip_local_vault_local_keeps_every_value(fake_vault, monkeypatch, org_a):
    org_id, slug, _ = org_a
    ids = _seed(org_id, VALUES)
    quiet = dict(slugs=[slug], out=lambda _s: None)

    with SessionLocal() as session:
        report = secret_storage.migrate(session, "vault", apply=True, **quiet)
    assert report["converted"] == 4 and not report["failed"], report
    raw = _read_back(org_id, ids)
    assert all(v.startswith("vault:") for v in raw.values()), raw
    assert len(fake_vault.store) == 4
    for name, value in raw.items():
        assert secretstore.decrypt(value) == VALUES[name]

    with SessionLocal() as session:
        again = secret_storage.migrate(session, "vault", apply=True, **quiet)
    assert again["converted"] == 0 and again["unchanged"] == 4

    with SessionLocal() as session:
        back = secret_storage.migrate(session, "local", apply=True, **quiet)
    assert back["converted"] == 4 and not back["failed"]
    raw = _read_back(org_id, ids)
    assert all(v.startswith("v1:") for v in raw.values()), raw
    fake_vault.store.clear()                  # the vault is gone: local must not need it
    for name, value in raw.items():
        assert secretstore.decrypt(value) == VALUES[name]


def test_migrate_through_mirror_reuses_the_vault_entry(fake_vault, monkeypatch, org_a):
    org_id, slug, _ = org_a
    ids = _seed(org_id, VALUES)
    quiet = dict(slugs=[slug], out=lambda _s: None)
    with SessionLocal() as session:
        secret_storage.migrate(session, "mirror", apply=True, **quiet)
    mirrored = _read_back(org_id, ids)
    assert all(v.startswith("vm1:") for v in mirrored.values())
    with SessionLocal() as session:
        secret_storage.migrate(session, "vault", apply=True, **quiet)
    final = _read_back(org_id, ids)
    for name in VALUES:
        assert secretstore.vault_key(final[name]) == secretstore.vault_key(mirrored[name])
    assert len(fake_vault.store) == 4           # no orphan per row


def test_an_unreadable_row_is_reported_and_left_alone(fake_vault, monkeypatch, org_a):
    org_id, slug, _ = org_a
    ids = _seed(org_id, VALUES)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.get(AiProvider, ids[0]).api_key_enc = "v1:not-a-fernet-token"
        session.commit()
    with SessionLocal() as session:
        report = secret_storage.migrate(session, "vault", apply=True, slugs=[slug], out=lambda _s: None)
    assert len(report["failed"]) == 1
    assert report["failed"][0]["column"] == "ai_providers.api_key_enc"
    assert report["converted"] == 3
    assert _read_back(org_id, ids)["ai"] == "v1:not-a-fernet-token"


def test_migrate_to_vault_is_refused_when_the_vault_is_down(fake_vault, monkeypatch, org_a):
    org_id, slug, _ = org_a
    ids = _seed(org_id, VALUES)
    before = _read_back(org_id, ids)
    _vault_down(monkeypatch)
    with SessionLocal() as session, pytest.raises(secretstore.SecretError):
        secret_storage.migrate(session, "vault", apply=True, slugs=[slug], out=lambda _s: None)
    assert _read_back(org_id, ids) == before


def test_status_counts_respect_the_tenant(fake_vault, monkeypatch, org_a, org_b):
    org_id, slug, _ = org_a
    _seed(org_id, VALUES)
    with SessionLocal() as session:
        secret_storage.migrate(session, "vault", apply=True, slugs=[slug], out=lambda _s: None)
        mine = secret_storage.totals(secret_storage.counts(session, org_id))
        other = secret_storage.totals(secret_storage.counts(session, org_b[0]))
    assert mine["vault"] == 4 and mine["local"] == 0
    assert other["vault"] == 0


def test_gc_lists_only_unreferenced_keys(fake_vault, monkeypatch, org_a):
    org_id, slug, _ = org_a
    _mode(monkeypatch, "vault")
    ids = _seed(org_id, VALUES)
    orphan = str(uuid.uuid4())
    secret_vault.write(orphan, "left-behind")
    with SessionLocal() as session:
        dry = secret_storage.gc(session, apply=False, min_age_minutes=0)
    assert dry["orphans"] == [orphan]
    assert orphan in fake_vault.store              # dry run deleted nothing
    with SessionLocal() as session:
        done = secret_storage.gc(session, apply=True, min_age_minutes=0)
    assert done["deleted"] == [orphan]
    assert orphan not in fake_vault.store
    for name, value in _read_back(org_id, ids).items():
        assert secretstore.decrypt(value) == VALUES[name]


def test_gc_keeps_an_unreferenced_entry_younger_than_the_grace_period(fake_vault, monkeypatch):
    young = str(uuid.uuid4())
    secret_vault.write(young, "save-in-flight")
    with SessionLocal() as session:
        report = secret_storage.gc(session, apply=True, min_age_minutes=60)
    assert young in report["too_recent"]
    assert young in fake_vault.store


def test_gc_reports_a_reference_the_vault_lost(fake_vault, monkeypatch, org_a):
    org_id, _slug, _ = org_a
    _mode(monkeypatch, "vault")
    ids = _seed(org_id, VALUES)
    key = secretstore.vault_key(_read_back(org_id, ids)["ai"])
    fake_vault.store.pop(key)
    with SessionLocal() as session:
        report = secret_storage.gc(session, apply=False, min_age_minutes=0)
    assert key in report["missing"]


def test_the_cli_is_wired(fake_vault, monkeypatch, capsys):
    from veyrs import cli

    # Exit codes depend on what earlier runs left in the shared test database
    # (an unrecognised value, a reference to a vault that is gone); the wiring
    # and the output are what is asserted here.
    assert cli.main(["secrets", "status"]) in (0, 1)
    out = capsys.readouterr().out
    assert "secret backend: local" in out
    assert "reachable: yes" in out
    assert "organizations.settings.ldap.bind_password_enc" in out
    assert SECRET_ID not in out
    assert cli.main(["secrets", "gc"]) in (0, 1)
    assert "vault entries listed: 0" in capsys.readouterr().out
    assert cli.main(["secrets", "migrate", "--to", "vault", "--org", "no-such-org"]) == 0
    assert "DRY RUN" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# the status endpoint
# ---------------------------------------------------------------------------
def test_status_endpoint_reports_without_leaking(client, admin_a, fake_vault, monkeypatch, org_a):
    _mode(monkeypatch, "vault")
    _seed(org_a[0], VALUES)
    response = client.get("/api/v1/secret-storage", headers=admin_a)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == "vault"
    assert body["vault"]["reachable"] is True and body["vault"]["auth_ok"] is True
    assert body["vault"]["addr"] == fake_vault.addr
    assert body["totals"]["vault"] == 4
    assert body["on_host"] == 0
    assert body["web_migration"] is False
    assert "veyrs secrets migrate --to vault --apply" in body["commands"].values()
    text = response.text
    assert SECRET_ID not in text
    assert ROLE_ID not in text
    assert settings.vault_secret_id_file not in text
    for token in fake_vault.tokens:
        assert token not in text
    for value in VALUES.values():
        assert value not in text


def test_status_endpoint_in_local_mode_says_what_is_exposed(client, admin_a, monkeypatch):
    monkeypatch.setattr(settings, "secret_backend", "local")
    monkeypatch.setattr(settings, "vault_addr", "")
    body = client.get("/api/v1/secret-storage", headers=admin_a).json()
    assert body["mode"] == "local"
    assert body["vault"]["reachable"] is None
    assert "same host" in body["meaning"]


def test_status_endpoint_refuses_a_non_admin(client, admin_a, org_a):
    _org_id, slug, _ = org_a
    email = f"ro-{uuid.uuid4().hex[:8]}@{slug}.test"
    created = client.post("/api/v1/users", headers=admin_a, json={
        "email": email, "full_name": "Read Only", "password": "Str0ng-Passw0rd!x",
        "role_slugs": ["read-only"]})
    assert created.status_code == 201, created.text
    token = login(client, email, slug, "Str0ng-Passw0rd!x")["access_token"]
    response = client.get("/api/v1/secret-storage", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_status_endpoint_refuses_a_team_scoped_admin(client, admin_a, org_a):
    org_id, slug, _ = org_a
    team = client.post("/api/v1/teams", headers=admin_a,
                       json={"name": "Net", "slug": f"net-{uuid.uuid4().hex[:6]}"})
    assert team.status_code == 201, team.text
    team_id = team.json()["id"]
    email = f"scoped-{uuid.uuid4().hex[:8]}@{slug}.test"
    created = client.post("/api/v1/users", headers=admin_a, json={
        "email": email, "full_name": "Scoped Admin", "password": "Str0ng-Passw0rd!x",
        "role_slugs": ["org-admin"], "team_ids": [team_id], "scope_team_ids": [team_id]})
    assert created.status_code == 201, created.text
    token = login(client, email, slug, "Str0ng-Passw0rd!x")["access_token"]
    response = client.get("/api/v1/secret-storage", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_status_endpoint_has_no_write_method(client, admin_a):
    for method in ("post", "put", "patch", "delete"):
        response = getattr(client, method)("/api/v1/secret-storage", headers=admin_a)
        assert response.status_code == 405, method


def test_an_unreadable_credential_is_a_503_not_a_500(client, admin_a, fake_vault, monkeypatch):
    from veyrs.main import app

    @app.get("/__phase48_probe")
    def _probe():  # noqa: ANN202
        raise secretstore.SecretError(f"vault at {fake_vault.addr} is unreachable")

    try:
        response = client.get("/__phase48_probe")
        assert response.status_code == 503
        assert fake_vault.addr not in response.text
    finally:
        app.router.routes[:] = [r for r in app.router.routes
                                if getattr(r, "path", "") != "/__phase48_probe"]


# ---------------------------------------------------------------------------
# LDAP: a stored password that cannot be read is an error, not an empty bind
# ---------------------------------------------------------------------------
def test_ldap_never_binds_with_an_unreadable_stored_password(fake_vault, monkeypatch):
    _mode(monkeypatch, "vault")
    cfg = {"bind_password_enc": secretstore.encrypt("svc-pass")}
    assert ldap_auth._bind_password(cfg) == "svc-pass"
    _vault_down(monkeypatch)
    with pytest.raises(ldap_auth.LdapError):
        ldap_auth._bind_password(cfg)
    assert ldap_auth._bind_password({}) is None


# ---------------------------------------------------------------------------
# docs and console
# ---------------------------------------------------------------------------
def test_the_manual_documents_the_commands():
    text = (ROOT / "docs" / "SYSTEM_MANUAL.md").read_text(encoding="utf-8")
    for command in ("veyrs secrets status", "veyrs secrets migrate", "veyrs secrets gc"):
        assert command in text


def test_the_console_has_a_read_only_secret_storage_tab():
    app = (ROOT / "frontend" / "console" / "app.js").read_text(encoding="utf-8")
    assert "['secrets', 'Secret storage']" in app
    assert "q: { tab: 'secrets' }" in app
    assert "get('/secret-storage')" in app
    body = app.split("async function secretStorageTab(", 1)[1].split("\n}\n", 1)[0]
    assert "put(" not in body and "post(" not in body and "del(" not in body
