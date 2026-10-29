"""Single sign-on through the organization's identity provider (OpenID Connect).

Any standard OIDC provider: Authentik, Microsoft Entra ID, Okta, Keycloak,
Google Workspace, Ping. VEYRS is a confidential client using the
authorization-code flow with PKCE (S256), `state` and `nonce`:

1. `GET /auth/oidc/{org}/start` -> 302 to the provider's authorization endpoint.
2. The provider signs the person in -- password, second factor, passkey,
   conditional access: all of that is the PROVIDER's policy, not VEYRS's.
3. `GET /auth/oidc/callback?code&state` -> VEYRS exchanges the code at the
   token endpoint and verifies the ID token: signature against the provider's
   JWKS, issuer, audience (client id), expiry and nonce.
4. The browser goes back to the console with a ONE-TIME handoff code (60 s,
   single use); the console swaps it for VEYRS tokens with a POST. Tokens never
   travel in a URL, where they would end up in proxy logs and browser history.

Decisions worth knowing before changing anything here
-----------------------------------------------------
  * Nothing is configured by default. The option exists; an administrator turns
    it on with the provider's issuer, a client id and a client secret.
  * Accounts are matched by e-mail inside the organization. Just-in-time
    creation is OFF unless the administrator turns it on; a provider that says
    yes about an address nobody created here is refused, by default.
  * A platform superuser is never signed in through SSO (same rule as the
    directory and RADIUS): the account that repairs a broken SSO configuration
    must not depend on it.
  * VEYRS's own second factor is not asked after SSO: the provider is the
    authority. `require_mfa_amr` refuses an ID token whose `amr` claim does not
    show a second factor (mfa / otp / hwk / swk / sms / fpt / face ...), for
    providers that report it.
  * The client secret is encrypted at rest and never returned by any API.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import secrets as _rand
import threading
import time
import uuid
from typing import Any
from urllib.parse import urlencode, urlsplit

from sqlalchemy.orm import Session

from ..models.tenancy import Organization
from ..security import secrets

SETTINGS_KEY = "oidc"
SECRET_FIELD = "client_secret_enc"
FLOW_TTL = 600
HANDOFF_TTL = 60
MFA_AMR = {"mfa", "otp", "hwk", "swk", "sms", "fpt", "face", "iris", "pop", "sc", "tel", "user"}
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "issuer": "",                     # e.g. https://auth.example.com/application/o/veyrs/
    "client_id": "",
    "redirect_uri": "",               # https://<console host>/api/v1/auth/oidc/callback
    "scopes": "openid email profile",
    "email_claim": "email",
    "groups_claim": "groups",
    "group_role_map": {},
    "jit_provisioning": False,
    "require_mfa_amr": False,
    "button_label": "Sign in with SSO",
    SECRET_FIELD: None,
}


class OidcError(Exception):
    """The provider could not be used, or its answer could not be trusted."""


# -------------------------------------------------------------- configuration ---
def _block(organization: Organization | None) -> dict[str, Any]:
    stored = (organization.settings or {}) if organization is not None else {}
    block = stored.get(SETTINGS_KEY)
    return dict(block) if isinstance(block, dict) else {}


def config(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    merged = dict(DEFAULTS)
    merged.update(_block(session.get(Organization, organization_id)))
    return merged


def is_enabled_cfg(cfg: dict) -> bool:
    return bool(cfg.get("enabled") and cfg.get("issuer") and cfg.get("client_id")
                and cfg.get("redirect_uri") and cfg.get(SECRET_FIELD))


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    cfg = config(session, organization_id)
    out = {k: v for k, v in cfg.items() if k != SECRET_FIELD}
    out["client_secret_set"] = bool(cfg.get(SECRET_FIELD))
    return out


def _https(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme == "https" and bool(parts.hostname) and not parts.username


def validate(cfg: dict[str, Any]) -> list[str]:
    problems = []
    if cfg.get("issuer") and not _https(cfg["issuer"]):
        problems.append("issuer must be an https URL")
    if cfg.get("redirect_uri"):
        if not _https(cfg["redirect_uri"]) or not cfg["redirect_uri"].endswith("/api/v1/auth/oidc/callback"):
            problems.append("redirect_uri must be https://<console host>/api/v1/auth/oidc/callback")
    if "openid" not in str(cfg.get("scopes") or "").split():
        problems.append("scopes must include openid")
    if len(str(cfg.get("client_id") or "")) > 255:
        problems.append("client_id is too long")
    for key in ("email_claim", "groups_claim"):
        if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,100}", str(cfg.get(key) or "")):
            problems.append(f"{key} must be a claim name")
    if not isinstance(cfg.get("group_role_map") or {}, dict):
        problems.append("group_role_map maps group names to role slugs")
    if cfg.get("enabled"):
        for key in ("issuer", "client_id", "redirect_uri"):
            if not cfg.get(key):
                problems.append(f"{key} is required to enable single sign-on")
    return problems


def set_config(session: Session, organization_id: uuid.UUID, payload: dict[str, Any], *,
               client_secret: str | None = None, actor_id: uuid.UUID | None = None) -> dict[str, Any]:
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError("organization not found")
    merged = config(session, organization_id)
    for key in DEFAULTS:
        if key in payload and key != SECRET_FIELD:
            merged[key] = payload[key]
    merged["issuer"] = str(merged.get("issuer") or "").strip()
    merged["group_role_map"] = {str(k).strip(): str(v).strip()
                                for k, v in (merged.get("group_role_map") or {}).items()
                                if str(k).strip() and str(v).strip()}
    if client_secret:
        merged[SECRET_FIELD] = secrets.encrypt(client_secret)
    if merged.get("enabled") and not merged.get(SECRET_FIELD):
        raise ValueError("a client secret is required to enable single sign-on")
    problems = validate(merged)
    if problems:
        raise ValueError("; ".join(problems))
    merged["changed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    merged["changed_by_id"] = str(actor_id) if actor_id else None
    stored = dict(organization.settings or {})
    stored[SETTINGS_KEY] = merged
    organization.settings = stored
    session.flush()
    return state(session, organization_id)


# ------------------------------------------------------------- provider calls ---
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


def _get_json(url: str) -> dict:
    import httpx

    try:
        r = httpx.get(url, timeout=10, follow_redirects=False, headers={"Accept": "application/json"})
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"{urlsplit(url).hostname}: {type(exc).__name__}: {str(exc)[:160]}") from None


def discovery(issuer: str, *, force: bool = False) -> dict:
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with _lock:
        hit = _cache.get(url)
    if hit and not force and hit[0] > time.time():
        return hit[1]
    doc = _get_json(url)
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if not doc.get(key):
            raise OidcError(f"the discovery document has no {key}")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not _https(doc[key]):
            raise OidcError(f"{key} is not https")
    with _lock:
        _cache[url] = (time.time() + 3600, doc)
    return doc


def jwks(doc: dict, *, force: bool = False) -> dict:
    url = doc["jwks_uri"]
    with _lock:
        hit = _cache.get(url)
    if hit and not force and hit[0] > time.time():
        return hit[1]
    keys = _get_json(url)
    if not isinstance(keys.get("keys"), list) or not keys["keys"]:
        raise OidcError("the provider publishes no signing keys (jwks_uri)")
    with _lock:
        _cache[url] = (time.time() + 3600, keys)
    return keys


def _store():
    from ..security import mfa_delivery
    return mfa_delivery.store()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def start(session: Session, organization: Organization, return_to: str = "") -> str:
    """The provider's authorization URL; the flow's secrets wait in Redis."""
    cfg = config(session, organization.id)
    if not is_enabled_cfg(cfg):
        raise OidcError("single sign-on is not configured for this organization")
    doc = discovery(cfg["issuer"])
    st, nonce, verifier = _rand.token_urlsafe(32), _rand.token_urlsafe(32), _rand.token_urlsafe(64)
    _store().set(f"veyrs:oidc:flow:{st}", json.dumps({
        "org": str(organization.id), "nonce": nonce, "verifier": verifier}), FLOW_TTL)
    query = {"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": cfg["redirect_uri"],
             "scope": cfg["scopes"], "state": st, "nonce": nonce,
             "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()),
             "code_challenge_method": "S256"}
    sep = "&" if "?" in doc["authorization_endpoint"] else "?"
    return doc["authorization_endpoint"] + sep + urlencode(query)


def take_flow(state_value: str) -> dict | None:
    if not state_value or not re.fullmatch(r"[A-Za-z0-9_\-]{20,100}", state_value):
        return None
    key = f"veyrs:oidc:flow:{state_value}"
    raw = _store().get(key)
    if not raw:
        return None
    _store().delete(key)                 # single use
    return json.loads(raw)


def finish(session: Session, flow: dict, code: str) -> dict:
    """Exchange the code and verify the ID token. Returns its claims."""
    import httpx
    from jose import jwt
    from jose.exceptions import JOSEError

    org_id = uuid.UUID(flow["org"])
    cfg = config(session, org_id)
    if not is_enabled_cfg(cfg):
        raise OidcError("single sign-on was turned off during the sign-in")
    doc = discovery(cfg["issuer"])
    try:
        secret = secrets.decrypt(cfg[SECRET_FIELD])
    except secrets.SecretError as exc:
        raise OidcError(f"the stored client secret cannot be read: {exc}") from None
    try:
        r = httpx.post(doc["token_endpoint"], timeout=15, data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": cfg["redirect_uri"],
            "client_id": cfg["client_id"], "client_secret": secret, "code_verifier": flow["verifier"]},
            headers={"Accept": "application/json"})
        tokens = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"token endpoint: {type(exc).__name__}") from None
    if r.status_code != 200 or not tokens.get("id_token"):
        raise OidcError(f"token endpoint refused the code: {str(tokens.get('error') or r.status_code)[:80]}")
    issuer = doc.get("issuer") or cfg["issuer"]
    options = {"verify_at_hash": bool(tokens.get("access_token"))}
    for attempt in (0, 1):               # one refresh of the keys: the provider may have rotated
        try:
            claims = jwt.decode(tokens["id_token"], jwks(doc, force=bool(attempt)), algorithms=ALGORITHMS,
                                audience=cfg["client_id"], issuer=issuer,
                                access_token=tokens.get("access_token"), options=options)
            break
        except JOSEError as exc:
            if attempt:
                raise OidcError(f"the ID token does not verify: {str(exc)[:160]}") from None
    if claims.get("nonce") != flow["nonce"]:
        raise OidcError("the ID token's nonce is not this sign-in's")
    if cfg.get("require_mfa_amr") and not (set(claims.get("amr") or []) & MFA_AMR):
        raise OidcError("the provider did not report a second factor (amr) and this organization requires one")
    return claims


def roles_for(cfg: dict, claims: dict) -> list[str] | None:
    mapping = cfg.get("group_role_map") or {}
    if not mapping:
        return None
    groups = claims.get(cfg.get("groups_claim") or "groups") or []
    if isinstance(groups, str):
        groups = [groups]
    return sorted({mapping[g] for g in groups if isinstance(g, str) and g in mapping})


def save_handoff(user_id: Any) -> str:
    handoff = _rand.token_urlsafe(32)
    _store().set(f"veyrs:oidc:handoff:{handoff}", str(user_id), HANDOFF_TTL)
    return handoff


def take_handoff(handoff: str) -> str | None:
    if not handoff or not re.fullmatch(r"[A-Za-z0-9_\-]{20,100}", handoff):
        return None
    key = f"veyrs:oidc:handoff:{handoff}"
    value = _store().get(key)
    if value:
        _store().delete(key)
    return value


def console_origin(cfg: dict) -> str:
    parts = urlsplit(cfg.get("redirect_uri") or "")
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""


def test_discovery(session: Session, organization_id: uuid.UUID) -> dict:
    """Is the SAVED provider reachable and usable? Never raises; nothing is signed in."""
    cfg = config(session, organization_id)
    steps = []
    problems = validate(cfg) + ([] if cfg.get(SECRET_FIELD) else ["no client secret saved"])
    steps.append({"step": "configuration", "ok": not problems, "detail": "; ".join(problems) or "saved and valid"})
    if not cfg.get("issuer"):
        return {"ok": False, "steps": steps}
    try:
        doc = discovery(cfg["issuer"], force=True)
        same = doc.get("issuer", "").rstrip("/") == cfg["issuer"].rstrip("/")
        steps.append({"step": "discovery", "ok": same,
                      "detail": f"issuer {doc.get('issuer')}" + ("" if same else " -- differs from the configured issuer: copy it exactly")})
        keys = jwks(doc, force=True)
        steps.append({"step": "signing keys", "ok": True, "detail": f"{len(keys['keys'])} key(s) at the jwks_uri"})
        pkce = "S256" in (doc.get("code_challenge_methods_supported") or ["S256"])
        steps.append({"step": "PKCE S256", "ok": pkce, "detail": "supported" if pkce else "the provider does not announce S256"})
    except OidcError as exc:
        steps.append({"step": "discovery", "ok": False, "detail": str(exc)})
    return {"ok": all(s["ok"] for s in steps), "steps": steps,
            "redirect_uri": cfg.get("redirect_uri") or None}
