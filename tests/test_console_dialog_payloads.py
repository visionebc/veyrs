"""0.35.3: the console's create dialogs must send what the API accepts.

Five dialogs answered every click with HTTP 422 -- Accept risk (finding page),
New SLA policy, New risk profile, New team and Invite user -- because the
payload in `frontend/console/app.js` had drifted from the Pydantic schema of
the route it posts to: missing required `slug`s, `hours` where the API reads
`remediate_within_hours`, a JSON body where the API reads the query string,
and `full_name: r.full_name || null` for a field that is required.

Nothing caught it because no test looked at both sides at once. This file
does, twice:

1. **Static drift check.** The object literal each dialog passes to `post()`
   is parsed out of app.js and compared with the route's schema: every key the
   console sends must be a field the schema knows, every required field must
   be sent, and a required field must not be given an `|| null` fallback.
   This is the half that fails when the CONSOLE drifts.
2. **HTTP round trip.** The same payload shape is posted to the API and must
   come back 2xx. This is the half that fails when the API drifts.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest
from pydantic import BaseModel

from veyrs.api.v1.schemas import TeamCreate, UserCreate
from veyrs.api.v1.vuln_schemas import RiskProfileWrite, SlaPolicyWrite
from veyrs.db import SessionLocal, set_tenant
from veyrs.main import app
from veyrs.models import Asset, Finding, Vulnerability

APP_JS = Path(__file__).resolve().parents[1] / "frontend" / "console" / "app.js"

_PAIRS = {"(": ")", "[": "]", "{": "}"}


@pytest.fixture(scope="module")
def source() -> str:
    return APP_JS.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# A small reader for the JS object literals the dialogs build.
# ---------------------------------------------------------------------------
def _balanced(text: str, start: int) -> str:
    """The bracketed expression opening at `text[start]`, strings respected."""
    stack, i, quote = [], start, None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif text.startswith("//", i):
            # a line comment inside the literal (the Invite user payload has one)
            i = text.find("\n", i)
            continue
        elif ch in "'\"`":
            quote = ch
        elif ch in _PAIRS:
            stack.append(_PAIRS[ch])
        elif ch in ")]}":
            assert stack and stack.pop() == ch, f"unbalanced literal near {text[start:i + 1]!r}"
            if not stack:
                return text[start:i + 1]
        i += 1
    raise AssertionError("unterminated literal")


def _split_top(body: str) -> list[str]:
    """Split `a, b: f(x, y), ...c` on the commas at depth 0."""
    parts, depth, quote, cur = [], 0, None, []
    i = 0
    while i < len(body):
        ch = body[i]
        if quote:
            cur.append(ch)
            if ch == "\\":
                cur.append(body[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _object_keys(literal: str) -> dict[str, str]:
    """`{ a, b: expr, ...(c ? { d: e } : {}) }` -> {"a": "a", "b": "expr", "d": "e"}."""
    assert literal.startswith("{") and literal.endswith("}"), literal
    body = re.sub(r"(?m)^\s*//.*$", "", literal[1:-1])
    out: dict[str, str] = {}
    for part in _split_top(body):
        if part.startswith("..."):
            # a conditional spread, `...(x ? { k: v } : {})`: every innermost
            # object literal in it contributes its keys
            for inner in re.findall(r"\{[^{}]*\}", part):
                if inner.strip("{} "):
                    out.update(_object_keys(inner))
            continue
        m = re.match(r"([A-Za-z_$][\w$]*)\s*(?::\s*(.*))?$", part, re.S)
        assert m, f"cannot read property {part!r}"
        out[m.group(1)] = (m.group(2) or m.group(1)).strip()
    return out


def _payloads_after(source: str, anchor: str) -> list[dict[str, str]]:
    """Every object literal that follows `anchor` (e.g. "post('/teams', ")."""
    found = []
    for m in re.finditer(re.escape(anchor), source):
        brace = source.index("{", m.end() - 1)
        found.append(_object_keys(_balanced(source, brace)))
    assert found, f"app.js no longer contains {anchor!r} -- update this guard"
    return found


def _check_against(model: type[BaseModel], payload: dict[str, str], where: str) -> None:
    fields = model.model_fields
    unknown = sorted(set(payload) - set(fields))
    assert not unknown, (
        f"{where} sends {unknown}, which {model.__name__} does not accept "
        f"(fields: {sorted(fields)}). The API ignores or refuses them."
    )
    required = {name for name, f in fields.items() if f.is_required()}
    missing = sorted(required - set(payload))
    assert not missing, f"{where} never sends required {model.__name__} fields {missing}: a 422 on every click"
    for name in required:
        assert not re.search(r"\|\|\s*null\s*$", payload[name]), (
            f"{where} sends {name} as `{payload[name]}`; {model.__name__}.{name} is "
            "required, so the null fallback is a 422 waiting for an empty input"
        )


# ---------------------------------------------------------------------------
# 1. Static drift check: console payload vs. route schema
# ---------------------------------------------------------------------------
DIALOGS = [
    ("New SLA policy", "post('/policies/sla', ", SlaPolicyWrite),
    ("New risk profile", "post('/risk/profiles', ", RiskProfileWrite),
    ("New team", "post('/teams', ", TeamCreate),
    ("Invite user", "post('/users', ", UserCreate),
]


@pytest.mark.parametrize("label,anchor,model", DIALOGS, ids=[d[0] for d in DIALOGS])
def test_dialog_payload_matches_the_schema(source, label, anchor, model):
    for payload in _payloads_after(source, anchor):
        _check_against(model, payload, f"the {label} dialog")


def _route(path: str, method: str = "POST"):
    for route in app.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", ()):
            return route
    raise AssertionError(f"no {method} {path} route")


def test_accept_risk_sends_reason_and_until_in_the_query_string(source):
    """The finding page used to send `{justification, until}` as JSON."""
    route = _route("/api/v1/findings/{finding_id}/accept-risk")
    query = {p.name: p for p in route.dependant.query_params}
    required = {name for name, p in query.items() if p.required}
    assert route.dependant.body_params == [], "accept-risk grew a body; update the console"

    calls = list(re.finditer(r"/accept-risk`\s*\+\s*qs\(", source))
    bare = re.findall(r"post\(`/findings/\$\{[^}]+\}/accept-risk`\s*,", source)
    assert not bare, f"an accept-risk call sends a body instead of a query string: {bare}"
    assert len(calls) >= 2, "both Accept risk entry points (finding page, triage) must use qs()"
    for m in calls:
        keys = _object_keys(_balanced(source, source.index("{", m.end())))
        assert set(keys) <= set(query), f"accept-risk query sends {sorted(set(keys) - set(query))}"
        assert required <= set(keys), f"accept-risk query is missing {sorted(required - set(keys))}"


# ---------------------------------------------------------------------------
# 2. HTTP round trip with exactly those shapes
# ---------------------------------------------------------------------------
def _slugify(value: str, fallback: str) -> str:
    """Python twin of app.js `slugify`."""
    s = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:80]
    return fallback if not s else f"{s}-{fallback}" if len(s) < 2 else s


def test_slugify_twin_matches_the_console(source):
    body = _balanced(source, source.index("{", source.index("const slugify = ")))
    assert "[^a-z0-9]+" in body and "slice(0, 80)" in body and "s.length < 2" in body, (
        "app.js slugify changed; update _slugify here so the round trip tests the real shape"
    )


def test_console_shaped_creates_are_accepted(client, admin_a):
    tag = uuid.uuid4().hex[:6]

    name = f"Critical KEV internet {tag}"
    r = client.post("/api/v1/policies/sla", headers=admin_a, json={
        "slug": _slugify(name, "sla-policy"), "name": name,
        "remediate_within_hours": 4, "priority": 10,
        "conditions": {"severity": ["critical"], "kev": True, "exposure": ["internet"]},
    })
    assert r.status_code == 201, r.text
    assert r.json()["remediate_within_hours"] == 4

    name = f"Executive risk {tag}"
    r = client.post("/api/v1/risk/profiles", headers=admin_a, json={
        "slug": _slugify(name, "risk-profile"), "name": name,
        "weights": {"technical": 0.30, "exploitability": 0.30, "business": 0.25, "exposure": 0.15},
    })
    assert r.status_code == 201, r.text

    name = f"Network Security {tag}"
    r = client.post("/api/v1/teams", headers=admin_a, json={
        "name": name, "slug": _slugify(name, "team"), "email": None,
    })
    assert r.status_code == 201, r.text

    r = client.post("/api/v1/users", headers=admin_a, json={
        "email": f"invitee-{tag}@example.com", "full_name": "Invited Person",
        "password": "a-long-enough-password", "role_slugs": ["read-only"],
    })
    assert r.status_code == 201, r.text


def test_a_one_character_team_name_still_gets_a_valid_slug(client, admin_a):
    r = client.post("/api/v1/teams", headers=admin_a, json={
        "name": "Q9", "slug": _slugify("Q", "team"), "email": None})
    assert r.status_code == 201, r.text


def test_console_shaped_accept_risk_is_accepted(client, admin_a, org_a):
    org_id = org_a[0]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = Asset(organization_id=org_id, name=f"host-{uuid.uuid4().hex[:8]}")
        vuln = Vulnerability(organization_id=org_id, title="fixture vulnerability",
                             internal_ref=f"fixture-{uuid.uuid4().hex[:12]}")
        session.add_all([asset, vuln])
        session.flush()
        finding = Finding(organization_id=org_id, asset_id=asset.id,
                          vulnerability_id=vuln.id, state="new",
                          dedupe_key=uuid.uuid4().hex, title="fixture finding")
        session.add(finding)
        session.commit()
        finding_id = str(finding.id)

    # What the finding page does for a `new` finding: triage first, then accept.
    r = client.post(f"/api/v1/findings/{finding_id}/transition", headers=admin_a,
                    json={"state": "triaged", "note": "Triaged for risk acceptance"})
    assert r.status_code == 200, r.text
    r = client.post(f"/api/v1/findings/{finding_id}/accept-risk", headers=admin_a,
                    params={"reason": "Compensating control: not reachable from outside.",
                            "until": "2027-01-31"}, json={})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "accepted_risk"

    # And the old shape is still a 422, so this test cannot pass by accident.
    r = client.post(f"/api/v1/findings/{finding_id}/accept-risk", headers=admin_a,
                    json={"justification": "a body the API never read", "until": None})
    assert r.status_code == 422
