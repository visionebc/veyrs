"""Source-level guardrails for the two new Administration screens.

They read `app.js` rather than a rendered page because the console has no test
harness that executes it, and the two mistakes worth catching here are both
visible in the source: a screen gated on the wrong permission family, and a
screen the scanning-mode filter would hide.
"""
from __future__ import annotations

import pathlib
import re

import pytest

APP = pathlib.Path("/opt/veyrs/frontend/console/app.js")


@pytest.fixture(scope="module")
def js() -> str:
    if not APP.exists():  # pragma: no cover - a checkout without the console
        pytest.skip("console app.js is not present")
    return APP.read_text(encoding="utf-8")


def test_both_tabs_are_registered(js):
    assert "['sources', 'Asset sources']" in js
    assert "['teamimport', 'Import teams']" in js
    assert "} else if (tab === 'sources') {" in js
    assert "} else if (tab === 'teamimport') {" in js


def test_both_tabs_are_in_the_sidebar(js):
    assert "{ path: 'admin', label: 'Asset sources', q: { tab: 'sources' } }," in js
    assert "{ path: 'admin', label: 'Import teams',  q: { tab: 'teamimport' } }," in js


def test_neither_entry_is_hidden_by_the_scanning_switch(js):
    """Reading somebody else's inventory is what an ingest-only deployment DOES.
    Hiding it with the scanner leaves that deployment unable to receive an asset."""
    for label in ("Asset sources", "Import teams"):
        line = next(l for l in js.splitlines()
                    if f"label: '{label}'" in l and "path: 'admin'" in l)
        assert ", scan: true }" not in line, f"{label} would vanish when scanning is off"


def test_the_source_screen_is_gated_on_the_importer_family(js):
    """`GET /asset-sources` requires `importer:read`. Gating the screen on
    `settings:admin` hid it from `security-manager`, the one built-in role
    that holds the permission, and showed them a missing page rather than a
    refusal."""
    block = js[js.index("} else if (tab === 'sources') {"):
               js.index("} else if (tab === 'teamimport') {")]
    assert "can('importer:read')" in block
    assert "can('settings:admin')" not in block
    assert "can('importer:admin')" in block, "write actions must carry their own gate"


def test_the_team_import_screen_is_gated_on_team_write(js):
    block = js[js.index("} else if (tab === 'teamimport') {"):
               js.index("} else if (tab === 'directory') {")]
    assert "can('team:write')" in block


def test_the_screens_call_routes_that_exist(js):
    """A path typo produces a 404 the operator reads as 'the feature is broken'."""
    from veyrs.main import app

    registered = {r.path for r in app.routes if getattr(r, "path", "").startswith("/api/v1/")}
    block = js[js.index("} else if (tab === 'sources') {"):
               js.index("} else if (tab === 'directory') {")]
    literals = set(re.findall(r"'(/(?:asset-sources|teams/import)[a-z/-]*)'", block))
    assert literals, "the screens call nothing"
    for path in literals:
        full = "/api/v1" + path
        if path.endswith("/"):
            # `'/asset-sources/' + id` -- a prefix, so the registered route
            # carries a path parameter where the id goes.
            assert any(r.startswith(full) and "{" in r[len(full):] for r in registered), \
                f"{path} prefixes no registered route"
        else:
            assert full in registered, f"{path} is not a registered route"


def test_the_source_form_offers_the_mapping_for_netbox_too(js):
    """`needs_field_map` is False for NetBox and the form must still show the
    mapping: `custom_fields.*` is the half of NetBox no driver can know, and a
    form that hides an optional mapping is why it stayed unreachable."""
    block = js[js.index("} else if (tab === 'sources') {"):
               js.index("} else if (tab === 'teamimport') {")]
    assert "Field overrides (optional)" in block
    assert "custom_fields.pve_node" in block
    assert "extra." in block, "the form must say how to keep a field VEYRS lacks"
