"""A distro package string must never be compared as an upstream version.

Written after a production incident, not as coverage: a CMDB import of the DMZ
filled `AssetProduct.version` with the verbatim Debian string, and 560 of 2818
findings in environment P (444 of them OpenSSH) were manufactured by the epoch
alone -- `1:9.2p1-2+deb12u10` parsed as `1.9.2`, which sits inside
"openssh <= 2.9", a CVE fixed in 2001.

Two layers are pinned here on purpose. The ingest guard is the correct place
for the rule, and the parser guard is what makes the whole class impossible
even when a future collector, a hand-typed row or a migration writes a package
string straight into the column.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Asset, AssetProduct
from veyrs.services import inventory
from veyrs.services.versions import (
    compare, in_range, is_distro_version, parse, upstream_version, version_key,
)


@pytest.fixture()
def tenant_session(org_a):
    org_id, _, _ = org_a
    session = SessionLocal()
    set_tenant(session, org_id)
    yield session, org_id
    session.rollback()
    session.close()


def _asset(session, org_id):
    asset, _ = inventory.upsert_asset(
        session, org_id, {"name": f"epoch-host-{uuid.uuid4().hex[:8]}"}
    )
    return asset


# --------------------------------------------------------------------------
# Layer 1: the comparison itself cannot be poisoned by an epoch.
# --------------------------------------------------------------------------

def test_the_epoch_is_not_read_as_a_major_version():
    """`1:9.2p1` is OpenSSH 9.2, not OpenSSH 1.9.2."""
    assert compare("1:9.2p1-2+deb12u10", "2.9") > 0
    # The epoch is the ONLY difference these two strings have left.
    assert compare("1:9.2p1", "9.2p1") == 0
    assert compare("2:1.24.0", "1.24.0") == 0


def test_the_incident_case_no_longer_raises_a_finding():
    """CVE-2001-0529 declares `openssh <= 2.9`. A 9.2 host is not affected."""
    assert in_range("1:9.2p1-2+deb12u10", end_including="2.9") is False
    assert in_range("9.2p1", end_including="2.9") is False


def test_an_epoch_does_not_hide_a_real_finding_either():
    """The guard must not swing the other way: 1:2.4 really is <= 2.9."""
    assert in_range("1:2.4-1+deb12u1", end_including="2.9") is True


def test_the_epoch_is_stripped_before_segmentation():
    assert parse("2:1.24.0") == parse("1.24.0")
    assert version_key("2:1.24.0") == version_key("1.24.0")


@pytest.mark.parametrize("value", ["1:9.2p1-2+deb12u10", "9.2p1-2", "1:2.4",
                                   "1.22.1-9+deb12u9", "4.9.6-150600.3.1"])
def test_distro_strings_are_recognised(value):
    assert is_distro_version(value) is True


@pytest.mark.parametrize("value", ["1.24.0", "7.2.4", "5.32", "15.6",
                                   "7.2.4-rc1", "1.0.0-beta2", "", None])
def test_upstream_strings_are_not_mistaken_for_packaging(value):
    """A pre-release tag is upstream identity and must survive untouched.

    This is the whole reason the reduction is gated behind a predicate instead
    of applied unconditionally: truncating `7.2.4-rc1` to `7.2.4` would claim a
    host is newer than it is, which hides findings rather than inventing them.
    """
    assert is_distro_version(value) is False


def test_a_prerelease_still_sorts_below_its_release():
    assert compare("7.2.4-rc1", "7.2.4") < 0


# --------------------------------------------------------------------------
# Layer 2: ingest reduces a `version` field that is really a package string.
# --------------------------------------------------------------------------

def test_upstream_version_reduces_both_epoch_and_revision():
    assert upstream_version("1:9.2p1-2+deb12u10") == "9.2p1"
    assert upstream_version("1.22.1-9+deb12u9") == "1.22.1"
    assert upstream_version("4.9.6-150600.3.1") == "4.9.6"


def test_install_normalises_a_collector_that_echoes_the_package_string(
    tenant_session,
):
    """The exact shape of the DMZ import: `version` == `raw_version`.

    Before the fix this stored `1:9.2p1-2+deb12u10` verbatim and every range
    comparison downstream was wrong.
    """
    session, org_id = tenant_session
    asset = _asset(session, org_id)
    inventory.install(
        session, asset,
        [{"product": "openssh", "vendor": "openbsd",
          "version": "1:9.2p1-2+deb12u10", "raw_version": "1:9.2p1-2+deb12u10"}],
        detected_by="test-cmdb",
    )
    row = _only_install(session, asset)
    assert row.version == "9.2p1", "the epoch and revision must not be stored"
    assert row.raw_version == "1:9.2p1-2+deb12u10", "the verbatim string is evidence"


def test_install_leaves_a_genuine_upstream_version_alone(tenant_session):
    session, org_id = tenant_session
    asset = _asset(session, org_id)
    inventory.install(
        session, asset,
        [{"product": "fortiweb", "vendor": "fortinet",
          "version": "7.2.4-rc1", "raw_version": "7.2.4-rc1"}],
        detected_by="test-cmdb",
    )
    assert _only_install(session, asset).version == "7.2.4-rc1"


def _only_install(session, asset):
    rows = session.execute(
        select(AssetProduct).where(AssetProduct.asset_id == asset.id)
    ).scalars().all()
    assert len(rows) == 1, f"expected one installation, got {len(rows)}"
    return rows[0]


# --------------------------------------------------------------------------
# The unique key includes `version`, and the lookup has to agree with it.
# --------------------------------------------------------------------------

def test_a_second_sweep_of_a_multi_version_product_does_not_collide(tenant_session):
    """`uq_asset_products_asset_id` is UNIQUE (asset_id, product_id, version).

    RPM hosts carry one `gpg-pubkey` row per trusted key, so several rows share
    (asset, product). The old lookup ignored `version` and took `.first()`, so
    the second sweep tried to rename an arbitrary sibling onto a version another
    row already held -- a UniqueViolation that aborted the entire import, and
    one that the first sweep cannot expose because every row is an INSERT.
    """
    session, org_id = tenant_session
    asset = _asset(session, org_id)
    keys = [{"product": "gpg-pubkey", "version": v, "raw_version": v}
            for v in ("25db7ae0", "29b700a4", "39db7c82")]

    inventory.install(session, asset, keys, detected_by="test-cmdb")
    session.flush()
    assert _versions(session, asset) == {"25db7ae0", "29b700a4", "39db7c82"}

    # The sweep that used to raise.
    inventory.install(session, asset, keys, detected_by="test-cmdb")
    session.flush()
    assert _versions(session, asset) == {"25db7ae0", "29b700a4", "39db7c82"}


def test_a_single_row_still_upgrades_in_place(tenant_session):
    """The ordinary case must not regress into growing a row per version."""
    session, org_id = tenant_session
    asset = _asset(session, org_id)
    inventory.install(session, asset,
                      [{"product": "nginx", "vendor": "f5", "raw_version": "1.22.1-9"}],
                      detected_by="test-cmdb")
    session.flush()
    inventory.install(session, asset,
                      [{"product": "nginx", "vendor": "f5", "raw_version": "1.24.0-2"}],
                      detected_by="test-cmdb")
    session.flush()
    assert _versions(session, asset) == {"1.24.0"}, "an upgrade is not a new row"


def _versions(session, asset):
    rows = session.execute(
        select(AssetProduct).where(AssetProduct.asset_id == asset.id)
    ).scalars().all()
    return {row.version for row in rows}
