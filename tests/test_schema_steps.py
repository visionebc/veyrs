"""Every schema step is idempotent: init-db runs all of them on every call."""
from veyrs.db import engine
from veyrs.schema_steps import all_steps, apply_all


def test_steps_are_named_and_unique():
    idents = [i for i, _sql in all_steps()]
    assert len(idents) == len(set(idents))
    assert all(":" in i for i in idents)


def test_applying_every_step_twice_is_harmless():
    first = apply_all(engine)
    second = apply_all(engine)
    assert first == second == len(all_steps())


def test_trigram_indexes_follow_the_extension():
    """TD-54: with pg_trgm installed (a superuser's one-time step) init-db
    builds the search indexes; without it the steps are no-ops."""
    from sqlalchemy import text

    with engine.connect() as conn:
        has_ext = conn.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'")).first()
        idx = {r[0] for r in conn.execute(text(
            "SELECT indexname FROM pg_indexes WHERE indexname LIKE 'ix_trgm_%'"))}
    if has_ext:
        assert {"ix_trgm_cve_title", "ix_trgm_finding_title", "ix_trgm_asset_hostname"} <= idx
    else:
        assert not idx


def test_dashboard_indexes_are_declared():
    from veyrs.models import Base

    findings = {i.name for i in Base.metadata.tables["findings"].indexes}
    assert {"ix_findings_org_detected", "ix_findings_org_remediated",
            "ix_findings_org_kev", "ix_findings_org_epss"} <= findings
    assert "ix_risk_history_org_created" in {i.name for i in Base.metadata.tables["risk_score_history"].indexes}
