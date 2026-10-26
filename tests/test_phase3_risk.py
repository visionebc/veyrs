"""Phase 3 - the risk engine.

These tests encode the product's central claim: identical CVSS does NOT mean
identical risk, and the ordering the engine produces must match what a security
professional would defend in a review.
"""
from __future__ import annotations

import datetime as dt

import pytest

from veyrs.engines import risk

NOW = dt.datetime(2026, 8, 10, tzinfo=dt.timezone.utc)


def base(**overrides) -> risk.RiskInput:
    defaults = dict(
        cvss_score=8.8, cvss_version="3.1", cvss_attack_vector="N",
        cvss_privileges_required="N", cvss_user_interaction="N",
        epss_score=0.05, kev=False, asset_criticality="medium",
        data_classification="internal", environment="production",
        exposure="internal", now=NOW,
        detected_at=NOW - dt.timedelta(days=1),
    )
    defaults.update(overrides)
    return risk.RiskInput(**defaults)


# --- the core thesis ------------------------------------------------------


def test_same_cvss_different_context_produces_different_risk():
    lab = risk.evaluate(base(asset_criticality="low", environment="test",
                             exposure="isolated", data_classification="public"))
    crown_jewel = risk.evaluate(base(asset_criticality="critical", environment="production",
                                     exposure="internet", data_classification="restricted"))
    assert lab.score < crown_jewel.score
    # the gap must be substantial, not cosmetic
    assert crown_jewel.score - lab.score > 25


def test_spec_example_scores_critical():
    """From the spec: CVSS 8.8 + EPSS 0.91 + KEV + internet + critical asset."""
    result = risk.evaluate(base(cvss_score=8.8, epss_score=0.91, kev=True,
                                exposure="internet", asset_criticality="critical"))
    assert result.level == "critical"
    assert result.score >= 90


def test_lower_cvss_can_outrank_higher_cvss():
    """CVSS 7.5 that is actively exploited on an internet-facing crown jewel must
    outrank a CVSS 9.8 sitting on an isolated development box."""
    exploited = risk.evaluate(base(cvss_score=7.5, epss_score=0.85, kev=True,
                                   exposure="internet", asset_criticality="critical",
                                   data_classification="restricted"))
    theoretical = risk.evaluate(base(cvss_score=9.8, epss_score=0.001, kev=False,
                                     exposure="isolated", asset_criticality="low",
                                     environment="development", data_classification="public"))
    assert exploited.score > theoretical.score


# --- policy floors --------------------------------------------------------


def test_kev_floor_applies():
    quiet_kev = risk.evaluate(base(cvss_score=4.0, epss_score=0.001, kev=True,
                                   asset_criticality="low", exposure="internal",
                                   environment="test", data_classification="public"))
    assert quiet_kev.score >= risk.DEFAULT_OPTIONS["kev_floor"]
    assert any(a["rule"] == "kev_floor" for a in quiet_kev.explanation["adjustments"])


def test_internet_kev_floor_is_higher_than_kev_floor():
    internal = risk.evaluate(base(cvss_score=4.0, kev=True, exposure="internal",
                                  asset_criticality="low"))
    internet = risk.evaluate(base(cvss_score=4.0, kev=True, exposure="internet",
                                  asset_criticality="low"))
    assert internet.score > internal.score
    assert internet.score >= risk.DEFAULT_OPTIONS["internet_kev_floor"]


def test_active_exploitation_floor():
    result = risk.evaluate(base(cvss_score=3.0, epss_score=0.0, active_exploitation=True,
                                asset_criticality="low", exposure="isolated"))
    assert result.score >= risk.DEFAULT_OPTIONS["active_exploitation_floor"]


def test_zero_cvss_without_exploitation_is_informational():
    result = risk.evaluate(base(cvss_score=0.0, epss_score=None))
    assert result.score == 0.0
    assert result.level == "informational"


def test_zero_cvss_with_kev_is_not_silenced():
    result = risk.evaluate(base(cvss_score=0.0, kev=True))
    assert result.score >= risk.DEFAULT_OPTIONS["kev_floor"]


# --- individual factors ---------------------------------------------------


def test_missing_cvss_defaults_to_medium_not_zero():
    result = risk.evaluate(base(cvss_score=None))
    technical = result.technical
    assert technical == 40.0
    assert result.score > 0


def test_epss_is_sqrt_scaled_so_low_values_still_register():
    low = risk.evaluate(base(epss_score=0.01)).exploitability
    mid = risk.evaluate(base(epss_score=0.25)).exploitability
    high = risk.evaluate(base(epss_score=0.90)).exploitability
    assert 0 < low < mid < high
    # a linear map would put 0.01 at 0.6 points; sqrt scaling gives it real weight
    assert low > 3.0


def test_compensating_controls_reduce_exposure_only():
    bare = risk.evaluate(base(exposure="internet"))
    with_waf = risk.evaluate(base(exposure="internet",
                                  compensating_controls=["waf", "network_segmentation"]))
    assert with_waf.exposure < bare.exposure
    assert with_waf.technical == bare.technical  # the flaw is unchanged
    assert with_waf.score < bare.score


def test_control_credit_is_capped():
    everything = risk.evaluate(base(
        exposure="internet",
        compensating_controls=list(risk.CONTROL_CREDIT),
    ))
    # cap is 50%: controls can halve exposure risk, never eliminate it
    bare = risk.evaluate(base(exposure="internet"))
    assert everything.exposure >= bare.exposure * 0.5 - 0.1


def test_unknown_control_is_ignored_not_credited():
    made_up = risk.evaluate(base(exposure="internet",
                                 compensating_controls=["thoughts-and-prayers"]))
    bare = risk.evaluate(base(exposure="internet"))
    assert made_up.exposure == bare.exposure


def test_age_penalty_grows_and_doubles_after_sla_breach():
    fresh = risk.evaluate(base(detected_at=NOW - dt.timedelta(days=5)))
    old = risk.evaluate(base(detected_at=NOW - dt.timedelta(days=120)))
    breached = risk.evaluate(base(detected_at=NOW - dt.timedelta(days=120),
                                  sla_due_at=NOW - dt.timedelta(days=60)))
    assert fresh.score < old.score < breached.score


def test_age_penalty_is_capped():
    ancient = risk.evaluate(base(detected_at=NOW - dt.timedelta(days=3650)))
    penalties = [a for a in ancient.explanation["adjustments"] if a["rule"] == "age_penalty"]
    assert penalties and penalties[0]["points"] <= risk.DEFAULT_OPTIONS["age_penalty_cap"]


def test_business_service_revenue_raises_business_risk():
    without = risk.evaluate(base())
    with_revenue = risk.evaluate(base(business_service_criticality="critical",
                                      revenue_per_hour=250_000))
    assert with_revenue.business > without.business


# --- profiles -------------------------------------------------------------


@pytest.mark.parametrize("slug", sorted(risk.BUILTIN_PROFILES))
def test_every_builtin_profile_scores_without_error(slug):
    spec = risk.BUILTIN_PROFILES[slug]
    result = risk.evaluate(base(), weights=spec["weights"], options=spec["options"],
                           profile_slug=slug)
    assert 0.0 <= result.score <= 100.0
    assert result.profile_slug == slug
    assert sum(spec["weights"].values()) == pytest.approx(1.0)


def test_technical_profile_favours_cvss_over_business_context():
    high_cvss_low_business = base(cvss_score=9.8, asset_criticality="low",
                                  data_classification="public", environment="development",
                                  exposure="isolated", epss_score=0.001)
    technical = risk.evaluate(high_cvss_low_business,
                              weights=risk.BUILTIN_PROFILES["technical-security"]["weights"],
                              profile_slug="technical-security")
    executive = risk.evaluate(high_cvss_low_business,
                              weights=risk.BUILTIN_PROFILES["executive-risk"]["weights"],
                              profile_slug="executive-risk")
    assert technical.score > executive.score


def test_internet_exposure_profile_favours_exposed_assets():
    exposed = base(exposure="internet", asset_criticality="medium")
    weights = risk.BUILTIN_PROFILES["internet-exposure"]["weights"]
    focused = risk.evaluate(exposed, weights=weights, profile_slug="internet-exposure")
    balanced = risk.evaluate(exposed)
    assert focused.score >= balanced.score


def test_custom_weights_are_honoured():
    only_business = risk.evaluate(
        base(cvss_score=10.0, asset_criticality="low", data_classification="public",
             environment="test"),
        weights={"technical": 0.0, "exploitability": 0.0, "business": 1.0, "exposure": 0.0},
    )
    assert only_business.score == pytest.approx(only_business.business, abs=0.1)


# --- explainability (spec section 26) -------------------------------------


def test_explanation_lists_every_contributing_factor():
    result = risk.evaluate(base(kev=True, epss_score=0.7, exposure="internet",
                                asset_criticality="critical"))
    explanation = result.explanation
    for group in ("technical", "exploitability", "business", "exposure"):
        assert explanation[group], f"{group} has no factors"
        for factor in explanation[group]:
            assert "factor" in factor and "points" in factor
    assert explanation["summary"].startswith("VEYRS risk")
    assert "cisa_kev" in " ".join(explanation["drivers"]) or explanation["adjustments"]


def test_explanation_reports_the_score_before_and_after_floors():
    result = risk.evaluate(base(cvss_score=2.0, kev=True, asset_criticality="low",
                                exposure="internal", environment="test",
                                data_classification="public", epss_score=0.001))
    assert result.explanation["base_score"] < result.explanation["final_score"]
    assert result.explanation["level"] == result.level


def test_levels_map_to_the_documented_bands():
    assert risk.level_for(95) == "critical"
    assert risk.level_for(90) == "critical"
    assert risk.level_for(89.9) == "high"
    assert risk.level_for(70) == "high"
    assert risk.level_for(69.9) == "medium"
    assert risk.level_for(40) == "medium"
    assert risk.level_for(39.9) == "low"
    assert risk.level_for(10) == "low"
    assert risk.level_for(9.9) == "informational"
    assert risk.level_for(0) == "informational"


def test_score_is_always_bounded():
    extreme = risk.evaluate(base(cvss_score=10.0, epss_score=1.0, kev=True,
                                 active_exploitation=True, exposure="internet",
                                 asset_criticality="critical",
                                 data_classification="restricted",
                                 business_service_criticality="critical",
                                 revenue_per_hour=10_000_000,
                                 detected_at=NOW - dt.timedelta(days=2000),
                                 sla_due_at=NOW - dt.timedelta(days=1900)))
    assert extreme.score == 100.0
    minimal = risk.evaluate(base(cvss_score=0.1, epss_score=0.0, exposure="isolated",
                                 asset_criticality="low", data_classification="public",
                                 environment="development",
                                 detected_at=NOW))
    assert 0.0 <= minimal.score <= 100.0
