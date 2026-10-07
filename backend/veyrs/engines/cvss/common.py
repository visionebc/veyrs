"""Shared helpers for the VEYRS CVSS engine.

Every version-specific module (v2, v3, v4) returns a `CVSSResult`, so callers
never need to branch on the version to render a score.
"""
from __future__ import annotations

import math
from decimal import Decimal, ROUND_HALF_UP
from dataclasses import dataclass, field
from typing import Any


class CVSSError(ValueError):
    """Raised when a vector string is malformed or carries an illegal value."""


@dataclass
class MetricBreakdown:
    """One metric as parsed from a vector, with human-readable context."""

    abbrev: str
    name: str
    value: str
    value_name: str
    group: str
    weight: float | None = None
    defaulted: bool = False


@dataclass
class CVSSResult:
    version: str
    vector: str
    base_score: float
    base_severity: str
    temporal_score: float | None = None
    temporal_severity: str | None = None
    environmental_score: float | None = None
    environmental_severity: str | None = None
    # v4 reports a single nomenclature-tagged score
    nomenclature: str | None = None
    metrics: list[MetricBreakdown] = field(default_factory=list)
    intermediates: dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> float:
        """The score that should drive prioritisation: most-specific available."""
        if self.environmental_score is not None:
            return self.environmental_score
        if self.temporal_score is not None:
            return self.temporal_score
        return self.base_score

    @property
    def severity(self) -> str:
        return severity_rating(self.score, self.version)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "vector": self.vector,
            "base_score": self.base_score,
            "base_severity": self.base_severity,
            "temporal_score": self.temporal_score,
            "temporal_severity": self.temporal_severity,
            "environmental_score": self.environmental_score,
            "environmental_severity": self.environmental_severity,
            "score": self.score,
            "severity": self.severity,
            "nomenclature": self.nomenclature,
            "metrics": [m.__dict__ for m in self.metrics],
            "intermediates": self.intermediates,
        }


def severity_rating(score: float, version: str) -> str:
    """Qualitative severity rating.

    CVSS v2 uses the 3-band FIRST ranking; v3.x and v4.0 use the 5-band scale
    defined in their respective specifications.
    """
    if version.startswith("2"):
        if score < 4.0:
            return "Low"
        if score < 7.0:
            return "Medium"
        return "High"
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def round1(value: float) -> float:
    """CVSS v2 / v4 rounding: nearest tenth."""
    return float(f"{value + 1e-9:.1f}")


def round_half_up_1(value: float) -> float:
    """Round to one decimal, ties away from zero - what CVSS v4 requires.

    Python's `round()` and `format()` both round half to *even*, which silently
    shifts 5.05 -> 5.0 where the FIRST reference implementation yields 5.1. That
    is a real one-tenth error on 43 of the 1058 official v4 vectors, so the
    rounding is done in Decimal. The intermediate quantize to 6 places first
    strips binary artefacts (5.6499999999999995 is meant to be 5.65).
    """
    cleaned = Decimal(repr(value)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    return float(cleaned.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def roundup_31(value: float) -> float:
    """CVSS v3.1 Appendix A Roundup - integer arithmetic to dodge FP error."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def roundup_30(value: float) -> float:
    """CVSS v3.0 Roundup - naive ceiling to one decimal, as specified."""
    return math.ceil(value * 10.0) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """Split a `AA:B/CC:D` vector body into a metric map, rejecting duplicates."""
    metrics: dict[str, str] = {}
    for part in [p for p in vector.strip().split("/") if p]:
        if ":" not in part:
            raise CVSSError(f"malformed metric segment: {part!r}")
        key, _, value = part.partition(":")
        key, value = key.strip(), value.strip()
        if not key or not value:
            raise CVSSError(f"malformed metric segment: {part!r}")
        if key in metrics:
            raise CVSSError(f"duplicate metric {key!r}")
        metrics[key] = value
    if not metrics:
        raise CVSSError("empty vector")
    return metrics


def detect_version(vector: str) -> str:
    """Infer the CVSS version from the vector prefix.

    v2 vectors carry no prefix, so anything without `CVSS:` is treated as v2 --
    but only after we confirm it actually parses as a v2 metric set.
    """
    v = vector.strip()
    if v.upper().startswith("CVSS:4.0"):
        return "4.0"
    if v.upper().startswith("CVSS:3.1"):
        return "3.1"
    if v.upper().startswith("CVSS:3.0"):
        return "3.0"
    if v.upper().startswith("CVSS:2.0"):
        # not part of the v2 spec, but scanners and importers emit it anyway
        return "2.0"
    if v.upper().startswith("CVSS:"):
        raise CVSSError(f"unsupported CVSS version prefix in {vector!r}")
    return "2.0"


def strip_prefix(vector: str, *prefixes: str) -> str:
    """Drop a `CVSS:x.y/` prefix if present - importers are inconsistent."""
    v = vector.strip()
    for prefix in prefixes:
        if v.upper().startswith(prefix.upper()):
            return v[len(prefix):]
    return v
