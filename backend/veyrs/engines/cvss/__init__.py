"""VEYRS CVSS_ENGINE - one façade over the versioned calculators.

    from veyrs.engines import cvss
    cvss.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")

Every calculator returns a `CVSSResult`, so the API layer and the UI never
branch on version. Supported: 2.0, 3.0, 3.1, 4.0.
"""
from __future__ import annotations

from . import v2, v3, v4
from .common import CVSSError, CVSSResult, MetricBreakdown, detect_version, severity_rating

SUPPORTED_VERSIONS = ("2.0", "3.0", "3.1", "4.0")

__all__ = [
    "CVSSError", "CVSSResult", "MetricBreakdown", "SUPPORTED_VERSIONS",
    "score", "validate", "explain", "compare", "generate", "detect_version",
    "severity_rating", "metric_catalogue", "v2", "v3", "v4",
]

# Metric ordering and grouping for the interactive calculator. Kept here (not in
# the UI) so the front end can never drift from the engine's accepted values.
_GROUPS = {
    "2.0": {"Base": v2.BASE_ORDER, "Temporal": v2.TEMPORAL_ORDER, "Environmental": v2.ENV_ORDER},
    "3.0": {"Base": v3.BASE_ORDER, "Temporal": v3.TEMPORAL_ORDER, "Environmental": v3.ENV_ORDER},
    "3.1": {"Base": v3.BASE_ORDER, "Temporal": v3.TEMPORAL_ORDER, "Environmental": v3.ENV_ORDER},
    "4.0": {
        "Base": v4.BASE_ORDER,
        "Threat": v4.THREAT_ORDER,
        "Environmental": v4.ENV_ORDER,
        "Supplemental": v4.SUPPLEMENTAL_ORDER,
    },
}


def metric_catalogue(version: str) -> dict:
    """Every metric of a version: label, allowed values and their names.

    Drives the calculator UI and lets an integrator discover the vocabulary
    without scraping the specification.
    """
    if version not in SUPPORTED_VERSIONS:
        raise CVSSError(f"unsupported CVSS version {version!r}")
    module = v2 if version == "2.0" else (v3 if version.startswith("3") else v4)
    names = module.NAMES
    modified_of = getattr(module, "MODIFIED_OF", {})
    groups = []
    for group_name, keys in _GROUPS[version].items():
        metrics = []
        for key in keys:
            base_key = modified_of.get(key, key)
            if base_key not in names:
                continue
            label, values = names[base_key]
            if key in modified_of:
                label = f"Modified {label}"
            metrics.append({
                "abbrev": key,
                "name": label,
                "values": [{"value": v, "name": n} for v, n in values.items()],
                "mandatory": group_name == "Base" and key not in modified_of,
            })
        groups.append({"group": group_name, "metrics": metrics})
    return {
        "version": version,
        "groups": groups,
        "severity_bands": (
            [{"label": "Low", "min": 0.0, "max": 3.9},
             {"label": "Medium", "min": 4.0, "max": 6.9},
             {"label": "High", "min": 7.0, "max": 10.0}]
            if version == "2.0" else
            [{"label": "None", "min": 0.0, "max": 0.0},
             {"label": "Low", "min": 0.1, "max": 3.9},
             {"label": "Medium", "min": 4.0, "max": 6.9},
             {"label": "High", "min": 7.0, "max": 8.9},
             {"label": "Critical", "min": 9.0, "max": 10.0}]
        ),
    }


def score(vector: str, version: str | None = None) -> CVSSResult:
    """Parse and score a vector of any supported CVSS version."""
    version = version or detect_version(vector)
    if version == "2.0":
        return v2.score(vector)
    if version in ("3.0", "3.1"):
        return v3.score(vector, version)
    if version == "4.0":
        return v4.score(vector)
    raise CVSSError(f"unsupported CVSS version {version!r}")


def validate(vector: str, version: str | None = None) -> tuple[bool, str | None]:
    """Return (is_valid, error_message)."""
    try:
        score(vector, version)
        return True, None
    except CVSSError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001 - surface parser bugs as validation errors
        return False, f"{type(exc).__name__}: {exc}"


def generate(metrics: dict[str, str], version: str) -> str:
    """Build a canonical vector string from a metric map, then validate it."""
    if version == "2.0":
        order = v2.BASE_ORDER + v2.TEMPORAL_ORDER + v2.ENV_ORDER
        body = "/".join(f"{k}:{metrics[k]}" for k in order if metrics.get(k) not in (None, "", "ND"))
        vector = body
    elif version in ("3.0", "3.1"):
        order = v3.BASE_ORDER + v3.TEMPORAL_ORDER + v3.ENV_ORDER
        body = "/".join(f"{k}:{metrics[k]}" for k in order if metrics.get(k) not in (None, "", "X"))
        vector = f"CVSS:{version}/{body}"
    elif version == "4.0":
        body = "/".join(
            f"{k}:{metrics[k]}" for k in v4.VECTOR_ORDER
            if metrics.get(k) not in (None, "", "X")
        )
        vector = f"CVSS:4.0/{body}"
    else:
        raise CVSSError(f"unsupported CVSS version {version!r}")
    score(vector, version)  # raises if the caller handed us something illegal
    return vector


def explain(vector: str, version: str | None = None) -> dict:
    """Score plus a plain-language rationale, grouped by metric family."""
    result = score(vector, version)
    drivers: list[str] = []
    by_abbrev = {m.abbrev: m for m in result.metrics}

    def has(abbrev: str, *values: str) -> bool:
        m = by_abbrev.get(abbrev)
        return bool(m and m.value in values)

    if result.version == "2.0":
        if has("AV", "N"):
            drivers.append("Remotely reachable over the network (AV:N).")
        if has("Au", "N"):
            drivers.append("Requires no authentication (Au:N).")
        if has("C", "C") or has("I", "C") or has("A", "C"):
            drivers.append("At least one impact is Complete.")
    elif result.version.startswith("3"):
        if has("AV", "N"):
            drivers.append("Remotely reachable over the network (AV:N).")
        if has("PR", "N"):
            drivers.append("No privileges required (PR:N).")
        if has("UI", "N"):
            drivers.append("No user interaction required (UI:N).")
        if has("S", "C"):
            drivers.append("Scope changes - impact escapes the vulnerable component (S:C).")
        highs = [a for a in ("C", "I", "A") if has(a, "H")]
        if highs:
            drivers.append(f"High impact on {', '.join(highs)}.")
    else:
        if has("AV", "N"):
            drivers.append("Remotely reachable over the network (AV:N).")
        if has("PR", "N") and has("UI", "N"):
            drivers.append("Neither privileges nor user interaction are required.")
        if has("AT", "N"):
            drivers.append("No special attack requirements (AT:N).")
        highs = [a for a in ("VC", "VI", "VA") if has(a, "H")]
        if highs:
            drivers.append(f"High impact on the vulnerable system: {', '.join(highs)}.")
        if has("SI", "S") or has("SA", "S") or has("MSI", "S") or has("MSA", "S"):
            drivers.append("Safety impact on subsequent systems - dominates EQ4.")
        if has("E", "A"):
            drivers.append("Exploit maturity is Attacked (E:A).")

    return {
        **result.as_dict(),
        "drivers": drivers,
        "summary": (
            f"CVSS v{result.version} scores this {result.severity.lower()} at {result.score}"
            + (f" ({result.nomenclature})" if result.nomenclature else "")
            + "."
        ),
    }


def compare(vectors: list[str]) -> dict:
    """Score several vectors side by side - used by the 'compare versions' UI."""
    scored = []
    for vector in vectors:
        ok, err = validate(vector)
        if not ok:
            scored.append({"vector": vector, "error": err})
            continue
        scored.append(score(vector).as_dict())
    valid = [s for s in scored if "error" not in s]
    return {
        "results": scored,
        "max_score": max((s["score"] for s in valid), default=None),
        "min_score": min((s["score"] for s in valid), default=None),
        "spread": (
            round(max(s["score"] for s in valid) - min(s["score"] for s in valid), 1)
            if len(valid) > 1 else None
        ),
    }
