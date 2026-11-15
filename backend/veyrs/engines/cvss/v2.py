"""CVSS v2.0 scoring, per the FIRST "A Complete Guide to the CVSS Version 2.0".

Reference: https://www.first.org/cvss/v2/guide  (Sections 3.2.1 - 3.2.3)
Equations are transcribed literally; no simplifications.
"""
from __future__ import annotations

from .common import (
    strip_prefix,
    CVSSError,
    CVSSResult,
    MetricBreakdown,
    parse_vector,
    round1,
    severity_rating,
)

BASE = {
    "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
    "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
    "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
    "C": {"N": 0.0, "P": 0.275, "C": 0.660},
    "I": {"N": 0.0, "P": 0.275, "C": 0.660},
    "A": {"N": 0.0, "P": 0.275, "C": 0.660},
}
TEMPORAL = {
    "E": {"U": 0.85, "POC": 0.9, "F": 0.95, "H": 1.0, "ND": 1.0},
    "RL": {"OF": 0.87, "TF": 0.90, "W": 0.95, "U": 1.0, "ND": 1.0},
    "RC": {"UC": 0.90, "UR": 0.95, "C": 1.0, "ND": 1.0},
}
ENVIRONMENTAL = {
    "CDP": {"N": 0.0, "L": 0.1, "LM": 0.3, "MH": 0.4, "H": 0.5, "ND": 0.0},
    "TD": {"N": 0.0, "L": 0.25, "M": 0.75, "H": 1.0, "ND": 1.0},
    "CR": {"L": 0.5, "M": 1.0, "H": 1.51, "ND": 1.0},
    "IR": {"L": 0.5, "M": 1.0, "H": 1.51, "ND": 1.0},
    "AR": {"L": 0.5, "M": 1.0, "H": 1.51, "ND": 1.0},
}

NAMES = {
    "AV": ("Access Vector", {"L": "Local", "A": "Adjacent Network", "N": "Network"}),
    "AC": ("Access Complexity", {"H": "High", "M": "Medium", "L": "Low"}),
    "Au": ("Authentication", {"M": "Multiple", "S": "Single", "N": "None"}),
    "C": ("Confidentiality Impact", {"N": "None", "P": "Partial", "C": "Complete"}),
    "I": ("Integrity Impact", {"N": "None", "P": "Partial", "C": "Complete"}),
    "A": ("Availability Impact", {"N": "None", "P": "Partial", "C": "Complete"}),
    "E": ("Exploitability", {"U": "Unproven", "POC": "Proof-of-Concept",
                             "F": "Functional", "H": "High", "ND": "Not Defined"}),
    "RL": ("Remediation Level", {"OF": "Official Fix", "TF": "Temporary Fix",
                                 "W": "Workaround", "U": "Unavailable", "ND": "Not Defined"}),
    "RC": ("Report Confidence", {"UC": "Unconfirmed", "UR": "Uncorroborated",
                                 "C": "Confirmed", "ND": "Not Defined"}),
    "CDP": ("Collateral Damage Potential",
            {"N": "None", "L": "Low", "LM": "Low-Medium", "MH": "Medium-High",
             "H": "High", "ND": "Not Defined"}),
    "TD": ("Target Distribution", {"N": "None", "L": "Low", "M": "Medium",
                                   "H": "High", "ND": "Not Defined"}),
    "CR": ("Confidentiality Requirement", {"L": "Low", "M": "Medium", "H": "High", "ND": "Not Defined"}),
    "IR": ("Integrity Requirement", {"L": "Low", "M": "Medium", "H": "High", "ND": "Not Defined"}),
    "AR": ("Availability Requirement", {"L": "Low", "M": "Medium", "H": "High", "ND": "Not Defined"}),
}

BASE_ORDER = ["AV", "AC", "Au", "C", "I", "A"]
TEMPORAL_ORDER = ["E", "RL", "RC"]
ENV_ORDER = ["CDP", "TD", "CR", "IR", "AR"]


def _impact(c: float, i: float, a: float) -> float:
    return 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))


def _exploitability(av: float, ac: float, au: float) -> float:
    return 20.0 * av * ac * au


def _base_from(impact: float, exploitability: float) -> float:
    f_impact = 0.0 if impact == 0 else 1.176
    return round1(((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact)


def score(vector: str) -> CVSSResult:
    raw = parse_vector(strip_prefix(vector, "CVSS:2.0/"))
    metrics: list[MetricBreakdown] = []

    for key in BASE_ORDER:
        if key not in raw:
            raise CVSSError(f"CVSS v2 base metric {key} is mandatory")
    for key, value in raw.items():
        table = BASE.get(key) or TEMPORAL.get(key) or ENVIRONMENTAL.get(key)
        if table is None:
            raise CVSSError(f"unknown CVSS v2 metric {key!r}")
        if value not in table:
            raise CVSSError(f"illegal value {value!r} for metric {key}")

    def w(key: str) -> float:
        table = BASE.get(key) or TEMPORAL.get(key) or ENVIRONMENTAL.get(key)
        return table[raw.get(key, "ND")] if key in raw else table["ND"]

    impact = _impact(BASE["C"][raw["C"]], BASE["I"][raw["I"]], BASE["A"][raw["A"]])
    exploitability = _exploitability(
        BASE["AV"][raw["AV"]], BASE["AC"][raw["AC"]], BASE["Au"][raw["Au"]]
    )
    base = _base_from(impact, exploitability)

    temporal = None
    has_temporal = any(k in raw and raw[k] != "ND" for k in TEMPORAL_ORDER)
    if has_temporal:
        temporal = round1(base * w("E") * w("RL") * w("RC"))

    environmental = None
    has_env = any(k in raw and raw[k] != "ND" for k in ENV_ORDER)
    if has_env:
        adj_impact = min(
            10.0,
            10.41
            * (
                1
                - (1 - BASE["C"][raw["C"]] * w("CR"))
                * (1 - BASE["I"][raw["I"]] * w("IR"))
                * (1 - BASE["A"][raw["A"]] * w("AR"))
            ),
        )
        adj_base = _base_from(adj_impact, exploitability)
        adj_temporal = round1(adj_base * w("E") * w("RL") * w("RC"))
        cdp, td = w("CDP"), w("TD")
        environmental = round1((adj_temporal + (10 - adj_temporal) * cdp) * td)

    for key in BASE_ORDER + TEMPORAL_ORDER + ENV_ORDER:
        if key not in raw and key in BASE_ORDER:
            continue
        value = raw.get(key, "ND")
        name, value_names = NAMES[key]
        group = ("Base" if key in BASE_ORDER
                 else "Temporal" if key in TEMPORAL_ORDER else "Environmental")
        table = BASE.get(key) or TEMPORAL.get(key) or ENVIRONMENTAL.get(key)
        metrics.append(
            MetricBreakdown(
                abbrev=key, name=name, value=value,
                value_name=value_names.get(value, value), group=group,
                weight=table.get(value), defaulted=key not in raw,
            )
        )

    return CVSSResult(
        version="2.0",
        vector="/".join(f"{k}:{raw[k]}" for k in raw),
        base_score=base,
        base_severity=severity_rating(base, "2.0"),
        temporal_score=temporal,
        temporal_severity=severity_rating(temporal, "2.0") if temporal is not None else None,
        environmental_score=environmental,
        environmental_severity=(
            severity_rating(environmental, "2.0") if environmental is not None else None
        ),
        metrics=metrics,
        intermediates={
            "impact": round(impact, 4),
            "exploitability": round(exploitability, 4),
        },
    )
