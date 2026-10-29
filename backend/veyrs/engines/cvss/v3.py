"""CVSS v3.0 and v3.1 scoring, per the FIRST specification documents.

References:
  https://www.first.org/cvss/v3.1/specification-document  (Section 7, formulas)
  https://www.first.org/cvss/v3.0/specification-document

The two revisions share metric weights and differ in exactly two places:
  * the Roundup function (3.1 uses integer arithmetic to remove FP artefacts)
  * the Modified Impact sub-formula for Scope:Changed
Both differences are honoured below rather than papered over.
"""
from __future__ import annotations

from .common import (
    CVSSError,
    CVSSResult,
    MetricBreakdown,
    parse_vector,
    roundup_30,
    roundup_31,
    severity_rating,
)

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {  # depends on Scope
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 0.0},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    "E": {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91},
    "RL": {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95},
    "RC": {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92},
    "CR": {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5},
    "IR": {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5},
    "AR": {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5},
}

BASE_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
TEMPORAL_ORDER = ["E", "RL", "RC"]
ENV_ORDER = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]

MODIFIED_OF = {
    "MAV": "AV", "MAC": "AC", "MPR": "PR", "MUI": "UI",
    "MS": "S", "MC": "C", "MI": "I", "MA": "A",
}

NAMES = {
    "AV": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack Complexity", {"L": "Low", "H": "High"}),
    "PR": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction", {"N": "None", "R": "Required"}),
    "S": ("Scope", {"U": "Unchanged", "C": "Changed"}),
    "C": ("Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "I": ("Integrity", {"H": "High", "L": "Low", "N": "None"}),
    "A": ("Availability", {"H": "High", "L": "Low", "N": "None"}),
    "E": ("Exploit Code Maturity", {"X": "Not Defined", "H": "High", "F": "Functional",
                                    "P": "Proof-of-Concept", "U": "Unproven"}),
    "RL": ("Remediation Level", {"X": "Not Defined", "U": "Unavailable", "W": "Workaround",
                                 "T": "Temporary Fix", "O": "Official Fix"}),
    "RC": ("Report Confidence", {"X": "Not Defined", "C": "Confirmed",
                                 "R": "Reasonable", "U": "Unknown"}),
    "CR": ("Confidentiality Requirement", {"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}),
    "IR": ("Integrity Requirement", {"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}),
    "AR": ("Availability Requirement", {"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}),
}


def _iss(c: float, i: float, a: float) -> float:
    return 1.0 - ((1 - c) * (1 - i) * (1 - a))


def score(vector: str, version: str | None = None) -> CVSSResult:
    v = vector.strip()
    upper = v.upper()
    if upper.startswith("CVSS:3.1/"):
        version, body = "3.1", v[len("CVSS:3.1/"):]
    elif upper.startswith("CVSS:3.0/"):
        version, body = "3.0", v[len("CVSS:3.0/"):]
    elif version in ("3.0", "3.1"):
        body = v
    else:
        raise CVSSError("CVSS v3 vectors must start with CVSS:3.0/ or CVSS:3.1/")

    roundup = roundup_31 if version == "3.1" else roundup_30
    raw = parse_vector(body)

    for key in BASE_ORDER:
        if key not in raw:
            raise CVSSError(f"CVSS v{version} base metric {key} is mandatory")
    for key, value in raw.items():
        base_key = MODIFIED_OF.get(key, key)
        table = WEIGHTS.get(base_key)
        if table is None:
            raise CVSSError(f"unknown CVSS v{version} metric {key!r}")
        allowed = set(table["U"]) | set(table["C"]) if base_key == "PR" else set(table)
        if key in MODIFIED_OF or key in ENV_ORDER:
            allowed = allowed | {"X"}
        if value not in allowed:
            raise CVSSError(f"illegal value {value!r} for metric {key}")

    scope = raw["S"]
    pr_w = WEIGHTS["PR"][scope][raw["PR"]]
    iss = _iss(WEIGHTS["C"][raw["C"]], WEIGHTS["I"][raw["I"]], WEIGHTS["A"][raw["A"]])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = (
        8.22 * WEIGHTS["AV"][raw["AV"]] * WEIGHTS["AC"][raw["AC"]] * pr_w * WEIGHTS["UI"][raw["UI"]]
    )

    if impact <= 0:
        base = 0.0
    elif scope == "U":
        base = roundup(min(impact + exploitability, 10.0))
    else:
        base = roundup(min(1.08 * (impact + exploitability), 10.0))

    e = WEIGHTS["E"][raw.get("E", "X")]
    rl = WEIGHTS["RL"][raw.get("RL", "X")]
    rc = WEIGHTS["RC"][raw.get("RC", "X")]
    # Per the v3.1 spec, Not Defined (X) temporal/environmental metrics take a
    # weight of 1.0 / fall back to their Base counterpart, so the Temporal and
    # Environmental scores are ALWAYS defined - with no modifiers they collapse
    # onto the Base score. We compute all three unconditionally (the reference
    # implementation does the same) and flag whether the operator actually
    # supplied any modifier, so the UI can hide redundant columns.
    has_temporal = any(raw.get(k, "X") != "X" for k in TEMPORAL_ORDER)
    temporal = roundup(base * e * rl * rc)

    has_env = any(raw.get(k, "X") != "X" for k in ENV_ORDER)

    def mod(key: str) -> str:
        mkey = f"M{key}"
        value = raw.get(mkey, "X")
        return raw[key] if value == "X" else value

    m_scope = mod("S")
    cr = WEIGHTS["CR"][raw.get("CR", "X")]
    ir = WEIGHTS["IR"][raw.get("IR", "X")]
    ar = WEIGHTS["AR"][raw.get("AR", "X")]
    miss = min(
        1
        - (1 - WEIGHTS["C"][mod("C")] * cr)
        * (1 - WEIGHTS["I"][mod("I")] * ir)
        * (1 - WEIGHTS["A"][mod("A")] * ar),
        0.915,
    )
    if m_scope == "U":
        m_impact = 6.42 * miss
    elif version == "3.1":
        m_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
    else:
        m_impact = 7.52 * (miss - 0.029) - 3.25 * (miss - 0.02) ** 15
    m_exploit = (
        8.22
        * WEIGHTS["AV"][mod("AV")]
        * WEIGHTS["AC"][mod("AC")]
        * WEIGHTS["PR"][m_scope][mod("PR")]
        * WEIGHTS["UI"][mod("UI")]
    )
    if m_impact <= 0:
        environmental = 0.0
    elif m_scope == "U":
        environmental = roundup(roundup(min(m_impact + m_exploit, 10.0)) * e * rl * rc)
    else:
        environmental = roundup(roundup(min(1.08 * (m_impact + m_exploit), 10.0)) * e * rl * rc)

    metrics: list[MetricBreakdown] = []
    for key in BASE_ORDER + TEMPORAL_ORDER + ENV_ORDER:
        value = raw.get(key, "X")
        base_key = MODIFIED_OF.get(key, key)
        name, value_names = NAMES[base_key]
        if key in MODIFIED_OF:
            name = f"Modified {name}"
        group = ("Base" if key in BASE_ORDER
                 else "Temporal" if key in TEMPORAL_ORDER else "Environmental")
        table = WEIGHTS[base_key]
        weight = None if base_key == "PR" else table.get(value)
        metrics.append(
            MetricBreakdown(
                abbrev=key, name=name, value=value,
                value_name=value_names.get(value, "Not Defined" if value == "X" else value),
                group=group, weight=weight, defaulted=key not in raw,
            )
        )

    canonical = f"CVSS:{version}/" + "/".join(f"{k}:{raw[k]}" for k in raw)
    return CVSSResult(
        version=version,
        vector=canonical,
        base_score=base,
        base_severity=severity_rating(base, version),
        temporal_score=temporal,
        temporal_severity=severity_rating(temporal, version),
        environmental_score=environmental,
        environmental_severity=severity_rating(environmental, version),
        metrics=metrics,
        intermediates={
            "iss": round(iss, 4),
            "impact": round(impact, 4),
            "exploitability": round(exploitability, 4),
            "miss": round(miss, 4),
            "modified_impact": round(m_impact, 4),
            "modified_exploitability": round(m_exploit, 4),
            "scope": scope,
            "modified_scope": m_scope,
            "temporal_metrics_supplied": has_temporal,
            "environmental_metrics_supplied": has_env,
        },
    )
