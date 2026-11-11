"""CVSS v4.0 scoring - faithful port of the FIRST.org reference implementation.

References:
  https://www.first.org/cvss/v4-0/specification-document   (Section 8, scoring)
  https://github.com/FIRSTdotorg/cvss-v4-calculator          (score.js)

The algorithm is *not* a closed-form equation. It is:
  1. reduce the 11 relevant metrics to a 6-digit MacroVector (EQ1..EQ6)
  2. look the MacroVector up in the official 270-entry score table
  3. interpolate downwards, per equivalence class, by the proportional
     severity distance between this vector and the maximal vector of its class

Steps 2 and 3 depend on tables that ship in `v4_tables.py`, generated verbatim
from FIRST's published JavaScript. Nothing here is approximated.
"""
from __future__ import annotations

from .common import (
    round_half_up_1,
    CVSSError,
    CVSSResult,
    MetricBreakdown,
    parse_vector,
    severity_rating,
)
from .v4_tables import CVSS_LOOKUP, MAX_COMPOSED, MAX_SEVERITY

ALLOWED: dict[str, list[str]] = {
    # Base - Exploitability
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "P"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "A"],
    # Base - Vulnerable system impact
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    # Base - Subsequent system impact
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
    # Threat
    "E": ["X", "A", "P", "U"],
    # Environmental - requirements
    "CR": ["X", "H", "M", "L"],
    "IR": ["X", "H", "M", "L"],
    "AR": ["X", "H", "M", "L"],
    # Environmental - modified base
    "MAV": ["X", "N", "A", "L", "P"],
    "MAC": ["X", "L", "H"],
    "MAT": ["X", "N", "P"],
    "MPR": ["X", "N", "L", "H"],
    "MUI": ["X", "N", "P", "A"],
    "MVC": ["X", "H", "L", "N"],
    "MVI": ["X", "H", "L", "N"],
    "MVA": ["X", "H", "L", "N"],
    "MSC": ["X", "H", "L", "N"],
    "MSI": ["X", "S", "H", "L", "N"],
    "MSA": ["X", "S", "H", "L", "N"],
    # Supplemental (informational only - never affect the score)
    "S": ["X", "N", "P"],
    "AU": ["X", "N", "Y"],
    "R": ["X", "A", "U", "I"],
    "V": ["X", "D", "C"],
    "RE": ["X", "L", "M", "H"],
    "U": ["X", "Clear", "Green", "Amber", "Red"],
}

MANDATORY = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
SUPPLEMENTAL = ["S", "AU", "R", "V", "RE", "U"]

# Severity-distance ladders (score.js: *_levels)
LEVELS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.05, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.05, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

NAMES = {
    "AV": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack Complexity", {"L": "Low", "H": "High"}),
    "AT": ("Attack Requirements", {"N": "None", "P": "Present"}),
    "PR": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction", {"N": "None", "P": "Passive", "A": "Active"}),
    "VC": ("Vulnerable System Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "VI": ("Vulnerable System Integrity", {"H": "High", "L": "Low", "N": "None"}),
    "VA": ("Vulnerable System Availability", {"H": "High", "L": "Low", "N": "None"}),
    "SC": ("Subsequent System Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "SI": ("Subsequent System Integrity", {"H": "High", "L": "Low", "N": "None", "S": "Safety"}),
    "SA": ("Subsequent System Availability", {"H": "High", "L": "Low", "N": "None", "S": "Safety"}),
    "E": ("Exploit Maturity", {"X": "Not Defined", "A": "Attacked",
                               "P": "Proof-of-Concept", "U": "Unreported"}),
    "CR": ("Confidentiality Requirement", {"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}),
    "IR": ("Integrity Requirement", {"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}),
    "AR": ("Availability Requirement", {"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}),
    "S": ("Safety", {"X": "Not Defined", "N": "Negligible", "P": "Present"}),
    "AU": ("Automatable", {"X": "Not Defined", "N": "No", "Y": "Yes"}),
    "R": ("Recovery", {"X": "Not Defined", "A": "Automatic", "U": "User", "I": "Irrecoverable"}),
    "V": ("Value Density", {"X": "Not Defined", "D": "Diffuse", "C": "Concentrated"}),
    "RE": ("Vulnerability Response Effort", {"X": "Not Defined", "L": "Low",
                                             "M": "Moderate", "H": "High"}),
    "U": ("Provider Urgency", {"X": "Not Defined", "Clear": "Clear", "Green": "Green",
                               "Amber": "Amber", "Red": "Red"}),
}


# Grouping used by the calculator UI (spec section 1.2 metric groups).
BASE_ORDER = list(MANDATORY)
THREAT_ORDER = ["E"]
ENV_ORDER = ["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
             "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]
SUPPLEMENTAL_ORDER = list(SUPPLEMENTAL)
MODIFIED_OF = {f"M{m}": m for m in MANDATORY}

VECTOR_ORDER = (
    MANDATORY + ["E", "CR", "IR", "AR"]
    + ["MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]
    + SUPPLEMENTAL
)


class _Vector:
    """Metric accessor implementing score.js `m()` - modified-metric resolution."""

    def __init__(self, raw: dict[str, str]):
        self.raw = raw

    def m(self, metric: str) -> str:
        selected = self.raw.get(metric, "X")
        modified = self.raw.get(f"M{metric}", "X")
        if modified != "X":
            return modified
        if metric == "E" and selected == "X":
            return "A"  # worst case: Attacked
        if metric in ("CR", "IR", "AR") and selected == "X":
            return "H"  # worst case: High requirement
        return selected


def _macro_vector(v: _Vector) -> str:
    av, pr, ui = v.m("AV"), v.m("PR"), v.m("UI")
    ac, at = v.m("AC"), v.m("AT")
    vc, vi, va = v.m("VC"), v.m("VI"), v.m("VA")
    sc, si, sa = v.m("SC"), v.m("SI"), v.m("SA")
    e = v.m("E")
    cr, ir, ar = v.m("CR"), v.m("IR"), v.m("AR")
    msi, msa = v.raw.get("MSI", "X"), v.raw.get("MSA", "X")

    # EQ1
    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = "1"
    else:
        eq1 = "2"

    # EQ2
    eq2 = "0" if (ac == "L" and at == "N") else "1"

    # EQ3
    if vc == "H" and vi == "H":
        eq3 = "0"
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = "1"
    else:
        eq3 = "2"

    # EQ4 - Safety on the subsequent system dominates
    if msi == "S" or msa == "S":
        eq4 = "0"
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = "1"
    else:
        eq4 = "2"

    # EQ5 - exploit maturity
    eq5 = {"A": "0", "P": "1", "U": "2"}[e]

    # EQ6 - security requirements against the vulnerable system
    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = "0"
    else:
        eq6 = "1"

    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _lookup(macro: str) -> float | None:
    return CVSS_LOOKUP.get(macro)


def _extract(vector_str: str, metric: str) -> str:
    """score.js extractValueMetric - read a metric out of a partial max-vector."""
    index = vector_str.index(metric) + len(metric) + 1
    rest = vector_str[index:]
    end = rest.find("/")
    return rest if end < 0 else rest[:end]


def _eq_maxes(macro: str, eq: int) -> list[str]:
    return MAX_COMPOSED[f"eq{eq}"][macro[eq - 1]]


def score(vector: str) -> CVSSResult:
    v = vector.strip()
    if not v.upper().startswith("CVSS:4.0/"):
        raise CVSSError("CVSS v4.0 vectors must start with CVSS:4.0/")
    raw = parse_vector(v[len("CVSS:4.0/"):])

    for key in MANDATORY:
        if key not in raw:
            raise CVSSError(f"CVSS v4.0 base metric {key} is mandatory")
    for key, value in raw.items():
        if key not in ALLOWED:
            raise CVSSError(f"unknown CVSS v4.0 metric {key!r}")
        if value not in ALLOWED[key]:
            raise CVSSError(f"illegal value {value!r} for metric {key}")

    vec = _Vector(raw)

    # A vulnerability with no impact anywhere scores 0.0 by definition.
    if all(vec.m(m) == "N" for m in ("VC", "VI", "VA", "SC", "SI", "SA")):
        final = 0.0
        macro = _macro_vector(vec)
        intermediates: dict[str, object] = {"macro_vector": macro, "zero_impact": True}
    else:
        macro = _macro_vector(vec)
        value = _lookup(macro)
        if value is None:
            raise CVSSError(f"MacroVector {macro} missing from the official lookup table")

        eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in macro)

        # --- 1. scores of the next-lower MacroVector in each equivalence class
        lower_eq1 = _lookup(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}")
        lower_eq2 = _lookup(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}")
        lower_eq4 = _lookup(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}")
        lower_eq5 = _lookup(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}")

        # EQ3 and EQ6 are jointly constrained: not every pair exists.
        if eq3 == 1 and eq6 == 1:
            lower_eq3eq6 = _lookup(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        elif eq3 == 0 and eq6 == 1:
            lower_eq3eq6 = _lookup(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        elif eq3 == 1 and eq6 == 0:
            lower_eq3eq6 = _lookup(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
        elif eq3 == 0 and eq6 == 0:
            left = _lookup(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
            right = _lookup(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
            lower_eq3eq6 = max(left or 0.0, right or 0.0) if (left or right) else None
        else:
            lower_eq3eq6 = _lookup(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")

        # --- 2. the maximal vector of this MacroVector
        eq3eq6_maxes = MAX_COMPOSED["eq3"][str(eq3)][str(eq6)]
        max_vectors = [
            a + b + c + d + e
            for a in _eq_maxes(macro, 1)
            for b in _eq_maxes(macro, 2)
            for c in eq3eq6_maxes
            for d in _eq_maxes(macro, 4)
            for e in _eq_maxes(macro, 5)
        ]

        distances: dict[str, float] = {}
        for candidate in max_vectors:
            trial = {}
            ok = True
            for metric in ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA",
                           "SC", "SI", "SA", "CR", "IR", "AR"):
                current = LEVELS[metric][vec.m(metric)]
                maximum = LEVELS[metric][_extract(candidate, metric)]
                delta = current - maximum
                if delta < 0:
                    ok = False
                    break
                trial[metric] = delta
            if ok:
                distances = trial
                break

        step = 0.1
        current_eq1 = distances["AV"] + distances["PR"] + distances["UI"]
        current_eq2 = distances["AC"] + distances["AT"]
        current_eq3eq6 = (distances["VC"] + distances["VI"] + distances["VA"]
                          + distances["CR"] + distances["IR"] + distances["AR"])
        current_eq4 = distances["SC"] + distances["SI"] + distances["SA"]

        max_eq1 = MAX_SEVERITY["eq1"][str(eq1)] * step
        max_eq2 = MAX_SEVERITY["eq2"][str(eq2)] * step
        max_eq3eq6 = MAX_SEVERITY["eq3eq6"][str(eq3)][str(eq6)] * step
        max_eq4 = MAX_SEVERITY["eq4"][str(eq4)] * step

        # --- 3. proportional interpolation across the classes that have a lower neighbour
        normalized: list[float] = []
        for available, current, maximum in (
            (None if lower_eq1 is None else value - lower_eq1, current_eq1, max_eq1),
            (None if lower_eq2 is None else value - lower_eq2, current_eq2, max_eq2),
            (None if lower_eq3eq6 is None else value - lower_eq3eq6, current_eq3eq6, max_eq3eq6),
            (None if lower_eq4 is None else value - lower_eq4, current_eq4, max_eq4),
            (None if lower_eq5 is None else value - lower_eq5, 0.0, 1.0),
        ):
            if available is None:
                continue
            percent = 0.0 if maximum == 0 else current / maximum
            normalized.append(available * percent)

        mean_distance = (sum(normalized) / len(normalized)) if normalized else 0.0
        final = round_half_up_1(max(0.0, min(10.0, value - mean_distance)))

        intermediates = {
            "macro_vector": macro,
            "macro_vector_score": value,
            "mean_distance": round(mean_distance, 6),
            "severity_distances": {k: round(x, 4) for k, x in distances.items()},
            "lower_macro_scores": {
                "eq1": lower_eq1, "eq2": lower_eq2, "eq3eq6": lower_eq3eq6,
                "eq4": lower_eq4, "eq5": lower_eq5,
            },
        }

    # Nomenclature per spec section 1.3: CVSS-B / BE / BT / BTE
    has_threat = raw.get("E", "X") != "X"
    has_env = any(
        raw.get(k, "X") != "X"
        for k in ("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
                  "MVC", "MVI", "MVA", "MSC", "MSI", "MSA")
    )
    nomenclature = "CVSS-B" + ("T" if has_threat else "") + ("E" if has_env else "")

    metrics: list[MetricBreakdown] = []
    for key in VECTOR_ORDER:
        value_ = raw.get(key, "X")
        base_key = key[1:] if key.startswith("M") and key[1:] in NAMES else key
        name, value_names = NAMES[base_key]
        if key.startswith("M") and base_key != key:
            name = f"Modified {name}"
        group = ("Base" if key in MANDATORY
                 else "Threat" if key == "E"
                 else "Supplemental" if key in SUPPLEMENTAL else "Environmental")
        metrics.append(
            MetricBreakdown(
                abbrev=key, name=name, value=value_,
                value_name=value_names.get(value_, "Not Defined" if value_ == "X" else value_),
                group=group, weight=None, defaulted=key not in raw,
            )
        )

    canonical = "CVSS:4.0/" + "/".join(
        f"{k}:{raw[k]}" for k in VECTOR_ORDER if k in raw
    )
    return CVSSResult(
        version="4.0",
        vector=canonical,
        base_score=final,
        base_severity=severity_rating(final, "4.0"),
        nomenclature=nomenclature,
        metrics=metrics,
        intermediates=intermediates,
    )
