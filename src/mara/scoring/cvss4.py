"""CVSS v4.0 base/threat/environmental score calculator.

Port of the FIRST reference implementation
(https://github.com/FIRSTdotorg/cvss-v4-calculator, BSD-2-Clause,
Copyright FIRST, Red Hat, and contributors). The MacroVector lookup table
(cvss4_lookup.json), the EQ max-composed vectors and the max-severity depths are
reproduced verbatim from that repository; only the control flow is translated to
Python. Scores are computed by code, never declared by a language model.
"""

from __future__ import annotations

import json
import math
from importlib import resources

METRIC_ORDER: dict[str, list[str]] = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "P"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
    "E": ["X", "A", "P", "U"],
    "CR": ["X", "H", "M", "L"],
    "IR": ["X", "H", "M", "L"],
    "AR": ["X", "H", "M", "L"],
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
    "S": ["X", "N", "P"],
    "AU": ["X", "N", "Y"],
    "R": ["X", "A", "U", "I"],
    "V": ["X", "D", "C"],
    "RE": ["X", "L", "M", "H"],
    "U": ["X", "Clear", "Green", "Amber", "Red"],
}
BASE_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

MAX_COMPOSED = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {0: ["AC:L/AT:N/"], 1: ["AC:H/AT:N/", "AC:L/AT:P/"]},
    "eq3": {
        0: {
            "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        1: {
            "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            "1": [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        2: {"1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {0: ["SC:H/SI:S/SA:S/"], 1: ["SC:H/SI:H/SA:H/"], 2: ["SC:L/SI:L/SA:L/"]},
    "eq5": {0: ["E:A/"], 1: ["E:P/"], 2: ["E:U/"]},
}

MAX_SEVERITY = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "E": {"U": 0.2, "P": 0.1, "A": 0},
}


def _lookup() -> dict[str, float]:
    with resources.files("mara.scoring").joinpath("cvss4_lookup.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


LOOKUP = _lookup()


class CVSS4Error(ValueError):
    pass


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS:4.0 vector string into a metric map (missing optional metrics -> 'X')."""
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:4.0":
        raise CVSS4Error("vector must start with CVSS:4.0")
    selected: dict[str, str] = {k: "X" for k in METRIC_ORDER}
    seen: set[str] = set()
    for part in parts[1:]:
        if ":" not in part:
            raise CVSS4Error(f"malformed metric {part!r}")
        key, val = part.split(":", 1)
        if key not in METRIC_ORDER:
            raise CVSS4Error(f"unknown metric {key!r}")
        if val not in METRIC_ORDER[key]:
            raise CVSS4Error(f"invalid value {val!r} for {key}")
        if key in seen:
            raise CVSS4Error(f"duplicate metric {key}")
        seen.add(key)
        selected[key] = val
    missing = [k for k in BASE_METRICS if k not in seen]
    if missing:
        raise CVSS4Error(f"missing base metrics: {', '.join(missing)}")
    return selected


def _m(sel: dict[str, str], metric: str) -> str:
    v = sel.get(metric, "X")
    if metric == "E" and v == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and v == "X":
        return "H"
    mod = sel.get("M" + metric)
    if mod is not None and mod != "X":
        return mod
    return v


def macro_vector(sel: dict[str, str]) -> str:
    av, pr, ui = _m(sel, "AV"), _m(sel, "PR"), _m(sel, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if (_m(sel, "AC") == "L" and _m(sel, "AT") == "N") else 1
    vc, vi, va = _m(sel, "VC"), _m(sel, "VI"), _m(sel, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2
    if _m(sel, "MSI") == "S" or _m(sel, "MSA") == "S":
        eq4 = 0
    elif _m(sel, "SC") == "H" or _m(sel, "SI") == "H" or _m(sel, "SA") == "H":
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[_m(sel, "E")]
    cr, ir, ar = _m(sel, "CR"), _m(sel, "IR"), _m(sel, "AR")
    eq6 = 0 if ((cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H")) else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _extract(metric: str, vec: str) -> str:
    idx = vec.index(metric + ":") + len(metric) + 1
    rest = vec[idx:]
    return rest.split("/", 1)[0] if "/" in rest else rest


def score(vector: str) -> float:
    """Return the CVSS v4.0 numeric score (B, BT, BE or BTE depending on metrics present)."""
    sel = parse_vector(vector)
    if all(_m(sel, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    mv = macro_vector(sel)
    value = LOOKUP[mv]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in mv)

    def lk(key: str) -> float:
        return LOOKUP.get(key, math.nan)

    s_eq1 = lk(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}")
    s_eq2 = lk(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}")
    if eq3 == 1 and eq6 == 1:
        s_eq3eq6 = lk(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 0 and eq6 == 1:
        s_eq3eq6 = lk(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 1 and eq6 == 0:
        s_eq3eq6 = lk(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
    elif eq3 == 0 and eq6 == 0:
        left = lk(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
        right = lk(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        # same semantics as the JS reference: a NaN comparison is false, so `right` wins
        s_eq3eq6 = left if left > right else right
    else:
        s_eq3eq6 = lk(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")
    s_eq4 = lk(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}")
    s_eq5 = lk(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}")

    eq1_max = MAX_COMPOSED["eq1"][eq1]
    eq2_max = MAX_COMPOSED["eq2"][eq2]
    eq3eq6_max = MAX_COMPOSED["eq3"][eq3][str(eq6)]
    eq4_max = MAX_COMPOSED["eq4"][eq4]
    eq5_max = MAX_COMPOSED["eq5"][eq5]
    max_vectors = [
        a + b + c + d + e for a in eq1_max for b in eq2_max for c in eq3eq6_max for d in eq4_max for e in eq5_max
    ]
    dist: dict[str, float] = {}
    for mvec in max_vectors:
        dist = {k: LEVELS[k][_m(sel, k)] - LEVELS[k][_extract(k, mvec)] for k in LEVELS if k != "E"}
        if all(v >= 0 for v in dist.values()):
            break
    cur_eq1 = dist["AV"] + dist["PR"] + dist["UI"]
    cur_eq2 = dist["AC"] + dist["AT"]
    cur_eq3eq6 = dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"]
    cur_eq4 = dist["SC"] + dist["SI"] + dist["SA"]
    step = 0.1
    avail = {
        "eq1": value - s_eq1,
        "eq2": value - s_eq2,
        "eq3eq6": value - s_eq3eq6,
        "eq4": value - s_eq4,
        "eq5": value - s_eq5,
    }
    n_lower = 0
    normalized = 0.0
    if not math.isnan(avail["eq1"]):
        n_lower += 1
        normalized += avail["eq1"] * (cur_eq1 / (MAX_SEVERITY["eq1"][eq1] * step))
    if not math.isnan(avail["eq2"]):
        n_lower += 1
        normalized += avail["eq2"] * (cur_eq2 / (MAX_SEVERITY["eq2"][eq2] * step))
    if not math.isnan(avail["eq3eq6"]):
        n_lower += 1
        normalized += avail["eq3eq6"] * (cur_eq3eq6 / (MAX_SEVERITY["eq3eq6"][eq3][eq6] * step))
    if not math.isnan(avail["eq4"]):
        n_lower += 1
        normalized += avail["eq4"] * (cur_eq4 / (MAX_SEVERITY["eq4"][eq4] * step))
    if not math.isnan(avail["eq5"]):
        n_lower += 1  # eq5 contributes 0 distance by definition
    mean = 0.0 if n_lower == 0 else normalized / n_lower
    value = value - mean
    value = max(0.0, min(10.0, value))
    return round(value * 10) / 10


def severity(numeric: float) -> str:
    """Qualitative severity rating per the CVSS v4.0 specification, section 6."""
    if numeric == 0:
        return "None"
    if numeric < 4.0:
        return "Low"
    if numeric < 7.0:
        return "Medium"
    if numeric < 9.0:
        return "High"
    return "Critical"


def nomenclature(vector: str) -> str:
    """CVSS-B / CVSS-BT / CVSS-BE / CVSS-BTE per specification section 1.3."""
    sel = parse_vector(vector)
    has_t = sel.get("E", "X") != "X"
    env_keys = [k for k in METRIC_ORDER if k.startswith("M") or k in ("CR", "IR", "AR")]
    has_e = any(sel.get(k, "X") != "X" for k in env_keys)
    return "CVSS-B" + ("T" if has_t else "") + ("E" if has_e else "")
