import json
from pathlib import Path

import pytest

from mara.scoring import cvss4

REF = json.loads((Path(__file__).parent / "cvss4_reference.json").read_text())


@pytest.mark.parametrize("vector", sorted(REF))
def test_matches_first_reference_implementation(vector):
    """Reference scores were produced by running FIRST's cvss_score.js under node."""
    assert cvss4.macro_vector(cvss4.parse_vector(vector)) == REF[vector]["macro"]
    assert cvss4.score(vector) == pytest.approx(REF[vector]["score"])


def test_rejects_missing_base_metric():
    with pytest.raises(cvss4.CVSS4Error):
        cvss4.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N")


def test_rejects_bad_value():
    with pytest.raises(cvss4.CVSS4Error):
        cvss4.score("CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


def test_severity_bands():
    assert cvss4.severity(0.0) == "None"
    assert cvss4.severity(3.9) == "Low"
    assert cvss4.severity(6.9) == "Medium"
    assert cvss4.severity(8.9) == "High"
    assert cvss4.severity(9.0) == "Critical"


def test_nomenclature():
    base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert cvss4.nomenclature(base) == "CVSS-B"
    assert cvss4.nomenclature(base + "/E:P") == "CVSS-BT"
    assert cvss4.nomenclature(base + "/CR:L") == "CVSS-BE"
    assert cvss4.nomenclature(base + "/E:P/MAV:A") == "CVSS-BTE"
