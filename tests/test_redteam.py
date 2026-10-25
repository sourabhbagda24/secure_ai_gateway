import pytest

from redteam.attacks import ATTACKS
from redteam.baseline import NaiveGateway
from run_redteam import run_one


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_secure_gateway_defeats_attack(attack):
    breached, resp = run_one(attack, secure=True)
    assert not breached, f"{attack.id} succeeded against the secure gateway: {resp.text!r}"


# these attacks must WORK on the insecure baseline, otherwise the test above proves nothing
NOT_EXPLOITABLE_ON_BASELINE = {
    "sql_stacked",
    "csv_formula_injection",
    "xxe_injection",
    "regex_dos",
    "tool_description_poisoning",
    "memory_exhaustion",
    "ssrf_internal_url",
    "jwt_alg_none",
    "path_traversal_null",
    "homoglyph_injection",
}


@pytest.mark.parametrize("attack", [a for a in ATTACKS if a.id not in NOT_EXPLOITABLE_ON_BASELINE], ids=lambda a: a.id)
def test_attack_is_real_on_insecure_baseline(attack):
    exploited, _ = run_one(attack, secure=False)
    assert exploited, f"{attack.id} does not work on the baseline - the test is meaningless"


def test_catalogue_covers_owasp_categories():
    assert {"LLM01", "LLM02", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM10"} <= {a.owasp for a in ATTACKS}