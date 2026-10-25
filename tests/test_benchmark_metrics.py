"""Unit tests for benchmark metric calculations. No gateway imports - pure math."""
from __future__ import annotations

import pytest

from benchmarks.security.metrics import (
    LEAKAGE_RELEVANT_SCENARIOS,
    LatencyStats,
    Outcome,
    attack_block_rate,
    attack_success_rate,
    authorization_accuracy,
    compute_all,
    count_attacks,
    count_leakage_relevant,
    count_legit,
    coverage_by_category,
    false_positive_rate,
    false_positive_rate_by_kind,
    latency_stats,
    unauthorized_data_leakage_rate,
)


def _o(sid, kind="attack", target="secure", success=False, blocked=False,
       leaked=False, latency=0.001, category="LLM01", note=""):
    return Outcome(
        scenario_id=sid, category=category, kind=kind, target=target,
        success=success, blocked=blocked, leaked=leaked,
        latency_s=latency, note=note,
    )


class TestASR:
    def test_empty_returns_none(self):
        assert attack_success_rate([]) is None

    def test_no_attacks_returns_none(self):
        assert attack_success_rate([_o("x", kind="legit")]) is None

    def test_all_blocked(self):
        rows = [_o(f"a{i}") for i in range(5)]
        assert attack_success_rate(rows) == 0.0

    def test_half_won(self):
        rows = [_o("a1", success=True), _o("a2", success=False)]
        assert attack_success_rate(rows) == 0.5

    def test_all_won(self):
        rows = [_o(f"a{i}", success=True) for i in range(4)]
        assert attack_success_rate(rows) == 1.0


class TestBlockRate:
    def test_complement_of_asr(self):
        rows = [_o("a1", success=True), _o("a2"), _o("a3")]
        assert attack_block_rate(rows) == pytest.approx(2 / 3)

    def test_empty(self):
        assert attack_block_rate([]) is None


class TestAuthzAccuracy:
    def test_equals_block_rate(self):
        rows = [_o("a1", success=True), _o("a2")]
        assert authorization_accuracy(rows) == attack_block_rate(rows)


class TestFPR:
    def test_empty(self):
        assert false_positive_rate([]) is None

    def test_no_legit(self):
        assert false_positive_rate([_o("a1")]) is None

    def test_legit_all_served(self):
        rows = [_o(f"l{i}", kind="legit", success=True) for i in range(3)]
        assert false_positive_rate(rows) == 0.0

    def test_one_blocked(self):
        rows = [_o("l1", kind="legit", success=True),
                _o("l2", kind="legit", success=False)]
        assert false_positive_rate(rows) == 0.5

    def test_mixed_kind_included(self):
        rows = [_o("l1", kind="legit", success=True),
                _o("ls1", kind="legit_suspicious", success=False)]
        assert false_positive_rate(rows) == 0.5

    def test_by_kind_distinguishes(self):
        rows = [
            _o("l1", kind="legit", success=True),
            _o("l2", kind="legit", success=True),
            _o("ls1", kind="legit_suspicious", success=False),
            _o("ls2", kind="legit_suspicious", success=True),
        ]
        out = false_positive_rate_by_kind(rows)
        assert out["legit"] == 0.0
        assert out["legit_suspicious"] == 0.5


class TestLeakage:
    def test_only_relevant_scenarios_in_denominator(self):
        rows = [_o("pii_in_answer"), _o("secret_echo"),
                _o("rag_acl_bypass"), _o("cross_tenant_leak")]
        assert count_leakage_relevant(rows) == 4

    def test_irrelevant_attack_excluded(self):
        rows = [_o("pii_in_answer"), _o("direct_injection")]
        assert count_leakage_relevant(rows) == 1
        assert unauthorized_data_leakage_rate(rows) == 0.0

    def test_leak_detected_even_if_blocked(self):
        rows = [
            _o("pii_in_answer", blocked=True, leaked=True),
            _o("secret_echo"),
            _o("rag_acl_bypass"),
            _o("cross_tenant_leak"),
        ]
        assert unauthorized_data_leakage_rate(rows) == 0.25

    def test_empty(self):
        assert unauthorized_data_leakage_rate([]) is None


class TestLatency:
    def test_empty(self):
        assert latency_stats([]) is None

    def test_single_value(self):
        s = latency_stats([_o("x", latency=0.123)])
        assert isinstance(s, LatencyStats)
        assert s.n == 1
        assert s.mean_s == pytest.approx(0.123)
        assert s.p95_s == pytest.approx(0.123)

    def test_basic_stats(self):
        vals = [1.0, 2.0, 3.0, 4.0, 5.0]
        s = latency_stats([_o(f"x{i}", latency=v) for i, v in enumerate(vals)])
        assert s.n == 5
        assert s.mean_s == pytest.approx(3.0)
        assert s.median_s == pytest.approx(3.0)
        assert s.min_s == 1.0
        assert s.max_s == 5.0

    def test_p95_nearest_rank(self):
        vals = list(range(1, 101))
        s = latency_stats([_o(f"x{i}", latency=float(v)) for i, v in enumerate(vals)])
        assert s.p95_s == 95.0

    def test_p95_small_n(self):
        vals = [1.0, 2.0, 3.0]
        s = latency_stats([_o(f"x{i}", latency=v) for i, v in enumerate(vals)])
        assert s.p95_s == 3.0


class TestCoverage:
    def test_groups_by_category(self):
        rows = [
            _o("a", category="LLM01", success=True),
            _o("b", category="LLM01"),
            _o("c", category="LLM02", success=True, leaked=True),
            _o("d", category="LLM00", kind="legit", success=True),
        ]
        cov = coverage_by_category(rows)
        by = {c.category: c for c in cov}
        assert by["LLM01"].attacks == 2
        assert by["LLM01"].attack_successes == 1
        assert by["LLM02"].leaks == 1
        assert by["LLM00"].legit == 1

    def test_sorted_by_category(self):
        rows = [_o("x", category="LLM05"), _o("y", category="LLM01")]
        cov = coverage_by_category(rows)
        assert [c.category for c in cov] == ["LLM01", "LLM05"]


class TestComputeAll:
    def test_rejects_mixed_targets(self):
        rows = [_o("x", target="secure"), _o("y", target="baseline")]
        with pytest.raises(ValueError):
            compute_all(rows, target="secure")

    def test_bundle_matches_individual_functions(self):
        rows = [
            _o("a1", success=True),
            _o("a2"),
            _o("l1", kind="legit", success=True),
            _o("pii_in_answer", leaked=True),
        ]
        bundle = compute_all(rows, target="secure")
        assert bundle.asr == attack_success_rate(rows)
        assert bundle.block_rate == attack_block_rate(rows)
        assert bundle.fpr == false_positive_rate(rows)
        assert bundle.leakage_rate == unauthorized_data_leakage_rate(rows)
        assert bundle.n_attacks == count_attacks(rows)
        assert bundle.n_legit == count_legit(rows)
        assert bundle.n_leakage_relevant == count_leakage_relevant(rows)
        assert bundle.fpr_by_kind == false_positive_rate_by_kind(rows)

    def test_to_dict_keys(self):
        bundle = compute_all([_o("x")], target="secure")
        d = bundle.to_dict()
        for k in (
            "target", "asr", "block_rate", "false_positive_rate",
            "false_positive_rate_by_kind", "unauthorized_data_leakage_rate",
            "authorization_accuracy", "latency", "sample_counts", "coverage",
        ):
            assert k in d
        assert d["sample_counts"] == {
            "attacks": 1, "legit": 0, "leakage_relevant": 0,
        }

    def test_none_when_no_samples(self):
        bundle = compute_all([], target="secure")
        assert bundle.asr is None
        assert bundle.block_rate is None
        assert bundle.fpr is None
        assert bundle.leakage_rate is None
        assert bundle.authz_accuracy is None
        assert bundle.latency is None


def test_leakage_relevant_set_is_stable():
    assert LEAKAGE_RELEVANT_SCENARIOS == frozenset({
        "pii_in_answer", "secret_echo", "rag_acl_bypass", "cross_tenant_leak",
    })