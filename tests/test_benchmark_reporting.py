"""Safety + schema tests for benchmark report writers."""
from __future__ import annotations

import json

import pytest

from benchmarks.security.metrics import compute_all, Outcome
from benchmarks.security.reporting import (
    BENCHMARK_VERSION,
    SCHEMA_VERSION,
    RunMetadata,
    write_csv,
    write_json,
    write_markdown,
)


def _o(sid, kind="attack", target="secure", success=False, blocked=False,
       leaked=False, latency=0.001, category="LLM01", note=""):
    return Outcome(
        scenario_id=sid, category=category, kind=kind, target=target,
        success=success, blocked=blocked, leaked=leaked,
        latency_s=latency, note=note,
    )


def _metadata():
    return RunMetadata.capture(iterations=1, warmup=0, seed=42, categories=None)


def _sample_outcomes(target: str) -> list[Outcome]:
    return [
        _o("direct_injection", target=target, blocked=True, note="prompt_injection"),
        _o("pii_in_answer", target=target, leaked=True),
        _o("legit_rag_refund", kind="legit", target=target, success=True),
        _o("legit_mentions_ignore_word", kind="legit_suspicious",
           target=target, success=False, blocked=True, note="prompt_injection"),
    ]


class TestMetadata:
    def test_metadata_has_version_and_run_id(self):
        m = _metadata()
        d = m.to_dict()
        assert d["benchmark_version"] == BENCHMARK_VERSION
        assert d["schema_version"] == SCHEMA_VERSION
        assert d["run_id"].endswith("Z")
        assert "T" in d["run_id"]

    def test_metadata_records_seed(self):
        m = _metadata()
        assert m.to_dict()["seed"] == 42


class TestJSON:
    def test_json_has_secure_section(self, tmp_path):
        outcomes = _sample_outcomes("secure")
        bundle = compute_all(outcomes, target="secure")
        path = tmp_path / "report.json"
        write_json(path, metadata=_metadata(),
                   secure_metrics=bundle, secure_outcomes=outcomes)
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert "metadata" in payload
        assert "secure" in payload["targets"]
        assert payload["targets"]["secure"]["metrics"]["target"] == "secure"

    def test_json_baseline_comparison(self, tmp_path):
        sec_o = _sample_outcomes("secure")
        base_o = _sample_outcomes("baseline")
        sec_b = compute_all(sec_o, target="secure")
        base_b = compute_all(base_o, target="baseline")
        path = tmp_path / "report.json"
        write_json(path, metadata=_metadata(),
                   secure_metrics=sec_b, secure_outcomes=sec_o,
                   baseline_metrics=base_b, baseline_outcomes=base_o)
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert "baseline" in payload["targets"]
        assert "comparison" in payload
        comp = payload["comparison"]
        assert "asr_delta_secure_minus_baseline" in comp

    def test_json_outcomes_have_no_extra_fields(self, tmp_path):
        outcomes = _sample_outcomes("secure")
        bundle = compute_all(outcomes, target="secure")
        path = tmp_path / "report.json"
        write_json(path, metadata=_metadata(),
                   secure_metrics=bundle, secure_outcomes=outcomes)
        payload = json.loads(path.read_text(encoding="utf-8"))
        allowed = {
            "scenario_id", "category", "kind", "target",
            "success", "blocked", "leaked", "latency_s", "note",
        }
        for o in payload["targets"]["secure"]["outcomes"]:
            assert set(o.keys()) == allowed, f"unexpected keys in {o}"


class TestCSV:
    def test_csv_has_header_and_rows(self, tmp_path):
        path = tmp_path / "outcomes.csv"
        write_csv(path, _sample_outcomes("secure"))
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert lines[0].startswith("target,scenario_id,category")
        assert len(lines) == 5


class TestMarkdown:
    def test_markdown_contains_expected_sections(self, tmp_path):
        outcomes = _sample_outcomes("secure")
        bundle = compute_all(outcomes, target="secure")
        path = tmp_path / "report.md"
        write_markdown(path, metadata=_metadata(), secure_metrics=bundle)
        text = path.read_text(encoding="utf-8")
        for phrase in (
            "# Secure AI Gateway",
            "## Secure Gateway",
            "Attack Success Rate",
            "False Positive Rate",
            "Unauthorized Data Leakage Rate",
            "## Notes",
        ):
            assert phrase in text


_SENSITIVE_MARKERS = [
    "9876543210",
    "support@acme.com",
    "sk-ant-abcdefghijkl",
    "launches in Q4",
    "90000",
    "ignore all previous instructions",
    "Ignore all previous instructions",
    "my key is",
]


def test_reports_contain_no_sensitive_payloads(tmp_path):
    """Regression guard: report artifacts must not contain raw payloads,
    PII markers, secrets, or matched leak values, even when those
    payloads were used in the benchmark."""
    outcomes = _sample_outcomes("secure")
    bundle = compute_all(outcomes, target="secure")

    json_path = tmp_path / "report.json"
    csv_path = tmp_path / "outcomes.csv"
    md_path = tmp_path / "report.md"

    write_json(json_path, metadata=_metadata(),
               secure_metrics=bundle, secure_outcomes=outcomes)
    write_csv(csv_path, outcomes)
    write_markdown(md_path, metadata=_metadata(), secure_metrics=bundle)

    for p in (json_path, csv_path, md_path):
        text = p.read_text(encoding="utf-8")
        for marker in _SENSITIVE_MARKERS:
            assert marker not in text, (
                f"SECURITY: {marker!r} appeared in {p.name}"
            )


def test_notes_are_truncated(tmp_path):
    """A long free-form note must be dropped, not included verbatim."""
    long_note = "x" * 200
    outcomes = [_o("a", note=long_note)]
    bundle = compute_all(outcomes, target="secure")
    path = tmp_path / "report.json"
    write_json(path, metadata=_metadata(),
               secure_metrics=bundle, secure_outcomes=outcomes)
    payload = json.loads(path.read_text(encoding="utf-8"))
    out = payload["targets"]["secure"]["outcomes"][0]
    assert len(out["note"]) <= 64