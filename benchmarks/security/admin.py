"""Admin dashboard data provider."""
from __future__ import annotations

import json
from pathlib import Path

BENCHMARKS_DIR = Path(__file__).parent / "runs"


def get_admin_stats() -> dict:
    if not BENCHMARKS_DIR.is_dir():
        return {"error": "No benchmark runs found", "runs": []}

    runs = sorted(
        [p for p in BENCHMARKS_DIR.iterdir()
         if p.is_dir() and (p / "report.json").is_file()],
        key=lambda p: p.name,
        reverse=True,
    )

    if not runs:
        return {"error": "No benchmark runs found", "runs": []}

    latest = runs[0]
    report = json.loads((latest / "report.json").read_text(encoding="utf-8"))
    secure = report.get("targets", {}).get("secure", {}).get("metrics", {})
    baseline = report.get("targets", {}).get("baseline", {}).get("metrics", {})
    comparison = report.get("comparison", {})

    outcomes = report.get("targets", {}).get("secure", {}).get("outcomes", [])
    total_attacks = sum(1 for o in outcomes if o.get("kind") == "attack")
    blocked_count = sum(1 for o in outcomes if o.get("kind") == "attack" and o.get("blocked"))
    leaked_count = sum(1 for o in outcomes if o.get("kind") == "attack" and o.get("leaked"))

    return {
        "run_id": latest.name,
        "total_runs": len(runs),
        "all_runs": [r.name for r in runs],
        "secure": {
            "asr": secure.get("asr"),
            "block_rate": secure.get("block_rate"),
            "fpr": secure.get("false_positive_rate"),
            "leakage": secure.get("unauthorized_data_leakage_rate"),
            "authz_accuracy": secure.get("authorization_accuracy"),
            "latency": secure.get("latency"),
        },
        "baseline": {
            "asr": baseline.get("asr"),
            "leakage": baseline.get("unauthorized_data_leakage_rate"),
        },
        "comparison": comparison,
        "attack_stats": {
            "total": total_attacks,
            "blocked_explicitly": blocked_count,
            "neutralized_total": total_attacks - (1 if secure.get("asr") else 0),
            "leaked": leaked_count,
        },
    }