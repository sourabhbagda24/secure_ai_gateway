"""
Report writers for the Secure AI Gateway benchmark.

Design rules
------------
1. SAFE fields only. The following must NEVER appear in any report:
   - response text
   - raw scenario messages / payloads
   - PII, secrets, tokens, API keys (even the fake test ones)
   - matched leak values (only leak *kind* is allowed)
2. Every artifact is timestamped and self-describing so a run can be
   reproduced from the reports alone (given the same repo state).
3. JSON is canonical; CSV and Markdown are derived views.
"""
from __future__ import annotations

import csv
import json
import platform
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .metrics import MetricsBundle, Outcome

BENCHMARK_VERSION = "1.0.0"
SCHEMA_VERSION = "1"


# ---------------------------------------------------------------------------
# Per-run metadata - captured once, embedded in every report.
# ---------------------------------------------------------------------------

@dataclass
class RunMetadata:
    run_id: str
    started_at_utc: str
    python_version: str
    platform: str
    iterations: int
    warmup: int
    seed: int | None
    categories: list[str] | None
    benchmark_version: str = BENCHMARK_VERSION
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def capture(
        cls,
        *,
        iterations: int,
        warmup: int,
        seed: int | None,
        categories: list[str] | None,
    ) -> "RunMetadata":
        now = datetime.now(timezone.utc)
        return cls(
            run_id=now.strftime("%Y%m%dT%H%M%SZ"),
            started_at_utc=now.isoformat(),
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            platform=f"{platform.system()} {platform.release()}",
            iterations=iterations,
            warmup=warmup,
            seed=seed,
            categories=categories,
        )

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "started_at_utc": self.started_at_utc,
            "python_version": self.python_version,
            "platform": self.platform,
            "benchmark_version": self.benchmark_version,
            "schema_version": self.schema_version,
            "iterations": self.iterations,
            "warmup": self.warmup,
            "seed": self.seed,
            "categories_filter": self.categories,
        }


# ---------------------------------------------------------------------------
# Safe per-scenario serialization
# ---------------------------------------------------------------------------

def _safe_outcome_dict(o: Outcome) -> dict:
    """
    Serialize an Outcome for the report. NEVER includes response text,
    scenario messages, or matched leak values.
    """
    return {
        "scenario_id": o.scenario_id,
        "category": o.category,
        "kind": o.kind,
        "target": o.target,
        "success": bool(o.success),
        "blocked": bool(o.blocked),
        "leaked": bool(o.leaked),
        "latency_s": round(float(o.latency_s), 6),
        # `note` is restricted to gateway-provided codes like "prompt_injection"
        # or "raised:InjectionDetected" - never free-form text from the model.
        "note": o.note if o.note and len(o.note) <= 64 else "",
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def write_json(
    path: Path,
    *,
    metadata: RunMetadata,
    secure_metrics: MetricsBundle,
    secure_outcomes: list[Outcome],
    baseline_metrics: MetricsBundle | None = None,
    baseline_outcomes: list[Outcome] | None = None,
) -> None:
    """
    Write the canonical JSON report. This is the primary artifact; CSV and
    Markdown are derived from the same in-memory data.
    """
    payload: dict = {
        "metadata": metadata.to_dict(),
        "targets": {
            "secure": {
                "metrics": secure_metrics.to_dict(),
                "outcomes": [_safe_outcome_dict(o) for o in secure_outcomes],
            },
        },
    }
    if baseline_metrics is not None and baseline_outcomes is not None:
        payload["targets"]["baseline"] = {
            "metrics": baseline_metrics.to_dict(),
            "outcomes": [_safe_outcome_dict(o) for o in baseline_outcomes],
        }
        payload["comparison"] = _build_comparison(secure_metrics, baseline_metrics)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")


def _build_comparison(secure: MetricsBundle, baseline: MetricsBundle) -> dict:
    """
    Explicit secure-vs-baseline deltas. Fields with None are reported as None
    rather than 0 so that a missing sample cannot be silently read as a pass.
    """

    def _delta(a: float | None, b: float | None) -> float | None:
        if a is None or b is None:
            return None
        return round(a - b, 6)

    return {
        "asr_delta_secure_minus_baseline": _delta(secure.asr, baseline.asr),
        "block_rate_delta": _delta(secure.block_rate, baseline.block_rate),
        "fpr_delta": _delta(secure.fpr, baseline.fpr),
        "leakage_rate_delta": _delta(secure.leakage_rate, baseline.leakage_rate),
        "authz_accuracy_delta": _delta(secure.authz_accuracy, baseline.authz_accuracy),
    }


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "target",
    "scenario_id",
    "category",
    "kind",
    "success",
    "blocked",
    "leaked",
    "latency_s",
    "note",
]


def write_csv(path: Path, outcomes: list[Outcome]) -> None:
    """Flat CSV of per-scenario outcomes. Safe fields only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        for o in outcomes:
            writer.writerow(_safe_outcome_dict(o))


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _fmt_pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.2f}%"


def _fmt_lat(stats) -> str:
    if stats is None:
        return "n/a"
    return (
        f"n={stats.n}, mean={stats.mean_s*1000:.1f}ms, "
        f"median={stats.median_s*1000:.1f}ms, p95={stats.p95_s*1000:.1f}ms"
    )


def write_markdown(
    path: Path,
    *,
    metadata: RunMetadata,
    secure_metrics: MetricsBundle,
    baseline_metrics: MetricsBundle | None = None,
) -> None:
    """Human-readable summary. Contains no payloads, no secrets, no response text."""
    lines: list[str] = []
    lines.append("# Secure AI Gateway - Security Benchmark Report")
    lines.append("")
    lines.append(f"- **Run ID:** `{metadata.run_id}`")
    lines.append(f"- **Started (UTC):** {metadata.started_at_utc}")
    lines.append(f"- **Benchmark version:** {metadata.benchmark_version}")
    lines.append(f"- **Schema version:** {metadata.schema_version}")
    lines.append(f"- **Python:** {metadata.python_version}")
    lines.append(f"- **Platform:** {metadata.platform}")
    lines.append(f"- **Iterations per scenario:** {metadata.iterations}")
    lines.append(f"- **Warm-up runs per scenario:** {metadata.warmup}")
    lines.append(f"- **Seed:** {metadata.seed}")
    lines.append(f"- **Category filter:** {metadata.categories or 'none (all)'}")
    lines.append("")

    lines.extend(_metrics_section("Secure Gateway", secure_metrics))
    if baseline_metrics is not None:
        lines.extend(_metrics_section("Insecure Baseline", baseline_metrics))
        lines.extend(_comparison_section(secure_metrics, baseline_metrics))

    lines.append("## Notes")
    lines.append("")
    lines.append("- Leakage is reported as a **critical** metric: a scenario is")
    lines.append("  counted as leaked even if the gateway marked the request blocked.")
    lines.append("- ASR is defined as `(# attack scenarios where the attacker won) /")
    lines.append("  (# attack scenarios)`. For the secure gateway this must be 0.0 to")
    lines.append("  indicate every catalogued attack was neutralised.")
    lines.append("- False-positive rate is `(# legit scenarios blocked or served")
    lines.append("  incorrectly) / (# legit scenarios)`. A `legit_suspicious` false")
    lines.append("  positive is *not* the same as a `legit` false positive.")
    lines.append("- Latency percentiles use the nearest-rank method.")
    lines.append("- No statistical-significance claim is made. Sample sizes are")
    lines.append("  reported alongside the metrics.")
    lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _metrics_section(title: str, m: MetricsBundle) -> list[str]:
    lines = [f"## {title}", ""]
    lines.append("| Metric | Value | Samples |")
    lines.append("|---|---|---|")
    lines.append(f"| Attack Success Rate (ASR) | {_fmt_pct(m.asr)} | {m.n_attacks} |")
    lines.append(f"| Attack Block Rate | {_fmt_pct(m.block_rate)} | {m.n_attacks} |")
    lines.append(f"| False Positive Rate | {_fmt_pct(m.fpr)} | {m.n_legit} |")
    lines.append(
        f"| Unauthorized Data Leakage Rate | {_fmt_pct(m.leakage_rate)} | {m.n_leakage_relevant} |"
    )
    lines.append(f"| Authorization Accuracy | {_fmt_pct(m.authz_accuracy)} | {m.n_attacks} |")
    lines.append(f"| Latency | {_fmt_lat(m.latency)} | {m.latency.n if m.latency else 0} |")
    lines.append("")

    if m.coverage:
        lines.append("### Coverage by category")
        lines.append("")
        lines.append("| Category | Attacks | Legit | Attack successes | Leaks |")
        lines.append("|---|---|---|---|---|")
        for c in m.coverage:
            lines.append(
                f"| {c.category} | {c.attacks} | {c.legit} | {c.attack_successes} | {c.leaks} |"
            )
        lines.append("")
    return lines


def _comparison_section(secure: MetricsBundle, baseline: MetricsBundle) -> list[str]:
    lines = ["## Secure vs Baseline", ""]
    lines.append("| Metric | Secure | Baseline | Delta (secure - baseline) |")
    lines.append("|---|---|---|---|")

    def _row(name: str, a: float | None, b: float | None) -> None:
        delta = "n/a" if (a is None or b is None) else _fmt_pct(a - b)
        lines.append(f"| {name} | {_fmt_pct(a)} | {_fmt_pct(b)} | {delta} |")

    _row("ASR", secure.asr, baseline.asr)
    _row("Block Rate", secure.block_rate, baseline.block_rate)
    _row("FPR", secure.fpr, baseline.fpr)
    _row("Leakage Rate", secure.leakage_rate, baseline.leakage_rate)
    _row("Authz Accuracy", secure.authz_accuracy, baseline.authz_accuracy)
    lines.append("")
    return lines