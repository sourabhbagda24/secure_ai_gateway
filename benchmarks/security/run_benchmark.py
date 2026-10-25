"""
CLI entry point for the Secure AI Gateway security benchmark.

Usage (from repository root):

    python -m benchmarks.security.run_benchmark
    python -m benchmarks.security.run_benchmark --out benchmarks/security/runs
    python -m benchmarks.security.run_benchmark --iterations 5 --warmup 1
    python -m benchmarks.security.run_benchmark --categories LLM01 LLM07
    python -m benchmarks.security.run_benchmark --compare-baseline

Exit codes:
    0  -> no critical findings (no attack succeeded, no leakage)
    1  -> one or more critical findings (attack won or leaked data)
    2  -> benchmark setup error (could not import / build a world)
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from .cases import ALL_SCENARIOS, by_category
from .metrics import Outcome, compute_all, false_positive_rate_by_kind
from .reporting import RunMetadata, write_csv, write_json, write_markdown
from .runner import run_all


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m benchmarks.security.run_benchmark",
        description="Reproducible security benchmark for the Secure AI Gateway.",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path("benchmarks/security/runs"),
        help="Directory to write timestamped run artifacts into.",
    )
    p.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Iterations per scenario (default: 1).",
    )
    p.add_argument(
        "--warmup",
        type=int,
        default=0,
        help="Warm-up runs per scenario, excluded from metrics (default: 0).",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed for any randomized behaviour. Only affects iteration order.",
    )
    p.add_argument(
        "--categories",
        nargs="+",
        default=None,
        help="Restrict to these categories (LLM01, LLM07, ...). Default: all.",
    )
    p.add_argument(
        "--compare-baseline",
        action="store_true",
        help="Also run the insecure baseline and include a comparison section.",
    )
    return p.parse_args(argv)


def _flush(msg: str) -> None:
    """Write to stderr so it is visible even when stdout is being piped."""
    print(msg, file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    random.seed(args.seed)

    scenarios = by_category(set(args.categories) if args.categories else None)
    if not scenarios:
        _flush(f"[benchmark] no scenarios matched categories={args.categories}")
        return 2

    metadata = RunMetadata.capture(
        iterations=args.iterations,
        warmup=args.warmup,
        seed=args.seed,
        categories=args.categories,
    )

    run_dir = args.out / metadata.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- secure
    _flush(f"[benchmark] running {len(scenarios)} scenarios against secure gateway...")
    try:
        secure_results = run_all(
            scenarios,
            target="secure",
            iterations=args.iterations,
            warmup=args.warmup,
        )
    except Exception as exc:  # noqa: BLE001
        _flush(f"[benchmark] secure target crashed: {type(exc).__name__}: {exc}")
        return 2

    secure_outcomes = [r.outcome for r in secure_results]
    secure_metrics = compute_all(secure_outcomes, target="secure")

    # Attach FPR-by-kind to the bundle manually (kept out of compute_all so
    # the core math stays minimal and easy to test).
    secure_metrics.fpr_by_kind = false_positive_rate_by_kind(secure_outcomes)

    # ---------------------------------------------------------------- baseline
    baseline_outcomes: list[Outcome] | None = None
    baseline_metrics = None
    if args.compare_baseline:
        _flush(f"[benchmark] running {len(scenarios)} scenarios against insecure baseline...")
        try:
            baseline_results = run_all(
                scenarios,
                target="baseline",
                iterations=args.iterations,
                warmup=args.warmup,
            )
            baseline_outcomes = [r.outcome for r in baseline_results]
            baseline_metrics = compute_all(baseline_outcomes, target="baseline")
            baseline_metrics.fpr_by_kind = false_positive_rate_by_kind(baseline_outcomes)
        except Exception as exc:  # noqa: BLE001
            _flush(f"[benchmark] baseline crashed (reporting without it): {type(exc).__name__}: {exc}")

    # ---------------------------------------------------------------- write
    write_json(
        run_dir / "report.json",
        metadata=metadata,
        secure_metrics=secure_metrics,
        secure_outcomes=secure_outcomes,
        baseline_metrics=baseline_metrics,
        baseline_outcomes=baseline_outcomes,
    )
    write_csv(run_dir / "outcomes.csv", secure_outcomes + (baseline_outcomes or []))
    write_markdown(
        run_dir / "report.md",
        metadata=metadata,
        secure_metrics=secure_metrics,
        baseline_metrics=baseline_metrics,
    )

    _flush(f"[benchmark] artifacts written to {run_dir}")

    # ---------------------------------------------------------------- exit code
    critical = False
    if secure_metrics.asr is not None and secure_metrics.asr > 0:
        _flush(f"[benchmark] CRITICAL: ASR={secure_metrics.asr:.3f} (> 0)")
        critical = True
    if secure_metrics.leakage_rate is not None and secure_metrics.leakage_rate > 0:
        _flush(f"[benchmark] CRITICAL: leakage_rate={secure_metrics.leakage_rate:.3f} (> 0)")
        critical = True

    return 1 if critical else 0


if __name__ == "__main__":
    sys.exit(main())