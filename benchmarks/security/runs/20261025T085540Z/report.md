# Secure AI Gateway - Security Benchmark Report

- **Run ID:** `20261025T085540Z`
- **Started (UTC):** 2026-10-25T08:55:40.663400+00:00
- **Benchmark version:** 1.0.0
- **Schema version:** 1
- **Python:** 3.11.1
- **Platform:** Windows 10
- **Iterations per scenario:** 1
- **Warm-up runs per scenario:** 0
- **Seed:** None
- **Category filter:** none (all)

## Secure Gateway

| Metric | Value | Samples |
|---|---|---|
| Attack Success Rate (ASR) | 0.00% | 33 |
| Attack Block Rate | 100.00% | 33 |
| False Positive Rate | 10.00% | 10 |
| Unauthorized Data Leakage Rate | 0.00% | 4 |
| Authorization Accuracy | 100.00% | 33 |
| Latency | n=43, mean=2.9ms, median=0.0ms, p95=16.0ms | 43 |

### Coverage by category

| Category | Attacks | Legit | Attack successes | Leaks |
|---|---|---|---|---|
| LLM00 | 0 | 10 | 0 | 0 |
| LLM01 | 7 | 0 | 0 | 0 |
| LLM02 | 2 | 0 | 0 | 0 |
| LLM04 | 1 | 0 | 0 | 0 |
| LLM05 | 7 | 0 | 0 | 0 |
| LLM06 | 9 | 0 | 0 | 0 |
| LLM07 | 1 | 0 | 0 | 0 |
| LLM08 | 2 | 0 | 0 | 0 |
| LLM10 | 4 | 0 | 0 | 0 |

## Insecure Baseline

| Metric | Value | Samples |
|---|---|---|
| Attack Success Rate (ASR) | 69.70% | 33 |
| Attack Block Rate | 30.30% | 33 |
| False Positive Rate | 0.00% | 10 |
| Unauthorized Data Leakage Rate | 100.00% | 4 |
| Authorization Accuracy | 30.30% | 33 |
| Latency | n=43, mean=2.9ms, median=0.0ms, p95=16.0ms | 43 |

### Coverage by category

| Category | Attacks | Legit | Attack successes | Leaks |
|---|---|---|---|---|
| LLM00 | 0 | 10 | 0 | 0 |
| LLM01 | 7 | 0 | 6 | 0 |
| LLM02 | 2 | 0 | 2 | 2 |
| LLM04 | 1 | 0 | 1 | 0 |
| LLM05 | 7 | 0 | 4 | 0 |
| LLM06 | 9 | 0 | 5 | 0 |
| LLM07 | 1 | 0 | 1 | 0 |
| LLM08 | 2 | 0 | 2 | 2 |
| LLM10 | 4 | 0 | 2 | 0 |

## Secure vs Baseline

| Metric | Secure | Baseline | Delta (secure - baseline) |
|---|---|---|---|
| ASR | 0.00% | 69.70% | -69.70% |
| Block Rate | 100.00% | 30.30% | 69.70% |
| FPR | 10.00% | 0.00% | 10.00% |
| Leakage Rate | 0.00% | 100.00% | -100.00% |
| Authz Accuracy | 100.00% | 30.30% | 69.70% |

## Notes

- Leakage is reported as a **critical** metric: a scenario is
  counted as leaked even if the gateway marked the request blocked.
- ASR is defined as `(# attack scenarios where the attacker won) /
  (# attack scenarios)`. For the secure gateway this must be 0.0 to
  indicate every catalogued attack was neutralised.
- False-positive rate is `(# legit scenarios blocked or served
  incorrectly) / (# legit scenarios)`. A `legit_suspicious` false
  positive is *not* the same as a `legit` false positive.
- Latency percentiles use the nearest-rank method.
- No statistical-significance claim is made. Sample sizes are
  reported alongside the metrics.
