# Secure AI Gateway — Measurable Security Benchmark

Reproducible, honest benchmark that measures the security of the
`secure-ai-gateway` gateway against an intentionally insecure baseline.

## What it measures

| Metric | Formula | Denominator |
|---|---|---|
| **Attack Success Rate (ASR)** | (# attacks where attacker won) / (# attacks) | All executed attack scenarios |
| **Attack Block Rate** | 1 − ASR | All executed attack scenarios |
| **False Positive Rate (FPR)** | (# legit scenarios blocked/failed) / (# legit scenarios) | All executed legit scenarios |
| **Unauthorized Data Leakage Rate** | (# leak-relevant attacks where sensitive content was observed) / (# leak-relevant attacks) | `pii_in_answer`, `secret_echo`, `rag_acl_bypass`, `cross_tenant_leak` |
| **Authorization Accuracy** | 1 − ASR (see `metrics.py` for the note on future divergence) | All executed attack scenarios |
| **Latency** | mean / median / p95 (nearest-rank) over monotonic-clock samples | All executed scenarios |

*"Attacker won"* means `Scenario.success(resp, world) is True`, i.e. the
scenario-specific success condition was met. **Leakage** is detected
independently of whether the request was blocked — a blocked request that
still leaked sensitive text counts as a leak. This is deliberate: aggregated
scores must never hide leakage.

## Files

| File | Purpose |
|---|---|
| `cases.py` | Scenario catalogue. Re-exports `redteam.attacks.ATTACKS` **unchanged** and adds legitimate-request scenarios. |
| `metrics.py` | Pure functions that compute each metric. No gateway imports, no side effects. |
| `runner.py` | Executes scenarios against `SecureAIGateway` or `NaiveGateway`. Records monotonic-clock latency. Scans responses for leak kinds (PII / secret / cross-tenant / ACL) without storing the matched value. |
| `reporting.py` | Writes JSON (canonical), CSV (flat), and Markdown (human) artifacts. Only safe fields are serialized — never payloads, never response text, never matched secrets. |
| `run_benchmark.py` | CLI entry point. |

## Running

From the repository root:

```powershell
# Default run
python -m benchmarks.security.run_benchmark

# Custom output directory and repetitions
python -m benchmarks.security.run_benchmark --out runs --iterations 5 --warmup 1

# Filter by category
python -m benchmarks.security.run_benchmark --categories LLM01 LLM07

# Include the insecure baseline comparison
python -m benchmarks.security.run_benchmark --compare-baseline