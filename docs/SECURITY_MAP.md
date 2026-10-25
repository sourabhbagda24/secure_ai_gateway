# Security map: concern -> code -> tests

OWASP IDs refer to the *OWASP Top 10 for LLM Applications (2025)*.

## Development phase
| Concern | Where in this project | Tests |
|---|---|---|
| Data privacy / PII | `pii_filter.py` (also used on input, output, logs, memory) | `test_pii.py` |
| Secrets management | `config.py` (secret from env, never source) + `dev_checks/secret_scanner.py` | `test_dev_checks.py` |
| Dependency security | `dev_checks/dependency_check.py` (pinning + advisories; use `pip-audit` for real CVEs) | `test_dev_checks.py` |
| Training-data poisoning (LLM04) | `dev_checks/dataset_check.py` | `test_dev_checks.py` |
| Prompt-injection testing | `redteam/` (20 attacks, insecure baseline vs secure gateway) | `test_redteam.py` |
| RAG security (LLM08) | `rag.py` (ACL + tenant filter *before* ranking, quarantine, escaping) | `test_rag.py` |
| Model & supply chain (LLM03) | `dev_checks/model_supply_chain.py` (hash pinning, no pickle, trusted hosts) | `test_dev_checks.py` |
| Secure CI/CD | `dev_checks/workflow_lint.py`, `.github/workflows/ci.yml` | `test_dev_checks.py` |

## Production phase / request pipeline
| Layer (infographic) | Module | OWASP | Tests |
|---|---|---|---|
| Authentication | `auth.py` (HMAC-signed, expiring tokens) | - | `test_auth.py` |
| Authorization | `auth.py` (role -> least-privilege permissions) | LLM06 | `test_auth.py`, `test_gateway.py` |
| Rate limiting | `rate_limiter.py` (token bucket) | LLM10 | `test_rate_limit.py` |
| Denial-of-wallet | `rate_limiter.py` (daily token budget) | LLM10 | `test_rate_limit.py` |
| Input validation | `input_validation.py` (size, unicode, zero-width, flood) | LLM10 | `test_input_validation.py` |
| Prompt-injection detection | `injection_detector.py` (rules, leetspeak, base64, zero-width) | LLM01 | `test_injection.py` |
| Indirect injection | `rag.py` quarantine + re-scan, `tools.py` output scan, `gateway.py` provenance check | LLM01 | `test_rag.py`, `test_gateway.py` |
| Orchestrator | `gateway.py` | - | `test_gateway.py` |
| Permission-checked tools | `tools.py` (allowlist -> permission -> schema -> validator -> approval) | LLM06 | `test_tools.py` |
| Human approval for high risk | `tools.py` (`approver` callback, default deny) | LLM06 | `test_tools.py` |
| Sandboxed file access | `builtin_tools.py: FileSandbox` | LLM06 | `test_tools.py` |
| Safe SQL | `builtin_tools.py: run_readonly_query` (validator + engine-level authorizer) | LLM05 | `test_tools.py` |
| Safe calculator (no `eval`) | `builtin_tools.py: safe_calculate` | LLM05 | `test_tools.py` |
| MCP / tool poisoning, rug-pull, shadowing | `mcp_guard.py` | LLM03/LLM01 | `test_mcp_guard.py` |
| Memory poisoning | `memory.py` (user-confirmed only, scanned, per-user, TTL) | LLM04 | `test_memory.py` |
| Output validation | `output_validation.py` | LLM05 | `test_output_validation.py` |
| System-prompt leakage | canary token + verbatim-line check | LLM07 | `test_output_validation.py` |
| Insecure output handling (XSS, exfil image) | HTML escaping, external image stripping | LLM05 | `test_output_validation.py` |
| Hallucination / over-reliance | citation grounding check | LLM09 | `test_output_validation.py` |
| PII & secret filtering | `pii_filter.py` on output | LLM02 | `test_pii.py` |
| Audit logging | `audit.py` (hash-chained, PII-redacted, retention) | - | `test_audit.py` |
| Monitoring & response | `audit.py: SecurityMonitor` (auto-suspend), kill switch | - | `test_audit.py`, `test_gateway.py` |
| Compliance | `compliance.py` (consent, erasure) | - | `test_gateway.py`, `test_memory.py` |

## 7 Golden Rules -> where they live
1. Never trust user input -> `input_validation.py`, `injection_detector.py`
2. Never expose secrets -> `config.py`, `pii_filter.py`, `secret_scanner.py`
3. Least privilege -> `auth.py` roles, `tools.py`
4. Authenticate & authorize sensitive operations -> `auth.py`, `tools.py`
5. Validate inputs *and* outputs -> `input_validation.py`, `output_validation.py`
6. Monitor & audit -> `audit.py`
7. Human approval for high-risk actions -> `tools.py` approver
