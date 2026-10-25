import pytest

from secure_ai.errors import BudgetExceeded, RateLimitError
from secure_ai.rate_limiter import BudgetTracker, RateLimiter, estimate_tokens


def test_burst_then_block_then_refill(clock):
    rl = RateLimiter(per_minute=5, clock=clock)
    for _ in range(5):
        rl.check("u")
    with pytest.raises(RateLimitError) as e:
        rl.check("u")
    assert e.value.details["retry_after"] > 0
    clock.advance(12)            # 5/min -> one token every 12s
    rl.check("u")


def test_users_are_independent(clock):
    rl = RateLimiter(per_minute=1, clock=clock)
    rl.check("a")
    rl.check("b")
    with pytest.raises(RateLimitError):
        rl.check("a")


def test_budget_blocks_and_resets_next_day(clock):
    b = BudgetTracker(100, clock=clock)
    b.check("u", 60); b.charge("u", 60)
    with pytest.raises(BudgetExceeded):
        b.check("u", 60)
    clock.advance(86_400)
    b.check("u", 60)


def test_estimate_tokens():
    assert estimate_tokens("") == 1 and estimate_tokens("a" * 400) == 100
