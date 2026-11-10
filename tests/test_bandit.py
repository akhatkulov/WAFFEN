"""reward_from_score must stay numerically stable: the best-first strategy crashed
with OverflowError when a small score followed a THROUGH parent (delta ~ -1e9)."""
import math

from waffen.search.bandit import reward_from_score


def test_reward_in_unit_interval_for_extreme_deltas():
    # the exact shape that crashed: tiny score after a THROUGH parent at 1e9
    for score, parent in [(1.0, 1e9), (0.0, 1e9), (-1.0, 1e8), (1e9, 1.0),
                          (1e7, 1e7), (5.0, 3.0), (-1e9, 1e9), (1e9, -1e9)]:
        r = reward_from_score(score, parent)
        assert 0.0 <= r <= 1.0, (score, parent, r)
        assert math.isfinite(r)


def test_reward_monotonic_and_centered():
    assert reward_from_score(10.0, 10.0) == 0.5          # no change -> 0.5
    assert reward_from_score(100.0, 1.0) > 0.9           # big improvement -> high
    assert reward_from_score(1.0, 100.0) < 0.1           # big regression -> low
    assert reward_from_score(1e9, 0.0) == 1.0            # THROUGH saturates
