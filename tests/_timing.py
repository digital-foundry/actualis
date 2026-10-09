"""Timing helpers for the tests, so a slow CI runner cannot flake a linearity check.

Two guards, used together:
  - a ratio: time input n and input 4n, best of three each; a linear
    implementation takes about 4x as long, a quadratic one about 16x, and
    anything under 8x (plus a little epsilon for timer noise) passes;
  - a ceiling from budget(): the local figure x1.5, and x5 when CI is set,
    because the hosted runners are 1.2-2.3x slower than a dev machine.
"""
import os
import time


def budget(seconds: float) -> float:
    return seconds * (5 if os.environ.get("CI") else 1.5)


def best_of(fn, arg, runs: int = 3) -> float:
    best = float("inf")
    for _ in range(runs):
        t = time.perf_counter()
        fn(arg)
        best = min(best, time.perf_counter() - t)
    return best


def assert_linear(test, fn, probes, ceiling: float, epsilon: float = 0.02) -> None:
    """probes: (prefix, unit, count, suffix); the input is prefix + unit*count + suffix.
    fn(text) is timed at count and at 4*count."""
    for prefix, unit, count, suffix in probes:
        small = prefix + unit * count + suffix
        big = prefix + unit * (4 * count) + suffix
        t1, t4 = best_of(fn, small), best_of(fn, big)
        label = (prefix + unit)[:16]
        test.assertLess(t1, budget(ceiling), (label, "n", t1))
        test.assertLess(t4, 8 * t1 + epsilon, (label, "4n is not ~4x n", t1, t4))
