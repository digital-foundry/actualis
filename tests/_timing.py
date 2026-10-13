"""Timing helpers for the tests, so a slow or busy machine cannot flake a linearity check.

Two guards, used together:
  - a ratio: time input n and input 4n; a linear implementation takes about 4x
    as long, a quadratic one about 16x, and anything under 8x (plus a little
    epsilon for timer noise) passes. The ratio is only meaningful when both
    samples are long enough to ride out the scheduler, so assert_linear:
      * measures CPU time (time.process_time), not wall time, where the clock
        is fine-grained (everywhere but Windows, whose CPU clock ticks every
        15.6 ms): another process taking the core does not count against us;
      * repeats a fast call until one sample lasts at least MIN_SAMPLE, so the
        n sample spans several scheduler quanta just as the 4n sample does
        (a 2 ms sample fits inside one quantum and is never preempted, while
        its 8 ms partner is; under load that alone read as 11x);
      * interleaves the n and 4n samples, so a burst of load hits both;
      * re-measures up to twice before failing: noise does not repeat, a
        quadratic does.
  - a ceiling from budget(): the base figure is the time measured on an
    unloaded dev Mac; the ceiling is x5 that locally and x12 when CI is set,
    because Python 3.9 is up to 1.5x slower than current versions, a dev
    machine is often busy (a second suite, a build), and the hosted runners
    are 1.2-2.3x slower again. Every ceiling keeps at least 5x headroom over
    its Python 3.9 time on an unloaded machine.
"""
import os
import sys
import time

MIN_SAMPLE = 0.02           # seconds of work per timed sample in assert_linear
# CPU time where it is fine-grained, wall time on Windows. Tests time their
# absolute ceilings with clock() too: time another process holds the core is
# then not counted against the code under test.
clock = time.perf_counter if sys.platform == "win32" else time.process_time


def budget(seconds: float) -> float:
    return seconds * (12 if os.environ.get("CI") else 5)


def best_of(fn, arg, runs: int = 3) -> float:
    best = float("inf")
    for _ in range(runs):
        t = clock()
        fn(arg)
        best = min(best, clock() - t)
    return best


def _per_call(fn, arg, reps: int) -> float:
    t = clock()
    for _ in range(reps):
        fn(arg)
    return (clock() - t) / reps


def assert_linear(test, fn, probes, ceiling: float, epsilon: float = 0.02) -> None:
    """probes: (prefix, unit, count, suffix); the input is prefix + unit*count + suffix.
    fn(text) is timed at count and at 4*count; `ceiling` bounds one call at count."""
    for prefix, unit, count, suffix in probes:
        small = prefix + unit * count + suffix
        big = prefix + unit * (4 * count) + suffix
        label = (prefix + unit)[:16]
        first = best_of(fn, small, runs=1)            # also warms any cache
        reps = max(1, min(1000, int(MIN_SAMPLE / max(first, 1e-6)) + 1))
        for _attempt in range(3):
            t1 = t4 = float("inf")
            for _ in range(3):
                t1 = min(t1, _per_call(fn, small, reps))
                t4 = min(t4, _per_call(fn, big, reps))
            if t4 < 8 * t1 + epsilon:
                break
        test.assertLess(min(t1, first), budget(ceiling), (label, "n", t1))
        test.assertLess(t4, 8 * t1 + epsilon, (label, "4n is not ~4x n", t1, t4))
