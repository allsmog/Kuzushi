"""Leaf-rate smoothing, beta credible intervals, and calibration metrics.

Design §14.7 and §16.7. Stdlib only: the regularized incomplete beta function is
implemented here (Lentz continued fraction) rather than pulled from SciPy, and
`tests/test_calibration.py` checks it against an independent Simpson-rule
integration of the same posterior density.

A leaf with three positives and no negatives must not display "100%" — that is
the product reason this module exists, not a statistical flourish.
"""

from __future__ import annotations

from math import exp, lgamma, log
from typing import Sequence

JEFFREYS_PRIOR = 0.5

_MAX_ITERATIONS = 200
_CONVERGENCE = 1e-14
_TINY = 1e-300
_BISECTION_STEPS = 60
_BISECTION_TOLERANCE = 1e-10


def jeffreys_rate(positive: int, negative: int) -> float:
    """Smoothed positive rate `(n+ + 0.5) / (n+ + n- + 1)`."""
    total = positive + negative
    return (positive + JEFFREYS_PRIOR) / (total + 2 * JEFFREYS_PRIOR)


def beta_credible_interval(
    positive: int, negative: int, level: float = 0.95
) -> tuple[float, float]:
    """Equal-tailed credible interval of the `Beta(n+ + .5, n- + .5)` posterior."""
    if not 0.0 < level < 1.0:
        raise ValueError(f"level must be in (0, 1), got {level}")
    alpha = positive + JEFFREYS_PRIOR
    beta = negative + JEFFREYS_PRIOR
    tail = (1.0 - level) / 2.0
    return (
        beta_quantile(tail, alpha, beta),
        beta_quantile(1.0 - tail, alpha, beta),
    )


def beta_quantile(probability: float, alpha: float, beta: float) -> float:
    """Inverse of `regularized_incomplete_beta` by bisection on [0, 1]."""
    low, high = 0.0, 1.0
    for _ in range(_BISECTION_STEPS):
        middle = (low + high) / 2.0
        if regularized_incomplete_beta(middle, alpha, beta) < probability:
            low = middle
        else:
            high = middle
        if high - low < _BISECTION_TOLERANCE:
            break
    return (low + high) / 2.0


def regularized_incomplete_beta(x: float, alpha: float, beta: float) -> float:
    """`I_x(a, b)`, the Beta CDF."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    prefactor = exp(
        lgamma(alpha + beta)
        - lgamma(alpha)
        - lgamma(beta)
        + alpha * log(x)
        + beta * log(1.0 - x)
    )
    if x < (alpha + 1.0) / (alpha + beta + 2.0):
        return prefactor * _beta_continued_fraction(x, alpha, beta) / alpha
    return 1.0 - prefactor * _beta_continued_fraction(1.0 - x, beta, alpha) / beta


def _beta_continued_fraction(x: float, alpha: float, beta: float) -> float:
    """Lentz's algorithm for the continued fraction of `I_x(a, b)`."""
    qab, qap, qam = alpha + beta, alpha + 1.0, alpha - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > _TINY else _TINY)
    fraction = d
    for iteration in range(1, _MAX_ITERATIONS + 1):
        for numerator in _fraction_numerators(iteration, x, alpha, beta, qab, qap, qam):
            d = 1.0 / _guarded(1.0 + numerator * d)
            c = _guarded(1.0 + numerator / c)
            fraction *= d * c
        if abs(d * c - 1.0) < _CONVERGENCE:
            break
    return fraction


def _fraction_numerators(
    iteration: int, x: float, alpha: float, beta: float, qab: float, qap: float, qam: float
) -> tuple[float, float]:
    even = iteration * (beta - iteration) * x / ((qam + 2.0 * iteration) * (alpha + 2.0 * iteration))
    odd = (
        -(alpha + iteration)
        * (qab + iteration)
        * x
        / ((alpha + 2.0 * iteration) * (qap + 2.0 * iteration))
    )
    return even, odd


def _guarded(value: float) -> float:
    return value if abs(value) > _TINY else _TINY


def brier(labels: Sequence[int], scores: Sequence[float]) -> float:
    """Mean squared error between predicted probability and outcome."""
    if len(labels) != len(scores):
        raise ValueError("labels and scores must have the same length")
    if not labels:
        return 0.0
    return sum((score - label) ** 2 for label, score in zip(labels, scores)) / len(labels)


def ece(labels: Sequence[int], scores: Sequence[float], bins: int = 10) -> float:
    """Expected calibration error over equal-width probability bins."""
    if bins < 1:
        raise ValueError("bins must be positive")
    if not labels:
        return 0.0
    buckets: list[list[tuple[int, float]]] = [[] for _ in range(bins)]
    for label, score in zip(labels, scores):
        buckets[min(bins - 1, int(score * bins))].append((label, score))
    return sum(_bucket_error(bucket, len(labels)) for bucket in buckets if bucket)


def _bucket_error(bucket: Sequence[tuple[int, float]], total: int) -> float:
    observed = sum(label for label, _ in bucket) / len(bucket)
    predicted = sum(score for _, score in bucket) / len(bucket)
    return (len(bucket) / total) * abs(observed - predicted)
