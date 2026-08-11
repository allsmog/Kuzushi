"""Paired bootstrap over durable identities (design §16.8).

Resampling is by identity group, not by row, because one durable identity is the
unit of independence (ADR-6). The seed is fixed and the resample indices come
from `random.Random`, so a reported interval is reproducible from the dataset
digest and the seed alone.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Sequence, TypeVar

T = TypeVar("T")

DEFAULT_REPLICATES = 1000
DEFAULT_SEED = 6601


@dataclass(frozen=True)
class Interval:
    """A point estimate with a percentile bootstrap interval."""

    point: float
    low: float
    high: float

    def excludes_zero_from_below(self) -> bool:
        """Whether the improvement's lower bound clears zero (gate §17.2)."""
        return self.low > 0.0

    def as_json(self) -> dict[str, float]:
        return {"point": self.point, "low95": self.low, "high95": self.high}


def paired_bootstrap_delta(
    groups: Sequence[T],
    delta_of: Callable[[Sequence[T]], float],
    *,
    replicates: int = DEFAULT_REPLICATES,
    seed: int = DEFAULT_SEED,
) -> Interval:
    """Percentile interval for `delta_of` under resampling of `groups`.

    `delta_of` receives a resampled collection of identity groups and returns one
    paired difference (for example ΔPrecision@20% between the tree policy and the
    baseline queue) computed on exactly those groups.
    """
    if not groups:
        return Interval(0.0, 0.0, 0.0)
    rng = random.Random(seed)
    count = len(groups)
    deltas = sorted(
        delta_of([groups[rng.randrange(count)] for _ in range(count)])
        for _ in range(replicates)
    )
    return Interval(
        point=delta_of(groups),
        low=_percentile(deltas, 0.025),
        high=_percentile(deltas, 0.975),
    )


def _percentile(sorted_values: Sequence[float], fraction: float) -> float:
    if not sorted_values:
        return 0.0
    index = int(fraction * (len(sorted_values) - 1))
    return sorted_values[index]
