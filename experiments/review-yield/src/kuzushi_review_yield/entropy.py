"""Shannon entropy, information gain, and numeric threshold candidates.

Design §13-§14.1 and Appendix A. Stdlib only, deliberately: the point of
Weeks 9-11 is that the learning mathematics is written out, not imported.
"""

from __future__ import annotations

from collections import Counter
from math import log2
from typing import Callable, Hashable, Mapping, Sequence, TypeVar

T = TypeVar("T")
Label = Hashable

#: Gains closer than this are one tie for split-selection purposes. Chosen well
#: above f64 rounding noise for the row counts this experiment sees and well
#: below any gain difference a real split produces.
GAIN_EQUALITY_EPSILON = 1e-12


def entropy(
    labels: Sequence[Label], weights: Mapping[Label, float] | None = None
) -> float:
    """Entropy in bits of a label multiset.

    `weights` gives a per-class multiplier (class-balanced fitting); absent, every
    example counts once. An empty or single-class population has entropy 0.
    """
    if not labels:
        return 0.0
    counts = Counter(labels)
    weighted = {
        label: count * (1.0 if weights is None else weights.get(label, 1.0))
        for label, count in counts.items()
    }
    total = sum(weighted.values())
    if total <= 0.0:
        return 0.0
    bits = -sum(
        (mass / total) * log2(mass / total) for mass in weighted.values() if mass > 0.0
    )
    # A pure population sums to zero and negation makes it -0.0, which would
    # serialize as "-0.0" in a model artifact and fail the schema's lower bound.
    return bits + 0.0


def information_gain(
    rows: Sequence[T],
    label_of: Callable[[T], Label],
    goes_left: Callable[[T], bool],
    weights: Mapping[Label, float] | None = None,
) -> float:
    """Bits of label uncertainty removed by a binary split.

    A split that sends every row the same way removes nothing and returns 0.0
    rather than a near-zero float, so degenerate splits can never win a tie.
    """
    if not rows:
        return 0.0
    left = [row for row in rows if goes_left(row)]
    right = [row for row in rows if not goes_left(row)]
    if not left or not right:
        return 0.0
    parent = entropy([label_of(row) for row in rows], weights)
    children = _weighted_child_entropy(rows, left, right, label_of, weights)
    return parent - children


def _weighted_child_entropy(
    rows: Sequence[T],
    left: Sequence[T],
    right: Sequence[T],
    label_of: Callable[[T], Label],
    weights: Mapping[Label, float] | None,
) -> float:
    left_share = len(left) / len(rows)
    right_share = len(right) / len(rows)
    return left_share * entropy(
        [label_of(row) for row in left], weights
    ) + right_share * entropy([label_of(row) for row in right], weights)


def candidate_numeric_thresholds(
    rows: Sequence[T],
    value_of: Callable[[T], float],
    label_of: Callable[[T], Label],
) -> list[float]:
    """Midpoints between adjacent distinct values whose labels can differ.

    Design §14.3: never test arbitrary floats. A boundary between two adjacent
    value groups is skipped only when both groups are pure and agree, because no
    such cut can separate anything.
    """
    groups = _label_sets_by_value(rows, value_of, label_of)
    values = sorted(groups)
    thresholds = []
    for lower, upper in zip(values, values[1:]):
        if _both_pure_and_equal(groups[lower], groups[upper]):
            continue
        thresholds.append((lower + upper) / 2)
    return thresholds


def _label_sets_by_value(
    rows: Sequence[T],
    value_of: Callable[[T], float],
    label_of: Callable[[T], Label],
) -> dict[float, set[Label]]:
    groups: dict[float, set[Label]] = {}
    for row in rows:
        groups.setdefault(float(value_of(row)), set()).add(label_of(row))
    return groups


def _both_pure_and_equal(lower: set[Label], upper: set[Label]) -> bool:
    return len(lower) == 1 and lower == upper


def gains_are_tied(first: float, second: float) -> bool:
    """Whether two gains count as equal for deterministic tie-breaking."""
    return abs(first - second) <= GAIN_EQUALITY_EPSILON
