"""Review-budget metrics, the within-band queue simulation, and promotion gates.

Design §16.6-§16.7 and §17. Two things are deliberate here:

* the queue simulation reorders *within* a proof/severity band and only when the
  whole band is model-eligible, because that is the product policy the artifact
  is allowed to influence — evaluating a raw unconstrained ranking would measure
  a model Kuzushi will never ship;
* every gate reports `pass`, `fail`, or `not_applicable_course_exercise`. A
  corpus too small for a production claim says so instead of being silently
  downgraded into a passing number.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from .calibration import brier
from .dataset import FEATURE_WHITELIST, PROOF_BAND, STATIC_PROOF_CONFIDENCE_RANK, Row
from .id3 import CategoryMap, TreeNode, decision_path, leaves, tree_depth

BUDGET_FRACTIONS: tuple[float, ...] = (0.10, 0.20, 0.50)

PASS = "pass"
FAIL = "fail"
NOT_APPLICABLE = "not_applicable_course_exercise"

MIN_ELIGIBLE_IDENTITIES = 200
MIN_PER_CLASS = 50
MAX_MODEL_DEPTH = 6
MIN_LEAF_SUPPORT = 20

Scored = Sequence[tuple[Row, float]]


def rank(scored: Scored) -> list[Row]:
    """Highest score first; ties broken by identity so the order is total."""
    return [
        row
        for row, _ in sorted(scored, key=lambda pair: (-pair[1], pair[0].identity_group))
    ]


def budget_size(count: int, fraction: float) -> int:
    """At least one item is reviewed whenever there is anything to review."""
    return max(1, int(count * fraction)) if count else 0


def precision_at(scored: Scored, fraction: float) -> float:
    ordered = rank(scored)
    budget = budget_size(len(ordered), fraction)
    if budget == 0:
        return 0.0
    return sum(row.label for row in ordered[:budget]) / budget


def recall_at(scored: Scored, fraction: float) -> float:
    ordered = rank(scored)
    positives = sum(row.label for row in ordered)
    budget = budget_size(len(ordered), fraction)
    if positives == 0 or budget == 0:
        return 0.0
    return sum(row.label for row in ordered[:budget]) / positives


def pr_auc(scored: Scored) -> float:
    """Average precision: precision at each positive, averaged over positives."""
    ordered = rank(scored)
    positives = sum(row.label for row in ordered)
    if positives == 0:
        return 0.0
    found = 0
    total = 0.0
    for position, row in enumerate(ordered, start=1):
        if row.label:
            found += 1
            total += found / position
    return total / positives


def budget_metrics(scored: Scored) -> dict[str, float]:
    metrics = {"prAuc": pr_auc(scored)}
    for fraction in BUDGET_FRACTIONS:
        label = int(fraction * 100)
        metrics[f"precisionAt{label}"] = precision_at(scored, fraction)
        metrics[f"recallAt{label}"] = recall_at(scored, fraction)
    return metrics


# --------------------------------------------------------------------------
# Product-faithful queue simulation
# --------------------------------------------------------------------------


def band_key(row: Row) -> tuple[int, int]:
    """Proof band then severity — the two boundaries a model may never cross."""
    return (PROOF_BAND[row.features["staticProofState"]], int(row.features["severityRank"]))


def baseline_queue(rows: Sequence[Row]) -> list[Row]:
    """The reconstructed product order: proof band, severity, then identity.

    Within a band this falls back to the full proof-state rank before the
    identity tiebreak, so the baseline is not arbitrary inside a band.
    """
    return sorted(
        rows,
        key=lambda row: (
            band_key(row),
            STATIC_PROOF_CONFIDENCE_RANK[row.features["staticProofState"]],
            row.identity_group,
        ),
    )


@dataclass(frozen=True)
class Eligibility:
    """Why a row may or may not be reordered by the model."""

    eligible: bool
    reason: str


def leaf_eligibility(
    tree: TreeNode, row: Row, categories: CategoryMap, minimum_leaf_support: int
) -> Eligibility:
    leaf, _ = decision_path(tree, row, categories)
    if leaf.support < minimum_leaf_support:
        return Eligibility(False, f"leaf support {leaf.support} below {minimum_leaf_support}")
    return Eligibility(True, "eligible")


def simulate_within_band_queue(
    rows: Sequence[Row],
    tree: TreeNode,
    categories: CategoryMap,
    *,
    minimum_leaf_support: int = MIN_LEAF_SUPPORT,
) -> list[Row]:
    """Reorders inside each band only when the whole band is model-eligible.

    A single ineligible row keeps its entire band on the baseline order, which is
    the all-or-nothing rule §19.4 requires of within-band mode.
    """
    queue: list[Row] = []
    for _, band in _bands(baseline_queue(rows)):
        queue.extend(_ordered_band(band, tree, categories, minimum_leaf_support))
    return queue


def _bands(ordered: Sequence[Row]) -> Iterable[tuple[tuple[int, int], list[Row]]]:
    grouped: dict[tuple[int, int], list[Row]] = {}
    for row in ordered:
        grouped.setdefault(band_key(row), []).append(row)
    for key in sorted(grouped):
        yield key, grouped[key]


def _ordered_band(
    band: Sequence[Row],
    tree: TreeNode,
    categories: CategoryMap,
    minimum_leaf_support: int,
) -> list[Row]:
    if not all(
        leaf_eligibility(tree, row, categories, minimum_leaf_support).eligible for row in band
    ):
        return list(band)
    scored = [
        (row, decision_path(tree, row, categories)[0].smoothed_rate) for row in band
    ]
    return rank(scored)


def band_report(
    rows: Sequence[Row],
    tree: TreeNode,
    categories: CategoryMap,
    *,
    minimum_leaf_support: int = MIN_LEAF_SUPPORT,
) -> dict[str, int]:
    """How much room the within-band policy actually had.

    A ΔPrecision of exactly zero usually means the bands were singletons, not
    that the model failed; the report distinguishes the two.
    """
    bands = list(_bands(baseline_queue(rows)))
    reorderable = [
        band
        for _, band in bands
        if len(band) > 1
        and all(
            leaf_eligibility(tree, row, categories, minimum_leaf_support).eligible
            for row in band
        )
    ]
    return {
        "bands": len(bands),
        "multiRowBands": sum(1 for _, band in bands if len(band) > 1),
        "reorderableBands": len(reorderable),
        "rowsInReorderableBands": sum(len(band) for band in reorderable),
    }


def queue_metrics(queue: Sequence[Row]) -> dict[str, float]:
    """Budget metrics over an already-ordered queue (scores are the position)."""
    scored = [(row, float(len(queue) - index)) for index, row in enumerate(queue)]
    return budget_metrics(scored)


# --------------------------------------------------------------------------
# Gates
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Gate:
    name: str
    status: str
    detail: str

    def as_json(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


def _gate(name: str, ok: bool, detail: str, applicable: bool = True) -> Gate:
    if not applicable:
        return Gate(name, NOT_APPLICABLE, detail)
    return Gate(name, PASS if ok else FAIL, detail)


def dataset_gates(rows: Sequence[Row], incomplete: int) -> list[Gate]:
    """Design §17.1. A small corpus fails the production gate honestly."""
    positives = sum(row.label for row in rows)
    negatives = len(rows) - positives
    identities = {row.identity_group for row in rows}
    qualities = {row.cutoff_quality for row in rows}
    tools = {row.features["toolFamily"] for row in rows}
    repositories = {row.repository_group for row in rows}
    return [
        _gate(
            "eligible_identities",
            len(rows) >= MIN_ELIGIBLE_IDENTITIES,
            f"{len(rows)} eligible identities (need {MIN_ELIGIBLE_IDENTITIES})",
        ),
        _gate(
            "class_balance",
            min(positives, negatives) >= MIN_PER_CLASS,
            f"{positives} positive / {negatives} negative (need {MIN_PER_CLASS} each)",
        ),
        _gate(
            "unique_identities",
            len(identities) == len(rows),
            f"{len(identities)} distinct identity groups across {len(rows)} rows",
        ),
        _gate(
            "cutoff_quality_reported",
            bool(qualities),
            f"cutoff quality split: {sorted(qualities)}",
        ),
        _gate(
            "forbidden_field_check",
            all(row.features.keys() == set(FEATURE_WHITELIST) for row in rows),
            "every row passed the whitelist load; no forbidden key is representable",
        ),
        _gate(
            "tool_and_repository_diversity",
            len(tools) >= 2 and len(repositories) >= 2,
            f"{len(tools)} tool families across {len(repositories)} repository groups",
        ),
        _gate(
            "feature_completeness_reported",
            True,
            f"{incomplete} of {len(rows) + incomplete} rows carry an absent "
            "whitelisted feature and are excluded from fitting (design §10.6); "
            "this is reported, never imputed",
        ),
    ]


def model_gates(
    tree: TreeNode,
    *,
    active_leaves: Sequence[TreeNode],
    delta_precision_low: float | None,
    temporal_precision_delta: float,
    minimum_leaf_support: int = MIN_LEAF_SUPPORT,
) -> list[Gate]:
    """Design §17.2. `delta_precision_low` is None when no interval was computed."""
    depth = tree_depth(tree)
    weakest = min((leaf.support for leaf in active_leaves), default=0)
    return [
        _gate("tree_depth", depth <= MAX_MODEL_DEPTH, f"depth {depth} (max {MAX_MODEL_DEPTH})"),
        _gate(
            "active_leaf_support",
            weakest >= minimum_leaf_support,
            f"weakest active leaf holds {weakest} examples (need {minimum_leaf_support})",
        ),
        _gate(
            "bootstrap_improvement",
            (delta_precision_low or 0.0) > 0.0,
            (
                "no paired interval computed"
                if delta_precision_low is None
                else f"ΔPrecision@20% lower bound {delta_precision_low:.6f}"
            ),
            applicable=delta_precision_low is not None,
        ),
        _gate(
            "temporal_direction",
            temporal_precision_delta > 0.0,
            f"temporal ΔPrecision@20% {temporal_precision_delta:.6f}",
        ),
    ]


def active_leaves(tree: TreeNode, minimum_leaf_support: int = MIN_LEAF_SUPPORT) -> list[TreeNode]:
    """Leaves the product would actually act on."""
    return [leaf for leaf in leaves(tree) if leaf.support >= minimum_leaf_support]


# --------------------------------------------------------------------------
# Ablations
# --------------------------------------------------------------------------

ABLATION_GROUPS: dict[str, tuple[str, ...]] = {
    "no_tool_family": ("toolFamily",),
    "no_path_bucket": ("pathBucket",),
    "no_severity": ("severityRank",),
    "no_static_proof": ("staticProofState",),
    "no_corroboration_history": (
        "corroborationCount",
        "observationCount",
        "runCount",
        "reopenedCount",
    ),
    "no_producer_confidence": ("maxEvidenceConfidence", "meanEvidenceConfidenceMillis"),
}


def ablation_schemas(
    feature_schema: dict[str, str]
) -> dict[str, dict[str, str]]:
    """One reduced schema per ablation (design §16.9)."""
    return {
        name: {
            feature: kind
            for feature, kind in feature_schema.items()
            if feature not in removed
        }
        for name, removed in ABLATION_GROUPS.items()
    }


def scored_metrics(
    rows: Sequence[Row], score_of: Callable[[Row], float]
) -> dict[str, float]:
    scored = [(row, score_of(row)) for row in rows]
    metrics = budget_metrics(scored)
    metrics["brier"] = brier(
        [row.label for row in rows], [_clamped(score) for _, score in scored]
    )
    return metrics


def _clamped(score: float) -> float:
    """Brier only means something for probabilities; ordering baselines are not."""
    return min(1.0, max(0.0, score))
