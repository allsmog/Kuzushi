"""From-scratch ID3 with deterministic split selection and cost-complexity pruning.

Design §14.2-§14.7. Two rules make this reproducible rather than merely seeded:

1. equal gains are broken by `(feature, kind, threshold-or-category)` ascending,
   so the same rows and configuration always yield the same tree;
2. every leaf keeps raw counts, so smoothing and intervals are derived at
   display time and a three-example leaf can never claim certainty.

Missing values are not routed in version one: rows with an absent whitelisted
feature are excluded before fitting and every internal node records
`missingDirection: "ineligible"` (design §10.6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from .calibration import beta_credible_interval, jeffreys_rate
from .dataset import (
    BOOLEAN_FEATURES,
    CATEGORICAL_FEATURES,
    FEATURE_WHITELIST,
    NUMERIC_FEATURES,
    Row,
)
from .entropy import candidate_numeric_thresholds, entropy, information_gain

NUMERIC = "numeric"
CATEGORICAL = "categorical"
OTHER_CATEGORY = "other"
MISSING_INELIGIBLE = "ineligible"

DEFAULT_RARE_CATEGORY_MIN_COUNT = 5

FeatureSchema = Mapping[str, str]
CategoryMap = Mapping[str, Mapping[str, str]]


def default_feature_schema(features: Iterable[str] = FEATURE_WHITELIST) -> dict[str, str]:
    """Split kind per feature. Booleans are two-value categoricals (§14.4)."""
    schema: dict[str, str] = {}
    for name in features:
        if name in NUMERIC_FEATURES:
            schema[name] = NUMERIC
        elif name in CATEGORICAL_FEATURES or name in BOOLEAN_FEATURES:
            schema[name] = CATEGORICAL
        else:
            raise KeyError(f"{name} is not in the frozen feature schema")
    return schema


@dataclass(frozen=True)
class CandidateSplit:
    """One binary split. `threshold` and `category` are mutually exclusive."""

    feature: str
    kind: str
    threshold: float | None = None
    category: str | None = None

    def sort_key(self) -> tuple[str, str, str]:
        """Design §14.2: feature name, then split kind, then representation."""
        representation = repr(self.threshold) if self.kind == NUMERIC else str(self.category)
        return (self.feature, self.kind, representation)

    def describe(self) -> str:
        if self.kind == NUMERIC:
            return f"{self.feature}<={self.threshold!r}"
        return f'{self.feature}=="{self.category}"'


@dataclass
class TreeNode:
    """A fitted node. Internal nodes keep their training counts so pruning can
    compare a subtree against the leaf that would replace it."""

    positive_count: int
    negative_count: int
    depth: int
    split: CandidateSplit | None = None
    left: "TreeNode | None" = None
    right: "TreeNode | None" = None
    missing_direction: str = MISSING_INELIGIBLE
    gain_bits: float = 0.0
    node_id: int = field(default=-1, compare=False)

    @property
    def support(self) -> int:
        return self.positive_count + self.negative_count

    @property
    def is_leaf(self) -> bool:
        return self.split is None

    @property
    def smoothed_rate(self) -> float:
        return jeffreys_rate(self.positive_count, self.negative_count)

    @property
    def entropy_bits(self) -> float:
        return entropy([1] * self.positive_count + [0] * self.negative_count)

    @property
    def ci95(self) -> tuple[float, float]:
        return beta_credible_interval(self.positive_count, self.negative_count)


def fit_id3(
    rows: Sequence[Row],
    feature_schema: FeatureSchema,
    *,
    max_depth: int,
    min_samples_leaf: int,
    min_gain: float,
    class_weight: str = "none",
    rare_category_min_count: int = DEFAULT_RARE_CATEGORY_MIN_COUNT,
) -> TreeNode:
    """Fits a tree over complete rows. Raises on an incomplete row."""
    _reject_incomplete(rows, feature_schema)
    categories = build_category_map(rows, feature_schema, rare_category_min_count)
    weights = class_weights(rows, class_weight)
    tree = _grow(
        rows,
        feature_schema,
        categories,
        weights,
        depth=0,
        max_depth=max_depth,
        min_samples_leaf=min_samples_leaf,
        min_gain=min_gain,
    )
    assign_node_ids(tree)
    return tree


def _reject_incomplete(rows: Sequence[Row], feature_schema: FeatureSchema) -> None:
    for row in rows:
        for name in feature_schema:
            if row.features[name] is None:
                raise ValueError(
                    f"row {row.example_id} has no value for {name}; version one fits "
                    "complete rows only — call dataset.partition_complete_rows first"
                )


def class_weights(rows: Sequence[Row], class_weight: str) -> dict[int, float] | None:
    """`balanced` gives each class total mass `N/2`; `none` weights every row 1."""
    if class_weight == "none":
        return None
    if class_weight != "balanced":
        raise ValueError(f"unknown class_weight {class_weight!r}")
    positives = sum(row.label for row in rows)
    negatives = len(rows) - positives
    total = len(rows)
    return {
        1: total / (2 * positives) if positives else 0.0,
        0: total / (2 * negatives) if negatives else 0.0,
    }


def build_category_map(
    rows: Sequence[Row], feature_schema: FeatureSchema, rare_category_min_count: int
) -> dict[str, dict[str, str]]:
    """Maps each categorical value to its effective category, folding rare ones.

    Design §14.4: rare categories become `other` so a category seen a handful of
    times cannot become a high-cardinality shortcut. Booleans are exempt — a
    two-value vocabulary has nothing to fold.
    """
    mapping: dict[str, dict[str, str]] = {}
    for name, kind in feature_schema.items():
        if kind != CATEGORICAL:
            continue
        counts = _value_counts(rows, name)
        mapping[name] = {
            value: (
                value
                if name in BOOLEAN_FEATURES or count >= rare_category_min_count
                else OTHER_CATEGORY
            )
            for value, count in counts.items()
        }
    return mapping


def _value_counts(rows: Sequence[Row], name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = category_token(row.features[name])
        counts[value] = counts.get(value, 0) + 1
    return counts


def category_token(value: Any) -> str:
    """Categorical token for a feature value. Booleans read as "true"/"false",
    matching how PR 4's Rust evaluator presents them on categorical nodes."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def category_of(row: Row, feature: str, categories: CategoryMap) -> str:
    """Effective category of `feature` for `row`, after rare-value folding."""
    raw = category_token(row.features[feature])
    return categories.get(feature, {}).get(raw, OTHER_CATEGORY)


def numeric_of(row: Row, feature: str) -> float:
    value = row.features[feature]
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    return float(value)


def goes_left(row: Row, split: CandidateSplit, categories: CategoryMap) -> bool:
    """Routing predicate. `value <= threshold` goes left; PR 4 mirrors this."""
    if split.kind == NUMERIC:
        return numeric_of(row, split.feature) <= float(split.threshold)
    return category_of(row, split.feature, categories) == split.category


def _grow(
    rows: Sequence[Row],
    feature_schema: FeatureSchema,
    categories: CategoryMap,
    weights: Mapping[int, float] | None,
    *,
    depth: int,
    max_depth: int,
    min_samples_leaf: int,
    min_gain: float,
) -> TreeNode:
    node = _leaf(rows, depth)
    if _must_stop(rows, depth, max_depth, min_samples_leaf):
        return node
    chosen = best_split(
        rows, feature_schema, categories, weights, min_samples_leaf=min_samples_leaf
    )
    if chosen is None or chosen[1] < min_gain:
        return node
    split, gain = chosen
    left = [row for row in rows if goes_left(row, split, categories)]
    right = [row for row in rows if not goes_left(row, split, categories)]
    node.split = split
    node.gain_bits = gain
    recurse = dict(
        max_depth=max_depth, min_samples_leaf=min_samples_leaf, min_gain=min_gain
    )
    node.left = _grow(
        left, feature_schema, categories, weights, depth=depth + 1, **recurse
    )
    node.right = _grow(
        right, feature_schema, categories, weights, depth=depth + 1, **recurse
    )
    return node


def _must_stop(
    rows: Sequence[Row], depth: int, max_depth: int, min_samples_leaf: int
) -> bool:
    labels = {row.label for row in rows}
    return len(labels) < 2 or depth >= max_depth or len(rows) < 2 * min_samples_leaf


def _leaf(rows: Sequence[Row], depth: int) -> TreeNode:
    positives = sum(row.label for row in rows)
    return TreeNode(
        positive_count=positives, negative_count=len(rows) - positives, depth=depth
    )


def best_split(
    rows: Sequence[Row],
    feature_schema: FeatureSchema,
    categories: CategoryMap,
    weights: Mapping[int, float] | None = None,
    *,
    min_samples_leaf: int = 1,
) -> tuple[CandidateSplit, float] | None:
    """Highest-gain eligible split, with §14.2's tie-break already applied.

    Candidates are visited in tie-break order and a later candidate must beat the
    incumbent strictly, so the first member of any tie wins without a separate
    comparison pass.
    """
    best: tuple[CandidateSplit, float] | None = None
    for split in enumerate_splits(rows, feature_schema, categories):
        left = sum(1 for row in rows if goes_left(row, split, categories))
        if min(left, len(rows) - left) < min_samples_leaf:
            continue
        gain = information_gain(
            rows,
            lambda row: row.label,
            lambda row, split=split: goes_left(row, split, categories),
            weights,
        )
        if best is None or gain > best[1]:
            best = (split, gain)
    return best


def enumerate_splits(
    rows: Sequence[Row], feature_schema: FeatureSchema, categories: CategoryMap
) -> list[CandidateSplit]:
    """Every candidate split at a node, sorted into deterministic order."""
    candidates: list[CandidateSplit] = []
    for name in sorted(feature_schema):
        if feature_schema[name] == NUMERIC:
            candidates.extend(_numeric_candidates(rows, name))
        else:
            candidates.extend(_categorical_candidates(rows, name, categories))
    return sorted(candidates, key=CandidateSplit.sort_key)


def _numeric_candidates(rows: Sequence[Row], name: str) -> list[CandidateSplit]:
    thresholds = candidate_numeric_thresholds(
        rows, lambda row: numeric_of(row, name), lambda row: row.label
    )
    return [CandidateSplit(name, NUMERIC, threshold=value) for value in thresholds]


def _categorical_candidates(
    rows: Sequence[Row], name: str, categories: CategoryMap
) -> list[CandidateSplit]:
    present = sorted({category_of(row, name, categories) for row in rows})
    return [CandidateSplit(name, CATEGORICAL, category=value) for value in present]


# --------------------------------------------------------------------------
# Traversal
# --------------------------------------------------------------------------


def iter_nodes(tree: TreeNode) -> list[TreeNode]:
    """Pre-order node list: parents always precede their children."""
    nodes = [tree]
    index = 0
    while index < len(nodes):
        node = nodes[index]
        if not node.is_leaf:
            nodes.extend([node.left, node.right])
        index += 1
    return nodes


def assign_node_ids(tree: TreeNode) -> None:
    for identifier, node in enumerate(iter_nodes(tree)):
        node.node_id = identifier


def leaves(tree: TreeNode) -> list[TreeNode]:
    return [node for node in iter_nodes(tree) if node.is_leaf]


def tree_depth(tree: TreeNode) -> int:
    return max((node.depth for node in leaves(tree)), default=0)


def decision_path(
    tree: TreeNode, row: Row, categories: CategoryMap
) -> tuple[TreeNode, list[str]]:
    """Leaf reached by `row`, plus the `<id>:<feature><op>:<branch>` trace."""
    node, steps = tree, []
    while not node.is_leaf:
        left = goes_left(row, node.split, categories)
        steps.append(f"{node.node_id}:{node.split.describe()}:{'left' if left else 'right'}")
        node = node.left if left else node.right
    return node, steps


def score_row(tree: TreeNode, row: Row, categories: CategoryMap) -> float:
    return decision_path(tree, row, categories)[0].smoothed_rate


def score_rows(
    tree: TreeNode, rows: Sequence[Row], categories: CategoryMap
) -> list[float]:
    return [score_row(tree, row, categories) for row in rows]


def accuracy(tree: TreeNode, rows: Sequence[Row], categories: CategoryMap) -> float:
    if not rows:
        return 0.0
    correct = sum(
        1
        for row in rows
        if (score_row(tree, row, categories) >= 0.5) == bool(row.label)
    )
    return correct / len(rows)


# --------------------------------------------------------------------------
# Cost-complexity pruning
# --------------------------------------------------------------------------


def copy_tree(tree: TreeNode) -> TreeNode:
    clone = TreeNode(
        positive_count=tree.positive_count,
        negative_count=tree.negative_count,
        depth=tree.depth,
        split=tree.split,
        missing_direction=tree.missing_direction,
        gain_bits=tree.gain_bits,
        node_id=tree.node_id,
    )
    if not tree.is_leaf:
        clone.left = copy_tree(tree.left)
        clone.right = copy_tree(tree.right)
    return clone


def _resubstitution_error(node: TreeNode, total: int) -> float:
    """Misclassification mass of `node` if it were collapsed to a leaf."""
    return min(node.positive_count, node.negative_count) / total


def _subtree_error(node: TreeNode, total: int) -> float:
    return sum(_resubstitution_error(leaf, total) for leaf in leaves(node))


def _effective_alpha(node: TreeNode, total: int) -> float:
    leaf_count = len(leaves(node))
    if leaf_count < 2:
        return float("inf")
    collapsed = _resubstitution_error(node, total)
    return (collapsed - _subtree_error(node, total)) / (leaf_count - 1)


def _weakest_link(tree: TreeNode, total: int) -> tuple[TreeNode, float] | None:
    internal = [node for node in iter_nodes(tree) if not node.is_leaf]
    if not internal:
        return None
    scored = [(node, _effective_alpha(node, total)) for node in internal]
    return min(scored, key=lambda pair: (pair[1], pair[0].node_id))


def alpha_sequence(tree: TreeNode) -> list[float]:
    """Ascending weakest-link alphas, starting at 0.0.

    Deviation from the plan's `alpha_sequence(tree, rows)`: the fitted nodes
    already carry their training counts, and re-deriving them from a rows
    argument would let the two disagree silently.
    """
    working = copy_tree(tree)
    total = max(1, working.support)
    alphas = [0.0]
    while True:
        link = _weakest_link(working, total)
        if link is None:
            return alphas
        node, alpha = link
        if alpha > alphas[-1]:
            alphas.append(alpha)
        _collapse(node)


def _collapse(node: TreeNode) -> None:
    node.split = None
    node.left = None
    node.right = None
    node.gain_bits = 0.0


def prune(tree: TreeNode, alpha: float) -> TreeNode:
    """Collapses every subtree whose effective alpha is at most `alpha`."""
    working = copy_tree(tree)
    total = max(1, working.support)
    while True:
        link = _weakest_link(working, total)
        if link is None or link[1] > alpha:
            break
        _collapse(link[0])
    assign_node_ids(working)
    return working


def select_alpha(
    tree: TreeNode,
    validation_rows: Sequence[Row],
    categories: CategoryMap,
    *,
    metric: Callable[[TreeNode], float] | None = None,
) -> float:
    """Alpha minimizing validation Brier score; ties prefer the larger alpha.

    Selection touches validation rows only — the test fold is evaluated once, at
    the very end of `train.py` (design §16.10).
    """
    score = metric or (lambda candidate: _validation_brier(candidate, validation_rows, categories))
    best_alpha, best_score = 0.0, float("inf")
    for alpha in alpha_sequence(tree):
        value = score(prune(tree, alpha))
        if value <= best_score:
            best_alpha, best_score = alpha, value
    return best_alpha


def _validation_brier(
    tree: TreeNode, rows: Sequence[Row], categories: CategoryMap
) -> float:
    from .calibration import brier

    if not rows:
        return float("inf")
    return brier([row.label for row in rows], score_rows(tree, rows, categories))


def render_tree(tree: TreeNode, categories: CategoryMap | None = None) -> str:
    """Human-readable tree with leaf counts (Week 10 deliverable)."""
    lines: list[str] = []
    _render_into(tree, "", lines)
    return "\n".join(lines)


def _render_into(node: TreeNode, prefix: str, lines: list[str]) -> None:
    if node.is_leaf:
        low, high = node.ci95
        lines.append(
            f"{prefix}leaf#{node.node_id} n={node.support} "
            f"(+{node.positive_count}/-{node.negative_count}) "
            f"rate={node.smoothed_rate:.6f} ci95=[{low:.6f},{high:.6f}] "
            f"H={node.entropy_bits:.6f}"
        )
        return
    lines.append(
        f"{prefix}node#{node.node_id} {node.split.describe()} "
        f"gain={node.gain_bits:.6f} n={node.support}"
    )
    _render_into(node.left, prefix + "  L ", lines)
    _render_into(node.right, prefix + "  R ", lines)
