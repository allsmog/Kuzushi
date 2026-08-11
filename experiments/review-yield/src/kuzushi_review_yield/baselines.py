"""Baselines the tree has to beat (design §16.5).

Every baseline here is reconstructable from the whitelisted features alone, so
none of them can quietly consume the human outcome. The logistic regression is
written out by hand rather than imported: it is the headline linear control, and
the point of the comparison is that a shallow tree's *interactions* add value
beyond an additive boundary — that claim is worth owning end to end.

The confidence-first product order cannot be replayed exactly from a
pre-decision snapshot (amendment 5: three rival orderings exist, and the review
queue's backlog toggle bypasses the one the doc names). `static_proof_severity`
is therefore documented as a *reconstruction*, and the model card says so.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from .dataset import STATIC_PROOF_CONFIDENCE_RANK, Row
from .id3 import CATEGORICAL, FeatureSchema, category_token, numeric_of

Scorer = Callable[[Row], float]


def majority_class(rows: Sequence[Row]) -> Scorer:
    """Constant score equal to the training base rate."""
    rate = (sum(row.label for row in rows) / len(rows)) if rows else 0.0
    return lambda _row: rate


def severity_only(row: Row) -> float:
    """Higher score for more severe findings. severityRank 0 is critical."""
    return -float(row.features["severityRank"])


def static_proof_severity(row: Row) -> float:
    """Proof band first, severity second — the reconstructable product order."""
    proof = STATIC_PROOF_CONFIDENCE_RANK[row.features["staticProofState"]]
    return -(proof * 10.0 + float(row.features["severityRank"]))


#: Additive weights for the restricted static-impact reconstruction. These stand
#: in for the 12-factor ranker's `reasons` (amendment 13) using only features
#: that survive the pre-decision cutoff; it is a restricted reconstruction, not
#: the shipped score.
RESTRICTED_IMPACT_WEIGHTS: Mapping[str, float] = {
    "sourceSinkLinked": 3.0,
    "hasSourceEvidence": 1.0,
    "hasSinkEvidence": 1.0,
    "sanitizerChecked": -1.5,
    "hasCallPathEvidence": 1.5,
    "hasExploitScenario": 2.0,
    "corroborationCount": 0.75,
    "distinctToolCount": 0.5,
}


def restricted_static_impact(row: Row) -> float:
    total = sum(
        weight * _numeric(row.features[name])
        for name, weight in RESTRICTED_IMPACT_WEIGHTS.items()
    )
    return total - 0.5 * float(row.features["severityRank"])


def _numeric(value: object) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    return float(value)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Logistic regression, from scratch
# --------------------------------------------------------------------------


@dataclass
class Encoder:
    """One-hot categoricals plus z-scored numerics, fitted on the train fold only."""

    columns: tuple[str, ...]
    categories: Mapping[str, tuple[str, ...]]
    means: Mapping[str, float]
    deviations: Mapping[str, float]

    def encode(self, row: Row) -> list[float]:
        values: list[float] = []
        for column in self.columns:
            feature, _, category = column.partition("=")
            if category:
                values.append(1.0 if category_token(row.features[feature]) == category else 0.0)
            else:
                values.append(
                    (numeric_of(row, feature) - self.means[feature]) / self.deviations[feature]
                )
        return values


def fit_encoder(rows: Sequence[Row], feature_schema: FeatureSchema) -> Encoder:
    """Builds the design matrix layout. Zero-variance numerics are dropped."""
    columns: list[str] = []
    categories: dict[str, tuple[str, ...]] = {}
    means: dict[str, float] = {}
    deviations: dict[str, float] = {}
    for name in sorted(feature_schema):
        if feature_schema[name] == CATEGORICAL:
            present = tuple(sorted({category_token(row.features[name]) for row in rows}))
            categories[name] = present
            columns.extend(f"{name}={value}" for value in present)
            continue
        mean, deviation = _mean_and_deviation([numeric_of(row, name) for row in rows])
        if deviation == 0.0:
            continue
        means[name], deviations[name] = mean, deviation
        columns.append(name)
    return Encoder(tuple(columns), categories, means, deviations)


def _mean_and_deviation(values: Sequence[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return mean, math.sqrt(variance)


@dataclass
class LogisticModel:
    encoder: Encoder
    weights: tuple[float, ...]
    bias: float

    def probability(self, row: Row) -> float:
        activation = self.bias + sum(
            weight * value for weight, value in zip(self.weights, self.encoder.encode(row))
        )
        return _sigmoid(activation)

    def scorer(self) -> Scorer:
        return self.probability


def _sigmoid(activation: float) -> float:
    if activation >= 0.0:
        return 1.0 / (1.0 + math.exp(-activation))
    exponential = math.exp(activation)
    return exponential / (1.0 + exponential)


def fit_logistic(
    rows: Sequence[Row],
    feature_schema: FeatureSchema,
    *,
    learning_rate: float = 0.1,
    epochs: int = 500,
    l2: float = 1e-3,
) -> LogisticModel:
    """Full-batch gradient descent from zero initialization.

    Deterministic by construction: no shuffling, no random initialization, so a
    refit on the same fold reproduces the same weights bit for bit.
    """
    encoder = fit_encoder(rows, feature_schema)
    design = [encoder.encode(row) for row in rows]
    labels = [float(row.label) for row in rows]
    weights = [0.0] * len(encoder.columns)
    bias = 0.0
    for _ in range(epochs):
        weights, bias = _descend(design, labels, weights, bias, learning_rate, l2)
    return LogisticModel(encoder, tuple(weights), bias)


def _descend(
    design: Sequence[Sequence[float]],
    labels: Sequence[float],
    weights: list[float],
    bias: float,
    learning_rate: float,
    l2: float,
) -> tuple[list[float], float]:
    count = len(design) or 1
    residuals = [
        _sigmoid(bias + sum(w * v for w, v in zip(weights, features))) - label
        for features, label in zip(design, labels)
    ]
    gradients = [
        sum(residual * features[index] for residual, features in zip(residuals, design)) / count
        + l2 * weights[index]
        for index in range(len(weights))
    ]
    updated = [weight - learning_rate * gradient for weight, gradient in zip(weights, gradients)]
    return updated, bias - learning_rate * (sum(residuals) / count)


def all_baselines(
    train_rows: Sequence[Row], feature_schema: FeatureSchema
) -> dict[str, Scorer]:
    """Every baseline, fitted where fitting is required. Names are report keys."""
    logistic = fit_logistic(train_rows, feature_schema)
    return {
        "majority_class": majority_class(train_rows),
        "severity_only": severity_only,
        "static_proof_severity": static_proof_severity,
        "restricted_static_impact": restricted_static_impact,
        "logistic_regression": logistic.scorer(),
    }


def sklearn_comparison_tree(
    train_rows: Sequence[Row],
    test_rows: Sequence[Row],
    feature_schema: FeatureSchema,
    *,
    max_depth: int,
    min_samples_leaf: int,
) -> dict[str, float]:
    """Optional library cross-check. Requires the extras venv.

    Kept behind a function-local import so the stdlib-only suite never depends on
    it, and so the failure is an actionable message rather than a collection error.
    """
    try:
        from sklearn.tree import DecisionTreeClassifier  # noqa: PLC0415
    except ImportError as error:  # pragma: no cover - exercised only without the venv
        raise RuntimeError(
            "scikit-learn is not installed. Run experiments/review-yield/scripts/"
            "setup-venv.sh and re-run with the venv's python."
        ) from error

    encoder = fit_encoder(train_rows, feature_schema)
    classifier = DecisionTreeClassifier(
        criterion="entropy",
        max_depth=max_depth,
        min_samples_leaf=min_samples_leaf,
        random_state=0,
    )
    classifier.fit(
        [encoder.encode(row) for row in train_rows], [row.label for row in train_rows]
    )
    probabilities = classifier.predict_proba([encoder.encode(row) for row in test_rows])
    positive_column = list(classifier.classes_).index(1)
    from .calibration import brier  # noqa: PLC0415

    return {
        "depth": float(classifier.get_depth()),
        "leaves": float(classifier.get_n_leaves()),
        "brier": brier(
            [row.label for row in test_rows],
            [float(row[positive_column]) for row in probabilities],
        ),
    }


__all__ = [
    "Encoder",
    "LogisticModel",
    "all_baselines",
    "fit_encoder",
    "fit_logistic",
    "majority_class",
    "restricted_static_impact",
    "severity_only",
    "sklearn_comparison_tree",
    "static_proof_severity",
]
