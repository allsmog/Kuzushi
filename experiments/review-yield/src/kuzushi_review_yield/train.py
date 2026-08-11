"""Offline trainer: fit, select on validation, evaluate the test fold once.

Design §14.6, §16.10, §17, §18. Run identity is
`<datasetDigest8>-<configDigest8>`; there is no wall clock in the run id, in the
results, or in the artifact, so re-running the same corpus with the same grid
overwrites the same directory with byte-identical output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import model_card
from .baselines import all_baselines, sklearn_comparison_tree
from .bootstrap import Interval, paired_bootstrap_delta
from .calibration import brier, ece
from .dataset import Row, load_jsonl, partition_complete_rows
from .evaluate import (
    active_leaves,
    band_report,
    baseline_queue,
    budget_metrics,
    dataset_gates,
    model_gates,
    queue_metrics,
    scored_metrics,
    simulate_within_band_queue,
    ablation_schemas,
)
from .export_model import (
    MeasuredEvaluation,
    TrainingProvenance,
    build_artifact,
    write_artifact,
)
from .id3 import (
    TreeNode,
    build_category_map,
    default_feature_schema,
    fit_id3,
    leaves,
    prune,
    render_tree,
    score_rows,
    select_alpha,
    tree_depth,
    accuracy,
)
from .splits import TemporalSplit, freeze_manifest, temporal_split, verify_manifest

RANDOM_SEED = 6601
MAX_DEPTHS: tuple[int, ...] = (2, 3, 4, 5, 6)
MIN_SAMPLES_LEAVES: tuple[int, ...] = (10, 20, 40)
CLASS_WEIGHTS: tuple[str, ...] = ("none", "balanced")
MIN_GAIN = 1e-6

#: The intentionally permissive tree from §14.6, fitted only to show overfitting.
PERMISSIVE_MAX_DEPTH = 12
PERMISSIVE_MIN_SAMPLES_LEAF = 1


@dataclass(frozen=True)
class Configuration:
    max_depth: int
    min_samples_leaf: int
    class_weight: str

    def as_json(self) -> dict[str, Any]:
        return {
            "maxDepth": self.max_depth,
            "minSamplesLeaf": self.min_samples_leaf,
            "classWeight": self.class_weight,
        }


@dataclass
class Selection:
    configuration: Configuration
    alpha: float
    tree: TreeNode
    validation_brier: float


def grid() -> list[Configuration]:
    return [
        Configuration(depth, leaf, weight)
        for depth in MAX_DEPTHS
        for leaf in MIN_SAMPLES_LEAVES
        for weight in CLASS_WEIGHTS
    ]


def configuration_digest() -> str:
    payload = json.dumps(
        {
            "grid": [configuration.as_json() for configuration in grid()],
            "seed": RANDOM_SEED,
            "minGain": MIN_GAIN,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def select_model(
    split: TemporalSplit, feature_schema: Mapping[str, str], categories: Mapping
) -> Selection:
    """Grid search plus cost-complexity pruning, scored on validation only."""
    best: Selection | None = None
    for configuration in grid():
        tree = _fit(split.train, feature_schema, configuration)
        alpha = select_alpha(tree, split.validation, categories)
        pruned = prune(tree, alpha)
        score = brier(
            [row.label for row in split.validation],
            score_rows(pruned, split.validation, categories),
        )
        if best is None or score < best.validation_brier:
            best = Selection(configuration, alpha, pruned, score)
    assert best is not None, "the grid is never empty"
    return best


def _fit(
    rows: Sequence[Row], feature_schema: Mapping[str, str], configuration: Configuration
) -> TreeNode:
    return fit_id3(
        rows,
        feature_schema,
        max_depth=configuration.max_depth,
        min_samples_leaf=configuration.min_samples_leaf,
        min_gain=MIN_GAIN,
        class_weight=configuration.class_weight,
    )


def overfitting_report(
    split: TemporalSplit, feature_schema: Mapping[str, str], categories: Mapping, selected: TreeNode
) -> dict[str, float]:
    """Week 11: the permissive tree's train/validation gap next to the pruned one."""
    permissive = fit_id3(
        split.train,
        feature_schema,
        max_depth=PERMISSIVE_MAX_DEPTH,
        min_samples_leaf=PERMISSIVE_MIN_SAMPLES_LEAF,
        min_gain=0.0,
    )
    return {
        "permissiveDepth": float(tree_depth(permissive)),
        "permissiveLeaves": float(len(leaves(permissive))),
        "permissiveTrainAccuracy": accuracy(permissive, split.train, categories),
        "permissiveValidationAccuracy": accuracy(permissive, split.validation, categories),
        "selectedDepth": float(tree_depth(selected)),
        "selectedLeaves": float(len(leaves(selected))),
        "selectedTrainAccuracy": accuracy(selected, split.train, categories),
        "selectedValidationAccuracy": accuracy(selected, split.validation, categories),
    }


def tree_metrics(tree: TreeNode, rows: Sequence[Row], categories: Mapping) -> dict[str, float]:
    scores = score_rows(tree, rows, categories)
    metrics = budget_metrics(list(zip(rows, scores)))
    labels = [row.label for row in rows]
    metrics["brier"] = brier(labels, scores)
    metrics["ece"] = ece(labels, scores)
    return metrics


def holdout_results(
    rows: Sequence[Row],
    feature_schema: Mapping[str, str],
    selection: Configuration,
) -> list[dict[str, Any]]:
    """Leave-one-group-out for repository, tool family, and rule family."""
    from .splits import group_holdouts

    axes = {
        "repository": lambda row: row.repository_group,
        "toolFamily": lambda row: row.features["toolFamily"],
        "ruleFamily": lambda row: row.features["ruleFamily"],
    }
    results: list[dict[str, Any]] = []
    for axis, key in axes.items():
        for group, train, held_out in group_holdouts(rows, key):
            if len({row.label for row in train}) < 2:
                continue
            tree = _fit(train, feature_schema, selection)
            categories = build_category_map(train, feature_schema, 5)
            metrics = tree_metrics(tree, held_out, categories)
            results.append(
                {
                    "axis": axis,
                    "group": group,
                    "rows": len(held_out),
                    "precisionAt20": metrics["precisionAt20"],
                    "prAuc": metrics["prAuc"],
                }
            )
    return results


def ablation_results(
    split: TemporalSplit,
    feature_schema: dict[str, str],
    configuration: Configuration,
    reference: Mapping[str, float],
) -> dict[str, dict[str, float]]:
    results: dict[str, dict[str, float]] = {}
    for name, reduced in ablation_schemas(feature_schema).items():
        tree = _fit(split.train, reduced, configuration)
        categories = build_category_map(split.train, reduced, 5)
        metrics = tree_metrics(tree, split.test, categories)
        results[name] = {
            "prAuc": metrics["prAuc"],
            "precisionAt20": metrics["precisionAt20"],
            "deltaPrAuc": metrics["prAuc"] - reference["prAuc"],
            "deltaPrecisionAt20": metrics["precisionAt20"] - reference["precisionAt20"],
        }
    return results


def queue_delta_interval(
    rows: Sequence[Row], tree: TreeNode, categories: Mapping, minimum_leaf_support: int
) -> Interval:
    """Paired bootstrap of ΔPrecision@20% between the tree policy and baseline."""

    def delta(sample: Sequence[Row]) -> float:
        model_queue = simulate_within_band_queue(
            sample, tree, categories, minimum_leaf_support=minimum_leaf_support
        )
        return _precision20(model_queue) - _precision20(baseline_queue(sample))

    return paired_bootstrap_delta(list(rows), delta, seed=RANDOM_SEED)


def _precision20(queue: Sequence[Row]) -> float:
    return queue_metrics(queue)["precisionAt20"]


def _run(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    rows = load_jsonl(args.dataset)
    complete, incomplete = partition_complete_rows(rows)
    dataset_digest = _dataset_digest(args)
    feature_schema = default_feature_schema()
    split = temporal_split(complete)
    out_dir = args.out_dir or Path("reports") / _run_id(dataset_digest)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = split.manifest()
    freeze_manifest(manifest, out_dir)
    verify_manifest(manifest, temporal_split(complete))

    categories = build_category_map(split.train, feature_schema, 5)
    selection = select_model(split, feature_schema, categories)
    results = _assemble(
        split, complete, incomplete, feature_schema, categories, selection, dataset_digest, args
    )
    _write_outputs(out_dir, results, selection, categories, dataset_digest, manifest.digest, args)
    print(f"run {out_dir}")
    print(render_tree(selection.tree))
    return 0


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="review-yield offline trainer")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, help="dataset manifest sidecar")
    parser.add_argument("--out-dir", type=Path, help="report directory (default reports/<runid>)")
    parser.add_argument(
        "--sklearn-comparison",
        action="store_true",
        help="also fit a scikit-learn entropy tree (needs the extras venv)",
    )
    return parser.parse_args(argv)


def _dataset_digest(args: argparse.Namespace) -> str:
    if args.manifest and args.manifest.exists():
        return json.loads(args.manifest.read_text(encoding="utf-8"))["datasetDigest"]
    return f"sha256:{hashlib.sha256(args.dataset.read_bytes()).hexdigest()}"


def _run_id(dataset_digest: str) -> str:
    return f"{dataset_digest.split(':')[-1][:8]}-{configuration_digest()[:8]}"


def _assemble(
    split: TemporalSplit,
    complete: Sequence[Row],
    incomplete: Sequence[Row],
    feature_schema: dict[str, str],
    categories: Mapping,
    selection: Selection,
    dataset_digest: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    test_metrics = tree_metrics(selection.tree, split.test, categories)
    baseline_metrics = {
        name: scored_metrics(split.test, scorer)
        for name, scorer in all_baselines(split.train, feature_schema).items()
    }
    model_queue = simulate_within_band_queue(split.test, selection.tree, categories)
    interval = queue_delta_interval(split.test, selection.tree, categories, 20)
    gates = dataset_gates(complete, len(incomplete)) + model_gates(
        selection.tree,
        active_leaves=active_leaves(selection.tree),
        delta_precision_low=interval.low,
        temporal_precision_delta=(
            test_metrics["precisionAt20"]
            - baseline_metrics["static_proof_severity"]["precisionAt20"]
        ),
    )
    return {
        "datasetDigest": dataset_digest,
        "rows": {
            "total": len(complete) + len(incomplete),
            "complete": len(complete),
            "excludedIncomplete": len(incomplete),
            "train": len(split.train),
            "validation": len(split.validation),
            "test": len(split.test),
        },
        "selected": {
            **selection.configuration.as_json(),
            "ccpAlpha": selection.alpha,
            "validationBrier": selection.validation_brier,
        },
        "testMetrics": test_metrics,
        "baselineMetrics": baseline_metrics,
        "withinBandQueue": queue_metrics(model_queue),
        "withinBandRoom": band_report(split.test, selection.tree, categories),
        "baselineQueue": queue_metrics(baseline_queue(split.test)),
        "deltaPrecisionAt20": interval.as_json(),
        "overfitting": overfitting_report(split, feature_schema, categories, selection.tree),
        "holdouts": holdout_results(complete, feature_schema, selection.configuration),
        "ablations": ablation_results(
            split, feature_schema, selection.configuration, test_metrics
        ),
        "gates": [gate.as_json() for gate in gates],
        "sklearnComparison": _sklearn_block(split, feature_schema, selection, args),
        "testFoldEvaluations": 1,
        "note": (
            "Selection used the validation fold only; the test fold was scored "
            "once. Changing the model after reading these test errors invalidates "
            "the test fold (design §16.10)."
        ),
        "_gates": gates,
    }


def _sklearn_block(
    split: TemporalSplit,
    feature_schema: dict[str, str],
    selection: Selection,
    args: argparse.Namespace,
) -> dict[str, Any] | None:
    if not args.sklearn_comparison:
        return None
    return sklearn_comparison_tree(
        split.train,
        split.test,
        feature_schema,
        max_depth=selection.configuration.max_depth,
        min_samples_leaf=selection.configuration.min_samples_leaf,
    )


def _write_outputs(
    out_dir: Path,
    results: dict[str, Any],
    selection: Selection,
    categories: Mapping,
    dataset_digest: str,
    split_digest: str,
    args: argparse.Namespace,
) -> None:
    gates = results.pop("_gates")
    metrics = results["testMetrics"]
    artifact = build_artifact(
        selection.tree,
        categories,
        training=TrainingProvenance(
            dataset_digest=dataset_digest,
            training_cutoff_seq=results["rows"]["train"],
            random_seed=RANDOM_SEED,
            max_depth=selection.configuration.max_depth,
            min_samples_leaf=selection.configuration.min_samples_leaf,
        ),
        evaluation=MeasuredEvaluation(
            precision_at_20=metrics["precisionAt20"],
            recall_at_20=metrics["recallAt20"],
            pr_auc=metrics["prAuc"],
            brier=metrics["brier"],
            measured_on_dataset_digest=dataset_digest,
        ),
    )
    write_artifact(out_dir / "model.json", artifact)
    (out_dir / "results.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "tree.txt").write_text(render_tree(selection.tree) + "\n", encoding="utf-8")
    (out_dir / "model-card.md").write_text(
        model_card.render(
            model_id=artifact["modelId"],
            dataset_digest=dataset_digest,
            split_digest=split_digest,
            row_counts=results["rows"],
            configuration=results["selected"],
            metrics={"decision_tree": metrics, **results["baselineMetrics"]},
            intervals={"deltaPrecisionAt20": results["deltaPrecisionAt20"]},
            holdouts=results["holdouts"],
            ablations=results["ablations"],
            gates=gates,
            training_command=(
                f"PYTHONPATH=src python3 -m kuzushi_review_yield.train "
                f"--dataset {args.dataset} --out-dir {out_dir}"
            ),
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    sys.exit(_run())
