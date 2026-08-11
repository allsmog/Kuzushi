"""Versioned model artifact export and digest verification (design §18).

This module owns the Python half of a two-language contract. PR 4's Rust loader
recomputes the same digest over the same bytes; `fixtures/parity/` pins them.

Digest rule (authoritative, from the PR 4 plan — it reuses the repo's existing
`hash_parts`, so agreement with the Rust event log's framing is structural):

    canonical = canonical JSON of the artifact with `modelId` removed
    digest    = hash_parts("kuzushi-review-yield-model-v1", [canonical])
    modelId   = "blake3:" + digest

Verification parses the file, drops `modelId`, re-canonicalizes, and recomputes
— exactly what the Rust loader does. That only works because every float in the
artifact is quantized so Python `repr` and Rust `ryu` produce identical text;
`hashing.canonical_json_bytes` fails loudly rather than emitting a form the two
languages would render differently.

The export refuses to write illustrative metrics as if they were measured
(design §18.1's closing note).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .hashing import (
    canonical_json_bytes,
    canonical_json_bytes_without_key,
    hash_parts,
    quantize_floats,
)
from .id3 import CATEGORICAL, NUMERIC, CategoryMap, TreeNode, iter_nodes

MODEL_DIGEST_DOMAIN = "kuzushi-review-yield-model-v1"
MODEL_SCHEMA_VERSION = 1
MODEL_KIND = "decision_tree"
TASK_ID = "review_yield_predecision_v1"
FEATURE_SCHEMA_ID = "kuzushi-review-yield-features-v1"
LABEL_POLICY_ID = "kuzushi-review-yield-labels-v1"

#: PR 4's bounded parser rejects anything larger (design §23.7).
MAX_MODEL_NODES = 127
MAX_MODEL_DEPTH = 6

DEFAULT_MINIMUM_LEAF_SUPPORT = 20
DEFAULT_MAXIMUM_UNKNOWN_CATEGORIES = 2
DEFAULT_HIGH_MINIMUM = 0.7
DEFAULT_MEDIUM_MINIMUM = 0.4

#: The §18.1 sample metrics. Shipping these as measured values is the specific
#: mistake the design calls out, so the exporter refuses them by identity.
ILLUSTRATIVE_METRICS: Mapping[str, float] = {
    "precisionAt20": 0.0,
    "recallAt20": 0.0,
    "prAuc": 0.0,
    "brier": 0.0,
}


class ExportError(ValueError):
    """The artifact cannot be written as an honest, loadable model."""


@dataclass(frozen=True)
class MeasuredEvaluation:
    """Metrics measured on a named dataset. There is no illustrative variant."""

    precision_at_20: float
    recall_at_20: float
    pr_auc: float
    brier: float
    measured_on_dataset_digest: str

    def as_artifact_block(self) -> dict[str, float]:
        return {
            "precisionAt20": self.precision_at_20,
            "recallAt20": self.recall_at_20,
            "prAuc": self.pr_auc,
            "brier": self.brier,
        }


@dataclass(frozen=True)
class TrainingProvenance:
    dataset_digest: str
    training_cutoff_seq: int
    random_seed: int
    max_depth: int
    min_samples_leaf: int
    criterion: str = "entropy"

    def as_artifact_block(self) -> dict[str, Any]:
        return {
            "datasetDigest": self.dataset_digest,
            "trainingCutoffSeq": self.training_cutoff_seq,
            "randomSeed": self.random_seed,
            "maxDepth": self.max_depth,
            "minSamplesLeaf": self.min_samples_leaf,
            "criterion": self.criterion,
        }


def build_artifact(
    tree: TreeNode,
    categories: CategoryMap,
    *,
    training: TrainingProvenance,
    evaluation: MeasuredEvaluation,
    minimum_leaf_support: int = DEFAULT_MINIMUM_LEAF_SUPPORT,
    maximum_unknown_categories: int = DEFAULT_MAXIMUM_UNKNOWN_CATEGORIES,
) -> dict[str, Any]:
    """Builds the sealed §18.1 artifact, `modelId` included."""
    _reject_illustrative(evaluation)
    nodes = build_nodes(tree, categories)
    _reject_out_of_bounds(nodes)
    artifact = {
        "schemaVersion": MODEL_SCHEMA_VERSION,
        "taskId": TASK_ID,
        "modelKind": MODEL_KIND,
        "featureSchemaId": FEATURE_SCHEMA_ID,
        "labelPolicyId": LABEL_POLICY_ID,
        "training": training.as_artifact_block(),
        "eligibility": {
            "minimumLeafSupport": minimum_leaf_support,
            "maximumUnknownCategories": maximum_unknown_categories,
        },
        "displayBands": {
            "highMinimum": DEFAULT_HIGH_MINIMUM,
            "mediumMinimum": DEFAULT_MEDIUM_MINIMUM,
        },
        "nodes": nodes,
        "evaluation": evaluation.as_artifact_block(),
    }
    return seal(quantize_floats(artifact))


def _reject_illustrative(evaluation: MeasuredEvaluation) -> None:
    if not evaluation.measured_on_dataset_digest:
        raise ExportError(
            "evaluation carries no dataset digest; the artifact would claim "
            "metrics nobody can trace back to a corpus"
        )
    if evaluation.as_artifact_block() == dict(ILLUSTRATIVE_METRICS):
        raise ExportError(
            "evaluation matches the design document's illustrative sample "
            "(all zeros); illustrative values must never ship as measured metrics"
        )


def _reject_out_of_bounds(nodes: Sequence[dict[str, Any]]) -> None:
    if not nodes:
        raise ExportError("a model artifact needs at least one node")
    if len(nodes) > MAX_MODEL_NODES:
        raise ExportError(
            f"{len(nodes)} nodes exceeds the loader's bound of {MAX_MODEL_NODES}"
        )


def build_nodes(tree: TreeNode, categories: CategoryMap) -> list[dict[str, Any]]:
    """Flat node table in pre-order; child ids always exceed their parent's."""
    ordered = iter_nodes(tree)
    identifiers = {id(node): index for index, node in enumerate(ordered)}
    return [_node_json(node, index, identifiers, categories) for index, node in enumerate(ordered)]


def _node_json(
    node: TreeNode,
    index: int,
    identifiers: Mapping[int, int],
    categories: CategoryMap,
) -> dict[str, Any]:
    if node.is_leaf:
        return _leaf_json(node, index)
    left = identifiers[id(node.left)]
    right = identifiers[id(node.right)]
    if node.split.kind == NUMERIC:
        return {
            "id": index,
            "nodeType": NUMERIC,
            "feature": node.split.feature,
            "threshold": float(node.split.threshold),
            "left": left,
            "right": right,
            "missingDirection": node.missing_direction,
        }
    return {
        "id": index,
        "nodeType": CATEGORICAL,
        "feature": node.split.feature,
        "branches": _branches(node, categories, left, right),
        "missingDirection": node.missing_direction,
    }


def _branches(
    node: TreeNode, categories: CategoryMap, left: int, right: int
) -> dict[str, int]:
    """One-vs-rest expanded over the feature's whole effective vocabulary.

    A value absent from this table is genuinely unseen in training, and PR 4's
    evaluator reports `UnknownCategory` for it rather than guessing a branch.
    """
    vocabulary = sorted(set(categories.get(node.split.feature, {}).values()))
    if node.split.category not in vocabulary:
        vocabulary.append(node.split.category)
    return {value: (left if value == node.split.category else right) for value in vocabulary}


def _leaf_json(node: TreeNode, index: int) -> dict[str, Any]:
    low, high = node.ci95
    return {
        "id": index,
        "nodeType": "leaf",
        "positiveCount": node.positive_count,
        "negativeCount": node.negative_count,
        "smoothedPositiveRate": node.smoothed_rate,
        "entropyBits": node.entropy_bits,
        "credibleInterval95": [low, high],
    }


# --------------------------------------------------------------------------
# Digest
# --------------------------------------------------------------------------


def hashed_bytes(artifact: Mapping[str, Any]) -> bytes:
    """Canonical bytes of the artifact with `modelId` removed."""
    return canonical_json_bytes_without_key(dict(artifact), "modelId")


def model_id(artifact: Mapping[str, Any]) -> str:
    return f"blake3:{hash_parts(MODEL_DIGEST_DOMAIN, [hashed_bytes(artifact)])}"


def seal(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Returns the artifact with its computed `modelId`."""
    sealed = dict(artifact)
    sealed["modelId"] = model_id(artifact)
    return sealed


def artifact_bytes(artifact: Mapping[str, Any]) -> bytes:
    """The exact file bytes: canonical form including `modelId`."""
    return canonical_json_bytes(dict(artifact))


def write_artifact(path: Path, artifact: Mapping[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(artifact_bytes(artifact))
    return path


def verify_artifact_bytes(raw: bytes) -> str:
    """Recomputes the digest the way PR 4's loader does. Returns the model id."""
    artifact = json.loads(raw)
    declared = artifact.get("modelId")
    if not isinstance(declared, str) or not declared.startswith("blake3:"):
        raise ExportError("artifact has no `blake3:`-prefixed modelId")
    computed = model_id(artifact)
    if computed != declared:
        raise ExportError(
            f"model digest mismatch: file declares {declared}, bytes hash to {computed}"
        )
    if artifact_bytes(artifact) != raw:
        raise ExportError(
            "artifact is not in canonical form; the digest matches but the file "
            "bytes do not round-trip, so two readers could disagree"
        )
    return declared


def verify_artifact(path: Path) -> str:
    return verify_artifact_bytes(path.read_bytes())


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="review-yield model artifact tool")
    parser.add_argument("--verify", type=Path, metavar="PATH", help="verify an artifact digest")
    args = parser.parse_args(argv)
    if args.verify is None:
        parser.error("nothing to do: pass --verify PATH")
    try:
        print(f"verified {args.verify}: {verify_artifact(args.verify)}")
    except (ExportError, OSError, json.JSONDecodeError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main())


__all__ = [
    "ExportError",
    "MAX_MODEL_DEPTH",
    "MAX_MODEL_NODES",
    "MODEL_DIGEST_DOMAIN",
    "MeasuredEvaluation",
    "TrainingProvenance",
    "artifact_bytes",
    "build_artifact",
    "build_nodes",
    "hashed_bytes",
    "model_id",
    "seal",
    "verify_artifact",
    "verify_artifact_bytes",
    "write_artifact",
]
