#!/usr/bin/env python3
"""Regenerates fixtures/parity/ — the Python<->Rust model contract.

Run this only when the canonical rule or the artifact shape changes on purpose.
Both `tests/test_parity_fixtures.py` and PR 4's Rust tests read the committed
output; regenerating it without a matching Rust change breaks the contract, so
the digests are pinned on both sides.

    PYTHONPATH=src python3 scripts/build-parity-fixtures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kuzushi_review_yield.artifact_eval import evaluate_artifact  # noqa: E402
from kuzushi_review_yield.export_model import (  # noqa: E402
    artifact_bytes,
    hashed_bytes,
    seal,
    verify_artifact_bytes,
)
from kuzushi_review_yield.hashing import quantize_floats  # noqa: E402

PARITY = ROOT / "fixtures" / "parity"

COMMON = {
    "schemaVersion": 1,
    "taskId": "review_yield_predecision_v1",
    "modelKind": "decision_tree",
    "featureSchemaId": "kuzushi-review-yield-features-v1",
    "labelPolicyId": "kuzushi-review-yield-labels-v1",
    "displayBands": {"highMinimum": 0.7, "mediumMinimum": 0.4},
}


def numeric_small() -> dict:
    """Design §18.1's own three-node example, with real counts and intervals."""
    return {
        **COMMON,
        "training": {
            "datasetDigest": "blake3:" + "00" * 32,
            "trainingCutoffSeq": 9000,
            "randomSeed": 6601,
            "maxDepth": 4,
            "minSamplesLeaf": 20,
            "criterion": "entropy",
        },
        "eligibility": {"minimumLeafSupport": 20, "maximumUnknownCategories": 2},
        "nodes": [
            {
                "id": 0,
                "nodeType": "numeric",
                "feature": "evidenceCount",
                "threshold": 2.5,
                "left": 1,
                "right": 2,
                "missingDirection": "ineligible",
            },
            _leaf(1, 12, 44),
            _leaf(2, 31, 6),
        ],
        "evaluation": {
            "precisionAt20": 0.625,
            "recallAt20": 0.25,
            "prAuc": 0.652023,
            "brier": 0.205708,
        },
    }


def mixed_depth3() -> dict:
    """Categorical root, numeric inner nodes, a left-routed missing direction,
    and one leaf deliberately below `minimumLeafSupport`.

    Several branch keys share a child, which is what one-vs-rest expansion always
    produces; no node has two *parents*, which PR 4's loader rejects.
    """
    return {
        **COMMON,
        "training": {
            "datasetDigest": "blake3:" + "11" * 32,
            "trainingCutoffSeq": 12000,
            "randomSeed": 6601,
            "maxDepth": 3,
            "minSamplesLeaf": 10,
            "criterion": "entropy",
        },
        "eligibility": {"minimumLeafSupport": 20, "maximumUnknownCategories": 2},
        "nodes": [
            {
                "id": 0,
                "nodeType": "categorical",
                "feature": "staticProofState",
                "branches": {
                    "code_cited": 1,
                    "signal_only": 2,
                    "source_sink_linked": 1,
                    "statically_confirmed": 2,
                },
                "missingDirection": "ineligible",
            },
            {
                "id": 1,
                "nodeType": "numeric",
                "feature": "evidenceCount",
                "threshold": 3.5,
                "left": 3,
                "right": 4,
                "missingDirection": "left",
            },
            {
                "id": 2,
                "nodeType": "numeric",
                "feature": "maxEvidenceConfidence",
                "threshold": 200.0,
                "left": 5,
                "right": 6,
                "missingDirection": "ineligible",
            },
            _leaf(3, 9, 51),
            _leaf(4, 40, 11),
            _leaf(5, 3, 9),
            _leaf(6, 55, 14),
        ],
        "evaluation": {
            "precisionAt20": 0.75,
            "recallAt20": 0.3,
            "prAuc": 0.71,
            "brier": 0.18,
        },
    }


def _leaf(identifier: int, positive: int, negative: int) -> dict:
    from kuzushi_review_yield.calibration import (
        beta_credible_interval,
        jeffreys_rate,
    )
    from kuzushi_review_yield.entropy import entropy

    low, high = beta_credible_interval(positive, negative)
    return {
        "id": identifier,
        "nodeType": "leaf",
        "positiveCount": positive,
        "negativeCount": negative,
        "smoothedPositiveRate": jeffreys_rate(positive, negative),
        "entropyBits": entropy([1] * positive + [0] * negative),
        "credibleInterval95": [low, high],
    }


SCORE_CASES = [
    ("model-numeric-small.json", "eligible high leaf", {"evidenceCount": 5}),
    ("model-numeric-small.json", "eligible low leaf", {"evidenceCount": 1}),
    ("model-numeric-small.json", "threshold boundary goes left", {"evidenceCount": 2.5}),
    ("model-numeric-small.json", "missing routed ineligible", {"evidenceCount": None}),
    ("model-numeric-small.json", "feature absent from vector", {}),
    (
        "model-mixed-depth3.json",
        "missing numeric routed left",
        {"staticProofState": "code_cited", "evidenceCount": None},
    ),
    (
        "model-mixed-depth3.json",
        "categorical branch then numeric right",
        {"staticProofState": "source_sink_linked", "evidenceCount": 7},
    ),
    (
        "model-mixed-depth3.json",
        "under-support leaf",
        {"staticProofState": "signal_only", "maxEvidenceConfidence": 120},
    ),
    (
        "model-mixed-depth3.json",
        "unknown category",
        {"staticProofState": "needs_runtime_evidence"},
    ),
    (
        "model-mixed-depth3.json",
        "confirmed branch then numeric right",
        {"staticProofState": "statically_confirmed", "maxEvidenceConfidence": 220},
    ),
]


def main() -> int:
    PARITY.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "model-numeric-small.json": seal(quantize_floats(numeric_small())),
        "model-mixed-depth3.json": seal(quantize_floats(mixed_depth3())),
    }
    digests = {}
    for name, artifact in artifacts.items():
        raw = artifact_bytes(artifact)
        (PARITY / name).write_bytes(raw)
        verify_artifact_bytes(raw)
        digests[name] = {
            "modelId": artifact["modelId"],
            "canonicalBytesLength": len(hashed_bytes(artifact)),
            "fileBytesLength": len(raw),
        }

    tampered = dict(artifacts["model-numeric-small.json"])
    tampered["modelId"] = _flip_last_hex(tampered["modelId"])
    (PARITY / "model-tampered-hash.json").write_bytes(artifact_bytes(tampered))
    digests["model-tampered-hash.json"] = {
        "declaredModelId": tampered["modelId"],
        "expectedModelId": artifacts["model-numeric-small.json"]["modelId"],
        "note": "one flipped hex character; must fail closed as a hash mismatch",
    }

    _write_json(PARITY / "pinned-digests.json", {
        "domain": "kuzushi-review-yield-model-v1",
        "framing": "blake3(u64_be(10)||'kuzushi:v3'||u64_be(len(domain))||domain||u64_be(len(canonical))||canonical)",
        "artifacts": digests,
    })
    _write_json(PARITY / "expected-scores.json", {"cases": _cases(artifacts)})
    print(f"wrote {len(artifacts) + 3} files into {PARITY}")
    return 0


def _cases(artifacts: dict) -> list[dict]:
    cases = []
    for model, name, features in SCORE_CASES:
        expected = evaluate_artifact(artifacts[model], features)
        cases.append({"model": model, "name": name, "features": features, "expected": expected})
    return cases


def _flip_last_hex(model_id: str) -> str:
    last = model_id[-1]
    return model_id[:-1] + ("0" if last != "0" else "1")


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
