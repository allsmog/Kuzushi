"""Shared fixture access for the review-yield tests. Stdlib only."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
PARITY = FIXTURES / "parity"

if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from kuzushi_review_yield.dataset import Row, load_jsonl  # noqa: E402

TINY = FIXTURES / "tiny-hand-verified.jsonl"
TINY_MANIFEST = FIXTURES / "tiny-manifest.json"
SYNTHETIC = FIXTURES / "synthetic-kuzushi-corpus.jsonl"
SYNTHETIC_MANIFEST = FIXTURES / "synthetic-kuzushi-corpus.jsonl.manifest.json"


def tiny_rows() -> list[Row]:
    return load_jsonl(TINY)


def tiny_records() -> list[dict[str, Any]]:
    return [json.loads(line) for line in TINY.read_text(encoding="utf-8").splitlines() if line]


def synthetic_rows() -> list[Row]:
    return load_jsonl(SYNTHETIC)


def parity_json(name: str) -> dict[str, Any]:
    return json.loads((PARITY / name).read_text(encoding="utf-8"))


def make_row(index: int = 0, **feature_overrides: Any) -> Row:
    """A row built from the tiny fixture with feature overrides applied.

    Row identity is derived from the overrides so two differently-configured
    rows never collide in a uniqueness check.
    """
    base = tiny_rows()[index]
    features = copy.deepcopy(base.features)
    features.update(feature_overrides)
    token = "|".join(f"{key}={value}" for key, value in sorted(feature_overrides.items()))
    return Row(
        example_id=f"{base.example_id}:{token}",
        identity_group=f"{base.identity_group}:{token}",
        repository_group=base.repository_group,
        feature_cutoff_seq=base.feature_cutoff_seq,
        anchor_seq=base.anchor_seq,
        label_seq=base.label_seq,
        verdict=base.verdict,
        label=base.label,
        cutoff_quality=base.cutoff_quality,
        features=features,
    )


def labeled_row(label: int, index: int = 0, **feature_overrides: Any) -> Row:
    row = make_row(index, **feature_overrides)
    return Row(
        example_id=f"{row.example_id}#{label}",
        identity_group=f"{row.identity_group}#{label}",
        repository_group=row.repository_group,
        feature_cutoff_seq=row.feature_cutoff_seq,
        anchor_seq=row.anchor_seq,
        label_seq=row.label_seq,
        verdict="confirmed" if label else "rejected_false_positive",
        label=label,
        cutoff_quality=row.cutoff_quality,
        features=row.features,
    )


def has_module(name: str) -> bool:
    """Whether an optional extra is importable (used by `skipUnless`)."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False
