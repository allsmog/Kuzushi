"""Offline Weeks 9-11 review-yield experiment (design §15).

Offline only (ADR-1). Nothing in this package is imported by Kuzushi's Rust
runtime, and nothing here ever opens Kuzushi's SQLite store: it consumes the
JSONL corpus that `kuzushi review-yield export` writes.

The core learner and the whole test suite are stdlib-only, so
`PYTHONPATH=src python3 -m unittest discover -s tests` runs with zero installs.
`scikit-learn` is an optional comparison only.
"""

__all__ = [
    "baselines",
    "blake3_pure",
    "bootstrap",
    "calibration",
    "dataset",
    "entropy",
    "evaluate",
    "export_model",
    "hashing",
    "id3",
    "ig_audit",
    "model_card",
    "splits",
    "train",
]
