"""Temporal splits, frozen split manifests, and group holdouts.

Design §16.1-§16.4. A random 80/20 split lets a tree memorize repositories,
scanners, rules, and neighbouring time periods, so the primary split is by label
event sequence and the fold membership is frozen to disk *before* any model
selection runs. `verify_manifest` refuses to evaluate against a manifest whose
dataset or fold membership has drifted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Sequence

from .dataset import TASK_ID, Row

TRAIN_FRACTION = 0.70
VALIDATION_FRACTION = 0.15


class SplitError(ValueError):
    """The frozen split no longer describes the dataset being evaluated."""


@dataclass(frozen=True)
class SplitManifest:
    """Frozen fold membership. `digest` covers the task and all three folds."""

    task_id: str
    train: tuple[str, ...]
    validation: tuple[str, ...]
    test: tuple[str, ...]
    digest: str

    def to_json(self) -> dict[str, object]:
        return {
            "taskId": self.task_id,
            "foldExampleIds": {
                "train": list(self.train),
                "validation": list(self.validation),
                "test": list(self.test),
            },
            "sha256": self.digest,
        }

    @classmethod
    def from_json(cls, payload: dict) -> "SplitManifest":
        folds = payload["foldExampleIds"]
        return cls(
            task_id=payload["taskId"],
            train=tuple(folds["train"]),
            validation=tuple(folds["validation"]),
            test=tuple(folds["test"]),
            digest=payload["sha256"],
        )


@dataclass(frozen=True)
class TemporalSplit:
    train: list[Row]
    validation: list[Row]
    test: list[Row]

    def manifest(self) -> SplitManifest:
        return build_manifest(self.train, self.validation, self.test)


def temporal_split(
    rows: Sequence[Row],
    train_fraction: float = TRAIN_FRACTION,
    validation_fraction: float = VALIDATION_FRACTION,
) -> TemporalSplit:
    """Oldest `train_fraction` trains, the next slice validates, the newest tests.

    Order is `(labelEvent.seq, exampleId)`, so two decisions recorded at the same
    sequence still land in a stable order.
    """
    ordered = sorted(rows, key=lambda row: (row.label_seq, row.example_id))
    train_end = int(len(ordered) * train_fraction)
    validation_end = train_end + int(len(ordered) * validation_fraction)
    return TemporalSplit(
        train=ordered[:train_end],
        validation=ordered[train_end:validation_end],
        test=ordered[validation_end:],
    )


def build_manifest(
    train: Sequence[Row], validation: Sequence[Row], test: Sequence[Row]
) -> SplitManifest:
    folds = {
        "train": [row.example_id for row in train],
        "validation": [row.example_id for row in validation],
        "test": [row.example_id for row in test],
    }
    payload = json.dumps(
        {"taskId": TASK_ID, "foldExampleIds": folds},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return SplitManifest(
        task_id=TASK_ID,
        train=tuple(folds["train"]),
        validation=tuple(folds["validation"]),
        test=tuple(folds["test"]),
        digest=hashlib.sha256(payload).hexdigest(),
    )


def freeze_manifest(manifest: SplitManifest, directory: Path) -> Path:
    """Writes `split-manifest-<digest8>.json`. Refuses to overwrite a differing file."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"split-manifest-{manifest.digest[:8]}.json"
    payload = json.dumps(manifest.to_json(), sort_keys=True, indent=2) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") != payload:
        raise SplitError(
            f"{path} already holds a different split with the same digest prefix; "
            "resolve the collision rather than overwriting a frozen split"
        )
    path.write_text(payload, encoding="utf-8")
    return path


def load_manifest(path: Path) -> SplitManifest:
    return SplitManifest.from_json(json.loads(path.read_text(encoding="utf-8")))


def verify_manifest(manifest: SplitManifest, split: TemporalSplit) -> None:
    """Fails when the recomputed split does not match the frozen one."""
    recomputed = split.manifest()
    if recomputed.digest == manifest.digest:
        return
    raise SplitError(
        "split manifest drift: the frozen folds "
        f"({manifest.digest[:8]}) do not match the dataset's current folds "
        f"({recomputed.digest[:8]}). Freeze a new split for a new dataset "
        "instead of evaluating against stale fold membership."
    )


def group_holdouts(
    rows: Sequence[Row],
    key: Callable[[Row], str],
    min_size: int = 20,
) -> Iterator[tuple[str, list[Row], list[Row]]]:
    """Leave-one-group-out folds as `(group, train, held_out)`.

    Groups smaller than `min_size` are skipped rather than reported as a holdout
    result nobody should read (design §16.3).
    """
    grouped: dict[str, list[Row]] = {}
    for row in rows:
        grouped.setdefault(key(row), []).append(row)
    for group in sorted(grouped):
        held_out = grouped[group]
        if len(held_out) < min_size:
            continue
        train = [row for row in rows if key(row) != group]
        if train:
            yield group, train, held_out
