"""Standalone information-gain audit (design §13.4).

This report ships whether or not a model is ever promoted. Its value is not
prediction: it audits Kuzushi's own review assumptions. Low gain for severity
would say severity is an impact axis, not a precision axis. High gain for raw
tool identity would say the corpus encodes tool quality or tool memorization,
not evidence quality. High gain for `pathBucket` would point at a corpus problem
rather than a usable feature.

Stdlib only, and it never fits a tree — it reports the single best root split
per feature, so the numbers can be checked by hand.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .dataset import Row, load_jsonl, partition_complete_rows
from .entropy import entropy
from .id3 import (
    CandidateSplit,
    FeatureSchema,
    build_category_map,
    default_feature_schema,
    enumerate_splits,
    goes_left,
)
from .entropy import information_gain

#: Reading order for §13.4's interpretation checklist.
INTERPRETATION_FEATURES: tuple[str, ...] = (
    "severityRank",
    "staticProofState",
    "evidenceCount",
    "distinctToolCount",
    "pathBucket",
    "toolFamily",
)


@dataclass(frozen=True)
class FeatureGain:
    feature: str
    split: CandidateSplit | None
    gain_bits: float
    left_support: int
    right_support: int

    def describe(self) -> str:
        return "—" if self.split is None else self.split.describe()


def audit(
    rows: Sequence[Row],
    feature_schema: FeatureSchema | None = None,
    *,
    min_samples_leaf: int = 1,
) -> list[FeatureGain]:
    """Best root split per feature, sorted by gain descending then feature name."""
    schema = dict(feature_schema or default_feature_schema())
    categories = build_category_map(rows, schema, rare_category_min_count=5)
    gains = [
        _best_for_feature(rows, name, schema, categories, min_samples_leaf)
        for name in sorted(schema)
    ]
    return sorted(gains, key=lambda gain: (-gain.gain_bits, gain.feature))


def _best_for_feature(
    rows: Sequence[Row],
    name: str,
    schema: FeatureSchema,
    categories: dict,
    min_samples_leaf: int,
) -> FeatureGain:
    best = FeatureGain(name, None, 0.0, 0, 0)
    for split in enumerate_splits(rows, {name: schema[name]}, categories):
        left = sum(1 for row in rows if goes_left(row, split, categories))
        if min(left, len(rows) - left) < min_samples_leaf:
            continue
        gain = information_gain(
            rows, lambda row: row.label, lambda row, split=split: goes_left(row, split, categories)
        )
        if gain > best.gain_bits:
            best = FeatureGain(name, split, gain, left, len(rows) - left)
    return best


def render_markdown(rows: Sequence[Row], gains: Sequence[FeatureGain], dataset_digest: str) -> str:
    parent = entropy([row.label for row in rows])
    positives = sum(row.label for row in rows)
    lines = [
        "# Review-yield information-gain audit",
        "",
        "**Measured.** Every number below comes from the dataset named by the",
        f"digest `{dataset_digest}`. Nothing here is illustrative.",
        "",
        f"- rows: {len(rows)} ({positives} positive / {len(rows) - positives} negative)",
        f"- parent entropy: {parent:.6f} bits",
        "",
        "| feature | best root split | information gain (bits) | left n | right n |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    lines.extend(
        f"| `{gain.feature}` | `{gain.describe()}` | {gain.gain_bits:.6f} "
        f"| {gain.left_support} | {gain.right_support} |"
        for gain in gains
    )
    lines.extend(["", *_interpretation(gains)])
    return "\n".join(lines) + "\n"


def _interpretation(gains: Sequence[FeatureGain]) -> list[str]:
    by_name = {gain.feature: gain for gain in gains}
    lines = ["## Interpretation checklist (design §13.4)", ""]
    for feature in INTERPRETATION_FEATURES:
        gain = by_name.get(feature)
        if gain is None:
            continue
        lines.append(f"- `{feature}`: {gain.gain_bits:.6f} bits — {_reading(feature, gain)}")
    lines.extend(
        [
            "",
            "Read these as questions about the corpus, not as feature importances "
            "of a fitted model: a single root split ignores every interaction the "
            "tree exists to find.",
        ]
    )
    return lines


def _reading(feature: str, gain: FeatureGain) -> str:
    readings = {
        "severityRank": "low gain means severity ranks impact, not scanner precision",
        "staticProofState": "high gain supports evidence-first review order",
        "evidenceCount": "high gain suggests corroboration predicts a real finding",
        "distinctToolCount": "high gain suggests cross-tool agreement predicts a real finding",
        "pathBucket": "high gain points at corpus quality (test/generated noise), not a general feature",
        "toolFamily": "high gain suggests tool memorization or sharply uneven tool quality",
    }
    return readings[feature]


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="review-yield information-gain audit")
    parser.add_argument("--dataset", type=Path, required=True, help="dataset JSONL")
    parser.add_argument("--digest", default="unnamed-dataset", help="dataset digest to record")
    parser.add_argument("--out", type=Path, help="write the markdown report here")
    args = parser.parse_args(argv)

    complete, incomplete = partition_complete_rows(load_jsonl(args.dataset))
    gains = audit(complete)
    report = render_markdown(complete, gains, args.digest)
    if incomplete:
        report += (
            f"\n{len(incomplete)} row(s) were excluded for an absent whitelisted "
            "feature; version one audits complete rows only.\n"
        )
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
