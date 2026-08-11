"""Model card renderer (design §18.3).

The card exists so a reader can tell what the artifact is entitled to claim. It
names the corpus by digest, states the baseline it was compared against *and*
why that baseline is a reconstruction, lists every failing gate, and ends with a
rollback that is one file deletion.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .dataset import FEATURE_WHITELIST
from .evaluate import Gate

PROHIBITED_USES = (
    "deciding that a finding is a false positive without a human review",
    "hiding, closing, or suppressing a finding",
    "moving a finding across a proof-confidence or severity boundary",
    "any claim that a low score means a finding is safe",
)


def render(
    *,
    model_id: str,
    dataset_digest: str,
    split_digest: str,
    row_counts: Mapping[str, int],
    configuration: Mapping[str, Any],
    metrics: Mapping[str, Mapping[str, float]],
    intervals: Mapping[str, Mapping[str, float]],
    holdouts: Sequence[Mapping[str, Any]],
    ablations: Mapping[str, Mapping[str, float]],
    gates: Sequence[Gate],
    training_command: str,
) -> str:
    """Renders the card. Every metric here is measured; none is illustrative."""
    sections = [
        _header(model_id, dataset_digest, split_digest, row_counts),
        _use_section(),
        _configuration_section(configuration, training_command),
        _metrics_section(metrics, intervals),
        _holdout_section(holdouts),
        _ablation_section(ablations),
        _gate_section(gates),
        _limitations_section(),
    ]
    return "\n\n".join(sections) + "\n"


def _header(
    model_id: str, dataset_digest: str, split_digest: str, row_counts: Mapping[str, int]
) -> str:
    counts = ", ".join(f"{name} {count}" for name, count in sorted(row_counts.items()))
    return "\n".join(
        [
            "# Review-yield model card",
            "",
            f"- model id: `{model_id}`",
            f"- dataset digest: `{dataset_digest}`",
            f"- frozen split: `{split_digest}`",
            f"- rows: {counts}",
            "- task: `review_yield_predecision_v1` — retrospective, not the "
            "prospective pre-review task a product model would need",
            "- label policy: `kuzushi-review-yield-labels-v1` — first eligible "
            "human decision; `confirmed`/`to_fix` positive, "
            "`rejected_false_positive` negative; policy outcomes excluded",
        ]
    )


def _use_section() -> str:
    prohibited = "\n".join(f"- {use}" for use in PROHIBITED_USES)
    return "\n".join(
        [
            "## Intended use",
            "",
            "Advisory only: an offline estimate of how often findings that looked "
            "like this one were confirmed by a human reviewer. It is evidence "
            "about review history, not about exploitability.",
            "",
            "## Prohibited uses",
            "",
            prohibited,
        ]
    )


def _configuration_section(configuration: Mapping[str, Any], training_command: str) -> str:
    rows = "\n".join(f"- `{key}`: {value}" for key, value in sorted(configuration.items()))
    features = ", ".join(f"`{name}`" for name in FEATURE_WHITELIST)
    return "\n".join(
        [
            "## Training configuration",
            "",
            rows,
            "",
            "Exact training command:",
            "",
            "```sh",
            training_command,
            "```",
            "",
            f"Feature schema (frozen, {len(FEATURE_WHITELIST)} fields): {features}",
            "",
            "Split policy: temporal 70/15/15 by label event sequence, frozen "
            "before model selection. Hyperparameters and pruning were selected on "
            "the validation fold only; the test fold was evaluated once.",
        ]
    )


def _metrics_section(
    metrics: Mapping[str, Mapping[str, float]], intervals: Mapping[str, Mapping[str, float]]
) -> str:
    lines = ["## Measured metrics", "", "| scorer | P@10% | P@20% | P@50% | R@20% | PR-AUC | Brier |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name in sorted(metrics):
        row = metrics[name]
        lines.append(
            f"| {name} | {row.get('precisionAt10', 0.0):.4f} | {row.get('precisionAt20', 0.0):.4f} "
            f"| {row.get('precisionAt50', 0.0):.4f} | {row.get('recallAt20', 0.0):.4f} "
            f"| {row.get('prAuc', 0.0):.4f} | {row.get('brier', 0.0):.4f} |"
        )
    if intervals:
        lines.extend(["", "Paired bootstrap by durable identity (95%):", ""])
        lines.extend(
            f"- {name}: {values['point']:+.4f} "
            f"[{values['low95']:+.4f}, {values['high95']:+.4f}]"
            for name, values in sorted(intervals.items())
        )
    return "\n".join(lines)


def _holdout_section(holdouts: Sequence[Mapping[str, Any]]) -> str:
    if not holdouts:
        return "## Holdouts\n\nNo group had enough examples for a holdout fold."
    lines = ["## Holdouts", "", "| axis | group | n | P@20% | PR-AUC |", "| --- | --- | ---: | ---: | ---: |"]
    lines.extend(
        f"| {item['axis']} | `{item['group']}` | {item['rows']} "
        f"| {item['precisionAt20']:.4f} | {item['prAuc']:.4f} |"
        for item in holdouts
    )
    lines.extend(
        [
            "",
            "If results hold only on repositories seen during training, the "
            "artifact is repository-local, not general.",
        ]
    )
    return "\n".join(lines)


def _ablation_section(ablations: Mapping[str, Mapping[str, float]]) -> str:
    if not ablations:
        return "## Ablations\n\nNot run."
    lines = ["## Ablations", "", "| removed | ΔPR-AUC | ΔP@20% |", "| --- | ---: | ---: |"]
    lines.extend(
        f"| {name} | {values['deltaPrAuc']:+.4f} | {values['deltaPrecisionAt20']:+.4f} |"
        for name, values in sorted(ablations.items())
    )
    return "\n".join(lines)


def _gate_section(gates: Sequence[Gate]) -> str:
    lines = ["## Promotion gates", "", "| gate | status | detail |", "| --- | --- | --- |"]
    lines.extend(f"| {gate.name} | `{gate.status}` | {gate.detail} |" for gate in gates)
    return "\n".join(lines)


def _limitations_section() -> str:
    return "\n".join(
        [
            "## Known bias and limitations",
            "",
            "- **Selective labels.** Only findings a human actually adjudicated "
            "appear. A retrospective replay cannot correct for what was never "
            "reviewed.",
            "- **Single-reviewer corpus.** Labels reflect one team's review "
            "conventions, not ground truth about exploitability. Human "
            "confirmation is not empirical proof.",
            "- **Baseline is a reconstruction.** The shipped confidence-first "
            "order cannot be replayed exactly from a pre-decision snapshot: three "
            "rival orderings exist in the codebase and the review queue's backlog "
            "toggle bypasses the documented one. The baseline here is proof band, "
            "then severity, then identity.",
            "- **Retrospective task.** `review_yield_predecision_v1` predicts a "
            "decision that has already happened. A product model needs the "
            "prospective pre-review task.",
            "- **Missing values are not routed.** Rows with an absent whitelisted "
            "feature are excluded from fitting and every internal node records "
            "`missingDirection: \"ineligible\"`.",
            "",
            "## Rollback",
            "",
            "Delete the artifact file and set review-yield mode off. There is no "
            "persisted state to unwind: the model is a file, and scoring is pure.",
        ]
    )
