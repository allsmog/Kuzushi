"""The training-row contract, mirrored from what `kuzushi review-yield export` emits.

The authority for this file is the merged Rust exporter on this branch —
`crates/kuzushi-core/src/review_yield/domain/{feature_schema,training_example,
label_policy}.rs` and `schemas/review-yield.training-example.schema.json` — not
any prose. The loader is strict on purpose: an unknown feature key, a forbidden
key, a duplicate identity, or a broken `anchor <= cutoff < label` ordering is a
corrupt corpus, not something to repair silently.

`gen_synthetic_corpus` produces the committed fixture. No real Kuzushi review
data is ever committed to this repository (design §11.4).
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from .hashing import canonical_json_bytes, prefixed_digest

SCHEMA_VERSION = 1
TASK_ID = "review_yield_predecision_v1"
FEATURE_SCHEMA_ID = "kuzushi-review-yield-features-v1"
LABEL_POLICY_ID = "kuzushi-review-yield-labels-v1"
EXPORTER_VERSION = "0.0.0-synthetic"

#: Frozen field order of `ReviewYieldFeaturesV1` (feature_schema.rs).
FEATURE_WHITELIST: tuple[str, ...] = (
    "severityRank",
    "staticProofState",
    "vulnSource",
    "toolFamily",
    "ruleFamily",
    "pathBucket",
    "languageFamily",
    "identityMatchTier",
    "groundingStatus",
    "isAttackChain",
    "evidenceCount",
    "distinctEvidenceKinds",
    "maxEvidenceConfidence",
    "meanEvidenceConfidenceMillis",
    "hasSourceEvidence",
    "hasSinkEvidence",
    "hasSanitizerEvidence",
    "hasCallPathEvidence",
    "sourceSinkLinked",
    "sanitizerChecked",
    "hasExploitScenario",
    "preconditionCount",
    "sourceCount",
    "distinctToolCount",
    "corroborationCount",
    "observationCount",
    "runCount",
    "reopenedCount",
    "hasRemediation",
)

CATEGORICAL_FEATURES: tuple[str, ...] = (
    "staticProofState",
    "vulnSource",
    "toolFamily",
    "ruleFamily",
    "pathBucket",
    "languageFamily",
    "identityMatchTier",
    "groundingStatus",
)

BOOLEAN_FEATURES: tuple[str, ...] = (
    "isAttackChain",
    "hasSourceEvidence",
    "hasSinkEvidence",
    "hasSanitizerEvidence",
    "hasCallPathEvidence",
    "sourceSinkLinked",
    "sanitizerChecked",
    "hasExploitScenario",
    "hasRemediation",
)

NUMERIC_FEATURES: tuple[str, ...] = tuple(
    name
    for name in FEATURE_WHITELIST
    if name not in CATEGORICAL_FEATURES and name not in BOOLEAN_FEATURES
)

#: Features whose exported value may be JSON null (design §10.6). Absence is a
#: state, never imputed as zero.
NULLABLE_FEATURES: frozenset[str] = frozenset(
    {"maxEvidenceConfidence", "meanEvidenceConfidenceMillis"}
)

#: Keys that must never reach a feature vector: they carry the verdict the row
#: is meant to predict, or raw content the privacy contract forbids (§10.4).
FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "triage",
        "triagedBy",
        "triaged_by",
        "suppressed",
        "snoozedUntil",
        "verification",
        "rationale",
        "reviewer",
        "message",
        "title",
        "description",
        "path",
        "filePath",
        "snippet",
        "evidence",
        "createdAt",
        "timestamp",
    }
)

#: `missing` is a real classification but never appears in an exported file:
#: such a decision has no usable read cutoff and is excluded (label_policy.rs).
CUTOFF_QUALITY_CLASSIFICATIONS: tuple[str, ...] = (
    "tui_read_watermark",
    "barrier_at_head",
    "missing",
)
EXPORTED_CUTOFF_QUALITY: tuple[str, ...] = ("tui_read_watermark", "barrier_at_head")

STATIC_PROOF_STATES: tuple[str, ...] = (
    "signal_only",
    "code_cited",
    "source_sink_linked",
    "sanitizer_checked",
    "statically_confirmed",
    "statically_rejected",
    "needs_runtime_evidence",
    "missing",
)

#: Ordering used only by the reconstructable proof/severity baseline. The Rust
#: `StaticProofState` derives `Ord` from declaration order, which is not a
#: confidence ladder (amendment 14) — this ladder is stated here explicitly.
STATIC_PROOF_CONFIDENCE_RANK: dict[str, int] = {
    "statically_confirmed": 0,
    "sanitizer_checked": 1,
    "source_sink_linked": 2,
    "code_cited": 3,
    "needs_runtime_evidence": 4,
    "signal_only": 5,
    "missing": 6,
    "statically_rejected": 7,
}

#: Coarse proof *bands* for the within-band queue policy (§16.6). A band, not a
#: state: the product's promise is that a model never moves a finding across a
#: proof boundary, and the boundary is the band, so eight raw states would make
#: every band a singleton and the policy untestable.
PROOF_BAND: dict[str, int] = {
    "statically_confirmed": 0,
    "sanitizer_checked": 1,
    "source_sink_linked": 1,
    "code_cited": 1,
    "needs_runtime_evidence": 2,
    "signal_only": 2,
    "missing": 2,
    "statically_rejected": 3,
}

VULN_SOURCES: tuple[str, ...] = (
    "sarif",
    "analysis",
    "analysis-multi",
    "diff-analyzer",
    "infer",
    "fuzzing",
    "unknown",
)

TOOL_FAMILIES: tuple[str, ...] = (
    "semgrep",
    "codeql",
    "secret-scan",
    "iac-scan",
    "dep-hygiene",
    "govulncheck",
    "infer",
    "systems-hunt",
    "carlini-threat-hunt",
    "full-mode-multi",
    "variant-ndiff",
    "chains",
    "other",
)

RULE_FAMILIES: tuple[str, ...] = (
    "authentication",
    "authorization",
    "availability",
    "command_injection",
    "concurrency",
    "crypto",
    "csrf",
    "deserialization",
    "injection",
    "memory_safety",
    "other",
    "path_traversal",
    "secrets",
    "sql_injection",
    "ssrf",
    "xss",
)

PATH_BUCKETS: tuple[str, ...] = (
    "application",
    "test",
    "generated",
    "vendor",
    "example",
    "config",
    "docs",
    "unknown",
)

IDENTITY_MATCH_TIERS: tuple[str, ...] = (
    "stable_fp",
    "dedup_collision",
    "dedup_key_cross_run",
    "model_dedupe",
    "unknown",
)

GROUNDING_STATUSES: tuple[str, ...] = (
    "grounded",
    "line_drift",
    "file_missing",
    "not_applicable",
    "native_or_unspecified",
)

LANGUAGE_FAMILIES: tuple[str, ...] = (
    "rust",
    "python",
    "typescript",
    "go",
    "java",
    "c",
    "unknown",
)

#: Closed vocabularies exactly as the exporter records them in the manifest.
#: `languageFamily` is open (pattern-validated), so it is not listed here.
CATEGORICAL_VOCABULARY: dict[str, tuple[str, ...]] = {
    "groundingStatus": tuple(sorted(GROUNDING_STATUSES)),
    "identityMatchTier": tuple(sorted(IDENTITY_MATCH_TIERS)),
    "pathBucket": tuple(sorted(PATH_BUCKETS)),
    "ruleFamily": tuple(sorted(RULE_FAMILIES)),
    "staticProofState": tuple(sorted(STATIC_PROOF_STATES)),
    "toolFamily": tuple(sorted(TOOL_FAMILIES)),
    "vulnSource": tuple(sorted(VULN_SOURCES)),
}

VERDICT_CLASS: dict[str, int] = {
    "confirmed": 1,
    "to_fix": 1,
    "rejected_false_positive": 0,
}


class DatasetError(ValueError):
    """The corpus violates the exported contract and must not be trained on."""


@dataclass(frozen=True)
class Row:
    """One exported training example, already contract-checked."""

    example_id: str
    identity_group: str
    repository_group: str
    feature_cutoff_seq: int
    anchor_seq: int
    label_seq: int
    verdict: str
    label: int
    cutoff_quality: str
    features: dict[str, Any]

    def value(self, feature: str) -> Any:
        return self.features[feature]

    def is_complete(self) -> bool:
        """Whether every whitelisted feature has a value (design §10.6)."""
        return all(self.features[name] is not None for name in FEATURE_WHITELIST)


def load_jsonl(path: Path) -> list[Row]:
    """Loads and contract-checks an exported dataset. Order is preserved."""
    rows = [
        _row_from_record(json.loads(line), index)
        for index, line in enumerate(_nonempty_lines(path))
    ]
    _reject_duplicate_identities(rows)
    return rows


def _nonempty_lines(path: Path) -> Iterable[str]:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield line


def _row_from_record(record: dict[str, Any], index: int) -> Row:
    _require_constants(record, index)
    features = _checked_features(record.get("features"), index)
    anchor = _require_mapping(record, "anchorObservation", index)
    label = _require_mapping(record, "labelEvent", index)
    quality = _require_mapping(record, "quality", index)
    row = Row(
        example_id=record["exampleId"],
        identity_group=record["identityGroup"],
        repository_group=record["repositoryGroup"],
        feature_cutoff_seq=int(record["featureCutoffSeq"]),
        anchor_seq=int(anchor["seq"]),
        label_seq=int(label["seq"]),
        verdict=str(label["verdict"]),
        label=int(label["class"]),
        cutoff_quality=_checked_cutoff_quality(quality, index),
        features=features,
    )
    _check_ordering(row, index)
    _check_label(row, index)
    return row


def _require_constants(record: dict[str, Any], index: int) -> None:
    expected = {
        "schemaVersion": SCHEMA_VERSION,
        "taskId": TASK_ID,
        "featureSchemaId": FEATURE_SCHEMA_ID,
        "labelPolicyId": LABEL_POLICY_ID,
        "labelConflict": False,
    }
    for key, want in expected.items():
        if record.get(key) != want:
            raise DatasetError(
                f"row {index}: {key} is {record.get(key)!r}, expected {want!r}"
            )


def _require_mapping(record: dict[str, Any], key: str, index: int) -> dict[str, Any]:
    value = record.get(key)
    if not isinstance(value, dict):
        raise DatasetError(f"row {index}: {key} is missing or not an object")
    return value


def _checked_cutoff_quality(quality: dict[str, Any], index: int) -> str:
    value = quality.get("cutoffQuality")
    if value not in CUTOFF_QUALITY_CLASSIFICATIONS:
        raise DatasetError(f"row {index}: unknown cutoffQuality {value!r}")
    if value == "missing":
        raise DatasetError(
            f"row {index}: cutoffQuality 'missing' is never exported — a decision "
            "with no usable read cutoff is ineligible, not a training row"
        )
    if quality.get("identityQuality") != "durable":
        raise DatasetError(f"row {index}: identityQuality must be 'durable'")
    if quality.get("forbiddenFieldCheck") != "passed":
        raise DatasetError(f"row {index}: forbiddenFieldCheck must be 'passed'")
    return str(value)


def _checked_features(features: Any, index: int) -> dict[str, Any]:
    if not isinstance(features, dict):
        raise DatasetError(f"row {index}: features is missing or not an object")
    forbidden = sorted(set(features) & FORBIDDEN_KEYS)
    if forbidden:
        raise DatasetError(
            f"row {index}: forbidden feature key(s) {forbidden} — these carry the "
            "outcome or raw content and can never appear in a feature vector"
        )
    unknown = sorted(set(features) - set(FEATURE_WHITELIST))
    if unknown:
        raise DatasetError(f"row {index}: unknown feature key(s) {unknown}")
    missing = sorted(set(FEATURE_WHITELIST) - set(features))
    if missing:
        raise DatasetError(f"row {index}: absent feature key(s) {missing}")
    return {name: _checked_value(name, features[name], index) for name in FEATURE_WHITELIST}


def _checked_value(name: str, value: Any, index: int) -> Any:
    if value is None:
        if name in NULLABLE_FEATURES:
            return None
        raise DatasetError(f"row {index}: feature {name} may not be null")
    if name in BOOLEAN_FEATURES:
        return _checked_boolean(name, value, index)
    if name in CATEGORICAL_FEATURES:
        return _checked_category(name, value, index)
    if isinstance(value, bool) or not isinstance(value, int):
        raise DatasetError(f"row {index}: feature {name} must be an integer")
    return value


def _checked_boolean(name: str, value: Any, index: int) -> bool:
    if not isinstance(value, bool):
        raise DatasetError(f"row {index}: feature {name} must be a boolean")
    return value


def _checked_category(name: str, value: Any, index: int) -> str:
    if not isinstance(value, str) or not value:
        raise DatasetError(f"row {index}: feature {name} must be a non-empty string")
    vocabulary = CATEGORICAL_VOCABULARY.get(name)
    if vocabulary is not None and value not in vocabulary and not _is_cwe_token(name, value):
        raise DatasetError(
            f"row {index}: feature {name} value {value!r} is outside the frozen vocabulary"
        )
    return value


def _is_cwe_token(name: str, value: str) -> bool:
    return name == "ruleFamily" and value.startswith("cwe-") and value[4:].isdigit()


def _check_ordering(row: Row, index: int) -> None:
    if not row.anchor_seq <= row.feature_cutoff_seq < row.label_seq:
        raise DatasetError(
            f"row {index}: leakage guard failed — expected anchor <= cutoff < label, "
            f"got {row.anchor_seq} <= {row.feature_cutoff_seq} < {row.label_seq}"
        )


def _check_label(row: Row, index: int) -> None:
    expected = VERDICT_CLASS.get(row.verdict)
    if expected is None:
        raise DatasetError(f"row {index}: verdict {row.verdict!r} is not an eligible label")
    if row.label != expected:
        raise DatasetError(
            f"row {index}: verdict {row.verdict!r} implies class {expected}, got {row.label}"
        )


def _reject_duplicate_identities(rows: Sequence[Row]) -> None:
    seen: set[str] = set()
    for row in rows:
        if row.identity_group in seen:
            raise DatasetError(
                f"duplicate identityGroup {row.identity_group}: one durable identity "
                "contributes exactly one example (ADR-6)"
            )
        seen.add(row.identity_group)


def partition_complete_rows(rows: Sequence[Row]) -> tuple[list[Row], list[Row]]:
    """Splits rows into (complete, incomplete).

    Version one trains on complete rows only and reports the excluded count
    instead of imputing an absent value (design §10.6). Every internal node the
    trainer exports therefore records `missingDirection: "ineligible"`.
    """
    complete = [row for row in rows if row.is_complete()]
    incomplete = [row for row in rows if not row.is_complete()]
    return complete, incomplete


# --------------------------------------------------------------------------
# Synthetic corpus
# --------------------------------------------------------------------------

SYNTHETIC_SEED = 6601
SYNTHETIC_ROWS = 320
_REPOSITORY_COUNT = 6


def gen_synthetic_corpus(
    seed: int = SYNTHETIC_SEED, count: int = SYNTHETIC_ROWS
) -> list[dict[str, Any]]:
    """Seeded synthetic rows in the exported shape. No wall clock anywhere.

    The signal is planted, not learned from anything real: evidence linkage and
    static proof drive the positive class, test/vendor paths suppress it, and one
    tool family is deliberately given an uneven base rate so the information-gain
    audit has a tool-shortcut to find (design §13.4).
    """
    rng = random.Random(seed)
    return [_synthetic_row(rng, index) for index in range(count)]


def _synthetic_row(rng: random.Random, index: int) -> dict[str, Any]:
    features = _synthetic_features(rng, index)
    label = 1 if rng.random() < _positive_probability(features) else 0
    label_seq = 1000 + 3 * index
    verdict = rng.choice(["confirmed", "to_fix"]) if label == 1 else "rejected_false_positive"
    repository = index % _REPOSITORY_COUNT
    return {
        "schemaVersion": SCHEMA_VERSION,
        "taskId": TASK_ID,
        "exampleId": prefixed_digest("review-yield-example", [f"synthetic-{index}".encode()]),
        "identityGroup": prefixed_digest(
            "review-yield-identity-group", [f"synthetic-{index}".encode()]
        ),
        "repositoryGroup": prefixed_digest(
            "review-yield-repository-group", [f"synthetic-repo-{repository}".encode()]
        ),
        "featureSchemaId": FEATURE_SCHEMA_ID,
        "labelPolicyId": LABEL_POLICY_ID,
        "featureCutoffSeq": label_seq - 1,
        "anchorObservation": {
            "seq": label_seq - 2,
            "observationHash": _synthetic_hex(f"observation-{index}"),
            "snapshotHash": _synthetic_hex(f"snapshot-{index}"),
        },
        "labelEvent": {
            "seq": label_seq,
            "eventHash": _synthetic_hex(f"event-{index}"),
            "verdict": verdict,
            "class": label,
        },
        "features": features,
        "quality": {
            "cutoffQuality": EXPORTED_CUTOFF_QUALITY[index % 2],
            "identityQuality": "durable",
            "forbiddenFieldCheck": "passed",
        },
        "labelConflict": False,
    }


def _synthetic_hex(token: str) -> str:
    from .hashing import hash_parts

    return hash_parts("review-yield-synthetic", [token.encode()])


def _synthetic_features(rng: random.Random, index: int) -> dict[str, Any]:
    """Exercises every closed vocabulary value at least once by construction."""
    evidence_count = rng.choice([0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 8])
    has_evidence = evidence_count > 0
    source_sink = has_evidence and rng.random() < 0.45
    proof = _cycled(STATIC_PROOF_STATES, index, rng, 0.55)
    tool = _cycled(TOOL_FAMILIES, index, rng, 0.5)
    # ~7% of rows carry no evidence confidence at all, so the trainer's
    # incomplete-row exclusion path is exercised by the committed corpus.
    confidence_known = has_evidence and rng.random() > 0.07
    max_confidence = rng.randrange(40, 256) if confidence_known else None
    return {
        "severityRank": rng.choice([0, 1, 1, 2, 2, 2, 3, 3, 4, 5]),
        "staticProofState": proof,
        "vulnSource": _cycled(VULN_SOURCES, index, rng, 0.5),
        "toolFamily": tool,
        "ruleFamily": _cycled(RULE_FAMILIES, index, rng, 0.5),
        "pathBucket": _cycled(PATH_BUCKETS, index, rng, 0.55),
        "languageFamily": _cycled(LANGUAGE_FAMILIES, index, rng, 0.5),
        "identityMatchTier": _cycled(IDENTITY_MATCH_TIERS, index, rng, 0.5),
        "groundingStatus": _cycled(GROUNDING_STATUSES, index, rng, 0.5),
        "isAttackChain": tool == "chains",
        "evidenceCount": evidence_count,
        "distinctEvidenceKinds": min(evidence_count, rng.randrange(0, 5)),
        "maxEvidenceConfidence": max_confidence,
        "meanEvidenceConfidenceMillis": (
            None if max_confidence is None else max(0, max_confidence * 4 - rng.randrange(0, 300))
        ),
        "hasSourceEvidence": has_evidence and rng.random() < 0.6,
        "hasSinkEvidence": has_evidence and rng.random() < 0.6,
        "hasSanitizerEvidence": rng.random() < 0.25,
        "hasCallPathEvidence": rng.random() < 0.35,
        "sourceSinkLinked": source_sink,
        "sanitizerChecked": proof == "sanitizer_checked",
        "hasExploitScenario": rng.random() < 0.3,
        "preconditionCount": rng.randrange(0, 4),
        "sourceCount": rng.randrange(1, 4),
        "distinctToolCount": rng.randrange(1, 4),
        "corroborationCount": rng.randrange(0, 3),
        "observationCount": rng.randrange(1, 6),
        "runCount": rng.randrange(1, 5),
        "reopenedCount": rng.randrange(0, 2),
        "hasRemediation": rng.random() < 0.4,
    }


def _cycled(
    vocabulary: Sequence[str], index: int, rng: random.Random, random_share: float
) -> str:
    """Round-robins the vocabulary, then randomizes, so every value appears."""
    if index < len(vocabulary) or rng.random() >= random_share:
        return vocabulary[index % len(vocabulary)]
    return rng.choice(list(vocabulary))


def _positive_probability(features: dict[str, Any]) -> float:
    score = (
        1.8 * float(features["sourceSinkLinked"])
        + 0.9 * _proof_strength(features["staticProofState"])
        - 1.4 * float(features["pathBucket"] in ("test", "generated"))
        + 0.4 * (features["evidenceCount"] - 3)
        + 0.5 * float(features["hasExploitScenario"])
        + 0.6 * float(features["toolFamily"] == "codeql")
        - 0.35 * features["severityRank"]
        - 0.4
    )
    return 1.0 / (1.0 + math.exp(-score))


def _proof_strength(state: str) -> float:
    strength = {
        "statically_confirmed": 1.5,
        "sanitizer_checked": 0.8,
        "source_sink_linked": 1.0,
        "code_cited": 0.3,
        "needs_runtime_evidence": 0.0,
        "signal_only": -0.3,
        "missing": -0.5,
        "statically_rejected": -1.5,
    }
    return strength[state]


def synthetic_manifest(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """A schema-shaped manifest for a synthetic corpus, sealed like the exporter.

    The digest reproduces `export_dataset.rs`: canonical manifest bytes with
    `datasetDigest` removed, followed by each canonical row line including its
    trailing newline, under the `review-yield-dataset` domain.
    """
    manifest = _manifest_without_digest(records)
    row_lines = [canonical_json_bytes(record) + b"\n" for record in records]
    manifest_bytes = canonical_json_bytes(
        {key: value for key, value in manifest.items() if key != "datasetDigest"}
    )
    manifest["datasetDigest"] = prefixed_digest(
        "review-yield-dataset", [manifest_bytes, *row_lines]
    )
    return manifest


def _manifest_without_digest(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    positives = sum(1 for record in records if record["labelEvent"]["class"] == 1)
    latest = max((record["labelEvent"]["seq"] for record in records), default=None)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "taskId": TASK_ID,
        "exporterVersion": EXPORTER_VERSION,
        "featureSchemaId": FEATURE_SCHEMA_ID,
        "labelPolicyId": LABEL_POLICY_ID,
        "labelPolicy": _label_policy_manifest(),
        "featureFields": list(FEATURE_WHITELIST),
        "ruleFamilyPattern": "^(cwe-[0-9]+|[a-z_]+)$",
        "categoricalVocabulary": {
            name: list(values) for name, values in CATEGORICAL_VOCABULARY.items()
        },
        "source": {
            "eventLogHeadSeq": (latest or 0) + 1,
            "projectionAppliedSeq": (latest or 0) + 1,
            "projectionGeneration": 1,
        },
        "census": _synthetic_census(records, positives, latest),
        "rowCount": len(records),
        "datasetDigest": "",
    }


def _label_policy_manifest() -> dict[str, Any]:
    return {
        "id": LABEL_POLICY_ID,
        "positive": ["confirmed", "to_fix"],
        "negative": ["rejected_false_positive"],
        "excluded": ["accepted_risk", "suppressed", "deferred", "needs_review"],
        "includedAuthors": ["human"],
        "excludedAuthors": ["auto", "imported", "other"],
        "identityRule": "one example per durable finding identity",
        "conflictRule": "identities with conflicting human verdicts are excluded",
        "cutoffRule": "features are read at the decision's read cutoff, never after",
        "exportedCutoffQuality": ["tui_read_watermark", "barrier_at_head"],
    }


def _synthetic_census(
    records: Sequence[dict[str, Any]], positives: int, latest: int | None
) -> dict[str, Any]:
    quality_counts: dict[str, int] = {}
    for record in records:
        key = record["quality"]["cutoffQuality"]
        quality_counts[key] = quality_counts.get(key, 0) + 1
    return {
        "taskId": TASK_ID,
        "featureSchemaId": FEATURE_SCHEMA_ID,
        "labelPolicyId": LABEL_POLICY_ID,
        "decisionEvents": len(records),
        "humanDecisionEvents": len(records),
        "byAuthor": {"human": len(records)},
        "byVerdict": _count_by(records, lambda record: record["labelEvent"]["verdict"]),
        "byDismissReason": {},
        "cutoffQuality": quality_counts,
        "adjudicatedIdentities": len(records),
        "eligibleIdentities": len(records),
        "positive": positives,
        "negative": len(records) - positives,
        "conflicted": 0,
        "policyTransitions": 0,
        "noEligibleLabel": 0,
        "missingExactCutoff": 0,
        "missingDurableIdentity": 0,
        "missingPreCutoffObservation": 0,
        "distinctRepositories": _REPOSITORY_COUNT,
        "distinctToolFamilies": _distinct(records, "toolFamily"),
        "distinctRuleFamilies": _distinct(records, "ruleFamily"),
        "distinctLanguageFamilies": _distinct(records, "languageFamily"),
        "earliestLabelEventSeq": min(
            (record["labelEvent"]["seq"] for record in records), default=None
        ),
        "latestLabelEventSeq": latest,
        "eventLogHeadSeq": (latest or 0) + 1,
        "projectionAppliedSeq": (latest or 0) + 1,
        "projectionGeneration": 1,
    }


def _count_by(records: Sequence[dict[str, Any]], key: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[key(record)] = counts.get(key(record), 0) + 1
    return dict(sorted(counts.items()))


def _distinct(records: Sequence[dict[str, Any]], feature: str) -> int:
    return len({record["features"][feature] for record in records})


def write_synthetic_corpus(directory: Path) -> tuple[Path, Path]:
    """Regenerates the committed synthetic fixture and its manifest."""
    records = gen_synthetic_corpus()
    corpus_path = directory / "synthetic-kuzushi-corpus.jsonl"
    manifest_path = directory / "synthetic-kuzushi-corpus.jsonl.manifest.json"
    corpus_path.write_bytes(b"".join(canonical_json_bytes(r) + b"\n" for r in records))
    manifest_path.write_bytes(canonical_json_bytes(synthetic_manifest(records)))
    return corpus_path, manifest_path


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="review-yield dataset utilities")
    parser.add_argument(
        "--emit-synthetic",
        type=Path,
        metavar="DIR",
        help="regenerate the synthetic corpus fixture into DIR",
    )
    args = parser.parse_args(argv)
    if args.emit_synthetic is None:
        parser.error("nothing to do: pass --emit-synthetic DIR")
    corpus, manifest = write_synthetic_corpus(args.emit_synthetic)
    print(f"wrote {corpus}")
    print(f"wrote {manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
