#!/usr/bin/env python3
"""Select unique Kuzushi findings for independent and empirical verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
REJECT_TOKENS = {
    "false_positive",
    "false-positive",
    "false positive",
    "rejected",
    "duplicate",
    "not_exploitable",
    "not-exploitable",
    "not exploitable",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--model-queue", type=Path, required=True)
    parser.add_argument("--empirical-queue", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--max-model", type=int, default=80)
    parser.add_argument("--max-empirical", type=int, default=40)
    return parser.parse_args()


def nested_values(value: Any, keys: set[str]) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in keys:
                yield item
            yield from nested_values(item, keys)
    elif isinstance(value, list):
        for item in value:
            yield from nested_values(item, keys)


def first_string(value: Any, keys: set[str]) -> str | None:
    for item in nested_values(value, keys):
        if isinstance(item, str) and item.strip():
            return item.strip()
    return None


def fingerprint(row: dict[str, Any]) -> str | None:
    for key in ("fingerprint", "findingFingerprint", "finding_fingerprint"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return first_string(row, {"fingerprint", "findingfingerprint", "finding_fingerprint"})


def severity(row: dict[str, Any]) -> str:
    raw = first_string(row, {"severity"}) or "unknown"
    normalized = raw.strip().lower()
    return normalized if normalized in SEVERITY_RANK else "unknown"


def compact_verdict_text(row: dict[str, Any]) -> str:
    values: list[str] = []
    for item in nested_values(
        row,
        {
            "verdict",
            "classification",
            "status",
            "triage",
            "decision",
            "outcome",
            "exploitable",
            "proofverdict",
            "proof_verdict",
        },
    ):
        if isinstance(item, (str, bool, int, float)):
            values.append(str(item))
        elif isinstance(item, dict):
            values.append(json.dumps(item, sort_keys=True))
    return " ".join(values).lower()


def rejected(row: dict[str, Any]) -> bool:
    text = compact_verdict_text(row)
    return any(token in text for token in REJECT_TOKENS)


def read_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"malformed JSONL at {path}:{line_number}: {error}") from error
        if isinstance(value, dict):
            rows.append(value)
    return rows


def canonical_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_fingerprint: dict[str, dict[str, Any]] = {}
    for row in rows:
        fp = fingerprint(row)
        if not fp:
            continue
        candidate = {
            "fingerprint": fp,
            "severity": severity(row),
            "rejectedByTriage": rejected(row),
            "title": first_string(row, {"title", "name", "summary"}) or "",
            "file": first_string(row, {"file", "filepath", "file_path", "path"}) or "",
            "verdictEvidence": compact_verdict_text(row)[:2000],
        }
        prior = by_fingerprint.get(fp)
        if prior is None or SEVERITY_RANK[candidate["severity"]] > SEVERITY_RANK[prior["severity"]]:
            by_fingerprint[fp] = candidate
        elif prior["rejectedByTriage"] and not candidate["rejectedByTriage"]:
            by_fingerprint[fp] = candidate
    return sorted(
        by_fingerprint.values(),
        key=lambda row: (-SEVERITY_RANK[row["severity"]], row["fingerprint"]),
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def main() -> int:
    args = parse_args()
    all_rows = canonical_rows(read_rows(args.findings))
    live = [row for row in all_rows if not row["rejectedByTriage"]]
    model_queue = live[: max(0, args.max_model)]
    empirical_queue = [
        row for row in live if row["severity"] in {"critical", "high", "medium"}
    ][: max(0, args.max_empirical)]

    write_jsonl(args.model_queue, model_queue)
    write_jsonl(args.empirical_queue, empirical_queue)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "inputRows": len(read_rows(args.findings)),
                "uniqueFindings": len(all_rows),
                "triageRejectedOrDuplicate": sum(1 for row in all_rows if row["rejectedByTriage"]),
                "modelVerificationQueued": len(model_queue),
                "empiricalVerificationQueued": len(empirical_queue),
                "modelQueueCap": args.max_model,
                "empiricalQueueCap": args.max_empirical,
                "selectionPolicy": {
                    "model": "every unique non-rejected finding, severity-ranked",
                    "empirical": "every critical/high/medium non-rejected finding, severity-ranked",
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "ok": True,
                "unique": len(all_rows),
                "model": len(model_queue),
                "empirical": len(empirical_queue),
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001
        print(f"select-juice-shop-verification: {error}", file=sys.stderr)
        raise
