#!/usr/bin/env python3
"""Convert a Kuzushi campaign plan into exactly 20 independent scan jobs.

The campaign planner provides the trusted shard x threat cross-product and
seasoned prompt files. This script adds per-job randomized context ordering and
an explicit analyst nonce without inventing unsupported tool options.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path
from typing import Any

EXPECTED_JOBS = 20
EXPECTED_SHARDS = 4
EXPECTED_THREATS = 5


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--model", required=True)
    return parser.parse_args()


def resolve_under(root: Path, value: str, label: str) -> Path:
    candidate = Path(value)
    resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    root_resolved = root.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as error:
        raise ValueError(f"{label} escapes target root: {value}") from error
    return resolved


def read_nonempty_lines(path: Path) -> list[str]:
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"scope file is empty: {path}")
    return lines


def append_independence_contract(prompt_path: Path, *, index: int, job: dict[str, Any], nonce: str) -> str:
    block = f"""

## Independent analyst run {index:02d}/{EXPECTED_JOBS}

- Hypothesis nonce: `{nonce}`
- Shard: `{job.get('shard', '')}`
- Threat lens: `{job.get('threatId', '')}` — {job.get('threatTitle', '')}

This is an independent non-deterministic review, not a continuation of another
job. Do not assume a sibling analyst found or rejected anything. Explore at
least three materially different attacker-to-impact paths before concluding the
shard is quiet. Vary the order in which you inspect entry points and sinks.
Attempt to falsify your strongest candidate before reporting it. Preserve
uncertainty and cite exact source evidence. The nonce exists only to prevent
semantic-cache collapse and correlated reasoning; it is not security evidence.
"""
    with prompt_path.open("a", encoding="utf-8") as handle:
        handle.write(block)
    return hashlib.sha256(prompt_path.read_bytes()).hexdigest()


def prepare_job(
    *,
    root: Path,
    plan: dict[str, Any],
    job: dict[str, Any],
    index: int,
    model: str,
) -> dict[str, Any]:
    input_data = job.setdefault("input", {})
    if not isinstance(input_data, dict):
        raise ValueError(f"job {index} input is not an object")

    prompt_value = job.get("promptPath") or input_data.get("AGENTIC_SAST_PROMPT")
    if not isinstance(prompt_value, str) or not prompt_value.strip():
        raise ValueError(f"job {index} has no seasoned prompt path")
    prompt_path = resolve_under(root, prompt_value, f"job {index} prompt")
    if not prompt_path.is_file():
        raise ValueError(f"job {index} prompt does not exist: {prompt_path}")

    scope_value = input_data.get("scopeFile")
    if not isinstance(scope_value, str) or not scope_value.strip():
        raise ValueError(f"job {index} has no scopeFile; agentic scan must be shard-bounded")
    source_scope = resolve_under(root, scope_value, f"job {index} scope")
    lines = read_nonempty_lines(source_scope)
    secrets.SystemRandom().shuffle(lines)

    campaign_id = str(plan.get("campaignId") or "campaign")
    job_id = str(job.get("jobId") or f"job-{index:03d}")
    scope_rel = Path(".kuzushi") / "v3" / "campaigns" / campaign_id / "scope" / f"{job_id}.txt"
    scope_path = resolve_under(root, str(scope_rel), f"job {index} private scope")
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    scope_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    nonce = secrets.token_urlsafe(24)
    prompt_sha256 = append_independence_contract(
        prompt_path,
        index=index,
        job=job,
        nonce=nonce,
    )

    input_data.update(
        {
            "model": model,
            "strategy": "chunked",
            "language": "unknown",
            "scopeFile": str(scope_rel),
            "maxTokensPerChunk": 9000,
            "depositUsdPerChunk": 1.25,
            "budgetUsd": 3.25,
            "autoTriage": False,
            "maxFindings": 35,
            "passes": 1,
            "focus": (
                f"Independent lens {job.get('threatId', '')} over shard "
                f"{job.get('shard', '')}: {job.get('threatTitle', '')}. "
                "Prioritize complete attacker-to-impact paths and attempt to falsify each candidate."
            ),
            "AGENTIC_SAST_PROMPT": str(prompt_path.relative_to(root.resolve())),
        }
    )
    job["jobBudgetUsd"] = 4.0
    job["independence"] = {
        "ordinal": index,
        "nonce": nonce,
        "scopeOrderSha256": hashlib.sha256(scope_path.read_bytes()).hexdigest(),
        "promptSha256": prompt_sha256,
        "cacheIsolation": "unique prompt nonce and per-job scope ordering",
    }
    return {
        "jobId": job_id,
        "ordinal": index,
        "shard": job.get("shard"),
        "threatId": job.get("threatId"),
        "threatTitle": job.get("threatTitle"),
        "model": model,
        "nonce": nonce,
        "scopeFile": str(scope_rel),
        "scopeFiles": len(lines),
        "scopeOrderSha256": job["independence"]["scopeOrderSha256"],
        "promptPath": input_data["AGENTIC_SAST_PROMPT"],
        "promptSha256": prompt_sha256,
    }


def validate_axes(plan: dict[str, Any], jobs: list[dict[str, Any]]) -> None:
    if len(jobs) != EXPECTED_JOBS:
        raise ValueError(f"expected exactly {EXPECTED_JOBS} jobs, got {len(jobs)}")
    if int(plan.get("droppedJobs") or 0) != 0:
        raise ValueError(f"campaign planner dropped jobs: {plan.get('droppedJobs')}")

    shards = {str(job.get("shard")) for job in jobs}
    threats = {str(job.get("threatId")) for job in jobs}
    cells = {(str(job.get("shard")), str(job.get("threatId"))) for job in jobs}
    if len(shards) != EXPECTED_SHARDS:
        raise ValueError(f"expected {EXPECTED_SHARDS} shards, got {sorted(shards)}")
    if len(threats) != EXPECTED_THREATS:
        raise ValueError(f"expected {EXPECTED_THREATS} threats, got {sorted(threats)}")
    if len(cells) != EXPECTED_JOBS:
        raise ValueError(f"expected {EXPECTED_JOBS} unique shard/threat cells, got {len(cells)}")


def main() -> int:
    args = parse_args()
    root = args.target_root.resolve()
    plan_path = args.plan.resolve()
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    jobs = plan.get("jobs")
    if not isinstance(jobs, list):
        raise ValueError("campaign plan has no jobs array")
    validate_axes(plan, jobs)

    manifest_jobs = [
        prepare_job(root=root, plan=plan, job=job, index=index, model=args.model)
        for index, job in enumerate(jobs, start=1)
    ]
    validate_axes(plan, jobs)

    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "campaignId": plan.get("campaignId"),
                "jobCount": len(manifest_jobs),
                "independenceMethod": [
                    "one unique shard/threat cell per job",
                    "cryptographically random prompt nonce",
                    "independently shuffled per-job scope ordering",
                    "one agentic pass per job with no inherited verdicts",
                    "dedicated cross-run triage occurs only after all scans",
                ],
                "jobs": manifest_jobs,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"ok": True, "jobs": len(manifest_jobs), "manifest": str(args.manifest)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 - CLI should emit one useful fatal line
        print(f"prepare-juice-shop-20x-plan: {error}", file=sys.stderr)
        raise
