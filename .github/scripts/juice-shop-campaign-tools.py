#!/usr/bin/env python3
"""Deterministic helpers for the isolated Juice Shop 20-scan campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except Exception:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def command_threat_model(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.path)
    document = json.loads(path.read_text(encoding="utf-8"))
    threats = document.get("threats")
    if not isinstance(threats, list) or len(threats) != 5:
        raise ValueError("threat model must contain exactly five threats")
    ids = {str(row.get("id")) for row in threats if isinstance(row, dict)}
    if len(ids) != 5:
        raise ValueError("threat ids must be unique")
    if args.expected_scans != 4 * len(threats):
        raise ValueError("four shards times threat count must equal expected scans")
    for row in threats:
        if not isinstance(row, dict) or not row.get("title") or not row.get("description"):
            raise ValueError("every threat requires a title and description")
        if not row.get("relatedCwe"):
            raise ValueError("every threat requires related CWEs")
    print(json.dumps({"threats": len(threats), "expectedScans": args.expected_scans}, sort_keys=True))
    return 0


def http_request(opener: urllib.request.OpenerDirector, method: str, url: str, body: Any = None) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("content-type", "application/json")
    started = time.monotonic()
    try:
        with opener.open(request, timeout=8) as response:
            raw = response.read(1_000_000)
            status = response.status
            location = response.headers.get("location")
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read(1_000_000)
        location = error.headers.get("location")
    except Exception as error:
        return {
            "status": None,
            "error": type(error).__name__,
            "durationMs": int((time.monotonic() - started) * 1000),
        }
    parsed = None
    try:
        parsed = json.loads(raw)
    except Exception:
        pass
    return {
        "status": status,
        "durationMs": int((time.monotonic() - started) * 1000),
        "bytes": len(raw),
        "bodySha256": hashlib.sha256(raw).hexdigest(),
        "authenticated": bool(isinstance(parsed, dict) and parsed.get("authentication")),
        "location": location,
    }


def command_http_fuzz(args: argparse.Namespace) -> int:
    opener = urllib.request.build_opener(NoRedirect)
    base = args.base.rstrip("/")
    wrong_password = "definitely-not-the-password"
    login_bodies = [
        {"email": "admin@juice-sh.op'-- ", "password": wrong_password},
        {"email": "' OR 1=1-- ", "password": wrong_password},
        {"email": '\" OR \"1\"=\"1', "password": wrong_password},
        {"email": "admin@juice-sh.op\\u0000'-- ", "password": wrong_password},
        {"email": "💥@juice-sh.op", "password": wrong_password},
        {"email": "A" * 4096, "password": wrong_password},
        {"email": None, "password": wrong_password},
        {"email": [], "password": wrong_password},
        {"email": {}, "password": wrong_password},
        {"email": "admin@juice-sh.op", "password": None},
        {"email": "admin@juice-sh.op", "password": []},
        {"email": "admin@juice-sh.op", "password": {}},
    ]
    query_cases = [
        (
            "product-search",
            "/rest/products/search?q=",
            ["'", '\"', "%' OR 1=1--", "../" * 20, "${7*7}", "<script>alert(1)</script>", "A" * 4096],
        ),
        (
            "redirect",
            "/redirect?to=",
            ["http://127.0.0.1", "//example.invalid", "javascript:alert(1)", "%2f%2fexample.invalid"],
        ),
    ]
    rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for body in login_bodies:
        encoded = json.dumps(body, sort_keys=True, default=str)
        result = http_request(opener, "POST", f"{base}/rest/user/login", body)
        rows.append({"surface": "login", "payloadSha256": hashlib.sha256(encoded.encode()).hexdigest(), **result})
        if result.get("authenticated") or (result.get("status") or 0) >= 500 or result.get("status") is None:
            findings.append({
                "file": "runtime/rest-user-login",
                "line": 1,
                "title": "HTTP mutation anomaly on POST /rest/user/login",
                "severity": "critical" if result.get("authenticated") else "medium",
                "class": "dynamic-http-fuzz",
                "cwe": "CWE-89" if result.get("authenticated") else "CWE-20",
            })
    for surface, prefix, payloads in query_cases:
        for payload in payloads:
            result = http_request(opener, "GET", f"{base}{prefix}{urllib.parse.quote(payload)}")
            rows.append({"surface": surface, "payloadSha256": hashlib.sha256(payload.encode()).hexdigest(), **result})
            if (result.get("status") or 0) >= 500 or result.get("status") is None:
                findings.append({
                    "file": f"runtime/{surface}",
                    "line": 1,
                    "title": f"HTTP mutation anomaly on {surface}",
                    "severity": "medium",
                    "class": "dynamic-http-fuzz",
                    "cwe": "CWE-20",
                })
    results = pathlib.Path(args.results)
    findings_path = pathlib.Path(args.findings)
    results.parent.mkdir(parents=True, exist_ok=True)
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    results.write_text(json.dumps({"cases": rows, "anomalyCount": len(findings)}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    seen: set[tuple[tuple[str, Any], ...]] = set()
    with findings_path.open("w", encoding="utf-8") as handle:
        for finding in findings:
            key = tuple(sorted(finding.items()))
            if key not in seen:
                seen.add(key)
                handle.write(json.dumps(finding, sort_keys=True) + "\n")
    return 0


def command_normalize_zap(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    out = pathlib.Path(args.out)
    risk_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
    rows: list[dict[str, Any]] = []
    for report in (root / "api-report.json", root / "full-report.json"):
        if not report.exists():
            continue
        try:
            document = json.loads(report.read_text(encoding="utf-8"))
        except Exception:
            continue
        for site in document.get("site", []):
            for alert in site.get("alerts", []):
                for instance in (alert.get("instances") or [{}])[:25]:
                    uri = str(instance.get("uri") or site.get("@name") or "runtime")
                    cwe = str(alert.get("cweid") or "").strip()
                    row = {
                        "file": "runtime/" + uri.replace("://", "/").lstrip("/")[:300],
                        "line": 1,
                        "title": f"ZAP: {alert.get('alert') or alert.get('name') or 'HTTP security alert'}",
                        "severity": risk_map.get(str(alert.get("riskdesc", "")).split(" ")[0], "info"),
                        "class": "dynamic-zap",
                    }
                    if cwe and cwe != "-1":
                        row["cwe"] = f"CWE-{cwe}"
                    rows.append(row)
    out.parent.mkdir(parents=True, exist_ok=True)
    seen: set[tuple[Any, ...]] = set()
    with out.open("w", encoding="utf-8") as handle:
        for row in rows:
            key = (row["file"], row["title"], row.get("cwe"))
            if key not in seen:
                seen.add(key)
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    return 0


def command_prepare_plan(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.plan)
    target = pathlib.Path(args.target)
    plan = json.loads(path.read_text(encoding="utf-8"))
    jobs = plan.get("jobs", [])
    if plan.get("jobCount") != args.expected or len(jobs) != args.expected:
        raise ValueError(f"expected {args.expected} jobs, got {len(jobs)}")
    if plan.get("threatCount") != 5:
        raise ValueError(f"expected five threat lenses, got {plan.get('threatCount')}")
    if len(plan.get("axes", {}).get("shards", [])) != 4:
        raise ValueError("expected four source shards")
    keys = {(row.get("shard"), row.get("threatId"), row.get("model")) for row in jobs}
    if len(keys) != args.expected:
        raise ValueError("matrix contains duplicate scan cells")
    for sequence, job in enumerate(jobs, start=1):
        input_data = job.setdefault("input", {})
        input_data.update({
            "strategy": "chunked",
            "language": "unknown",
            "maxTokensPerChunk": 9000,
            "depositUsdPerChunk": 0.75,
            "budgetUsd": args.tool_budget,
            "autoTriage": False,
            "maxFindings": 24,
            "passes": 1,
        })
        job["jobBudgetUsd"] = args.job_budget
        job["independentScanOrdinal"] = sequence
        prompt_rel = job.get("promptPath")
        if prompt_rel:
            prompt_path = target / prompt_rel
            with prompt_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    "\n\n## Independent scan contract\n\n"
                    f"Independent scan ordinal: {sequence:02d} of {args.expected}. "
                    f"Cell: {job.get('shard')} × {job.get('threatId')}. "
                    f"Campaign nonce: {plan.get('campaignId')}-{sequence:02d}.\n\n"
                    "Generate hypotheses independently from other campaign cells. Do not assume another pass will inspect this path. "
                    "Vary candidate ordering and actively search for counterexamples before returning. "
                    "A finding requires a concrete attacker-controlled source, reachable sink or invariant violation, exact code evidence, preconditions, impact, and a stated falsification test. "
                    "Unsupported runtime claims must be labeled as hypotheses rather than facts.\n"
                )
    path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def command_select_verification(args: argparse.Namespace) -> int:
    source = pathlib.Path(args.source)
    out = pathlib.Path(args.out)
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": -1}
    verdict_rank = {"true_positive": 3, "needs_review": 2, "by_design": 1, "false_positive": 0}
    ranked: list[tuple[Any, ...]] = []
    for finding in jsonl(source):
        if finding.get("suppressed"):
            continue
        fingerprint = str(finding.get("fingerprint") or "").strip()
        if not fingerprint:
            continue
        severity = str(finding.get("severity") or "unknown").lower()
        triage = finding.get("triage") or {}
        verdict = str(triage.get("verdict") or "needs_review").lower()
        confidence = float(triage.get("confidence") or 0.0)
        corroboration = int(finding.get("corroboration_count") or finding.get("corroborationCount") or 0)
        eligible = (
            verdict == "true_positive" and severity_rank.get(severity, -1) >= 2
        ) or (
            verdict == "needs_review" and severity_rank.get(severity, -1) >= 3 and confidence >= 0.55
        )
        if eligible:
            ranked.append((
                severity_rank.get(severity, -1),
                verdict_rank.get(verdict, 0),
                confidence,
                corroboration,
                fingerprint,
                severity,
                verdict,
                str(finding.get("title") or "").replace("\t", " ").replace("\n", " ")[:240],
            ))
    ranked.sort(reverse=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for ordinal, row in enumerate(ranked[: args.limit], start=1):
            _, _, confidence, corroboration, fingerprint, severity, verdict, title = row
            handle.write(f"{ordinal}\t{fingerprint}\t{severity}\t{verdict}\t{confidence:.3f}\t{corroboration}\t{title}\n")
    return 0


def command_summary(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.report_root)
    findings = jsonl(pathlib.Path(args.findings))
    plan_path = pathlib.Path(args.plan)
    queue_path = pathlib.Path(args.queue)
    candidates_path = pathlib.Path(args.candidates)
    plan = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.exists() else {}
    queue = json.loads(queue_path.read_text(encoding="utf-8")) if queue_path.exists() else {}
    queue_jobs = queue.get("jobs", queue if isinstance(queue, list) else [])
    if not isinstance(queue_jobs, list):
        queue_jobs = []
    lanes = jsonl(root / "lane-status.jsonl")
    triage: dict[str, int] = {}
    verification: dict[str, int] = {}
    severities: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        severities[severity] = severities.get(severity, 0) + 1
        verdict = str((finding.get("triage") or {}).get("verdict") or "untriaged").lower()
        triage[verdict] = triage.get(verdict, 0) + 1
        proof = finding.get("verification") or {}
        proof_verdict = str(proof.get("proofVerdict") or proof.get("proof_verdict") or "unverified").lower()
        verification[proof_verdict] = verification.get(proof_verdict, 0) + 1
    states: dict[str, int] = {}
    for job in queue_jobs:
        state = str(job.get("state") or job.get("status") or "unknown")
        states[state] = states.get(state, 0) + 1
    candidate_count = 0
    if candidates_path.exists():
        candidate_count = sum(1 for line in candidates_path.read_text(encoding="utf-8").splitlines() if line.strip())
    summary = {
        "campaignId": plan.get("campaignId"),
        "plannedModelScans": plan.get("jobCount", 0),
        "threatLenses": plan.get("threatCount", 0),
        "sourceShards": len(plan.get("axes", {}).get("shards", [])),
        "scanStates": states,
        "findingCount": len(findings),
        "findingSeverities": severities,
        "triageVerdicts": triage,
        "verificationVerdicts": verification,
        "verificationCandidateCount": candidate_count,
        "laneCounts": {
            status: sum(1 for lane in lanes if lane.get("status") == status)
            for status in ("completed", "partial", "failed", "skipped")
        },
        "proofPolicy": {
            "modelFindingsAreHypotheses": True,
            "triageDoesNotEqualProof": True,
            "empiricalReceiptsAuthoritativeWhenAvailable": True,
            "autoPatch": False,
        },
        "findingStateCaveat": "Counts include scanner candidates, independently generated model hypotheses, imported runtime observations, triage outcomes, and verification records as separate fields; the total is not a confirmed-vulnerability count.",
        "lanes": lanes,
    }
    (root / "campaign-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    threat = commands.add_parser("threat-model")
    threat.add_argument("--path", required=True)
    threat.add_argument("--expected-scans", type=int, required=True)
    threat.set_defaults(func=command_threat_model)

    fuzz = commands.add_parser("http-fuzz")
    fuzz.add_argument("--base", required=True)
    fuzz.add_argument("--results", required=True)
    fuzz.add_argument("--findings", required=True)
    fuzz.set_defaults(func=command_http_fuzz)

    zap = commands.add_parser("normalize-zap")
    zap.add_argument("--root", required=True)
    zap.add_argument("--out", required=True)
    zap.set_defaults(func=command_normalize_zap)

    plan = commands.add_parser("prepare-plan")
    plan.add_argument("--plan", required=True)
    plan.add_argument("--target", required=True)
    plan.add_argument("--expected", type=int, required=True)
    plan.add_argument("--tool-budget", type=float, required=True)
    plan.add_argument("--job-budget", type=float, required=True)
    plan.set_defaults(func=command_prepare_plan)

    select = commands.add_parser("select-verification")
    select.add_argument("--source", required=True)
    select.add_argument("--out", required=True)
    select.add_argument("--limit", type=int, required=True)
    select.set_defaults(func=command_select_verification)

    summary = commands.add_parser("summary")
    summary.add_argument("--report-root", required=True)
    summary.add_argument("--findings", required=True)
    summary.add_argument("--plan", required=True)
    summary.add_argument("--queue", required=True)
    summary.add_argument("--candidates", required=True)
    summary.set_defaults(func=command_summary)
    return root


def main() -> int:
    args = parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
