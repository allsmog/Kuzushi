"""Verify five real export consumers without changing observations or decisions."""
import csv
import hashlib
import json
from urllib.parse import unquote

from dfd_literal_links import PATHS, facts
from rejected_context import execute


def read_json(path):
    return json.loads(path.read_text())


def assert_record(row):
    evidence = row["evidence"]
    assert evidence["observedCount"] == evidence["observedCodeCount"] == 1
    assert evidence["reasoningAssertionCount"] == 1
    assert evidence["modelGeneratedReasoningCount"] == 0
    assert evidence["modelGeneratedReasoningPresent"] is False
    assert row["analysis"]["automatedReasoningPresent"] is False
    assert row["reviewDecision"] == "needs_review"
    assert row["proofConfidence"] == "unverified"


def verify_json_formats(report):
    records = read_json(report / "origins.json")["findings"]
    assert len(records) == 2
    assert {row["location"]["file"] for row in records} == set(PATHS)
    for row in records:
        assert_record(row)
    lines = [json.loads(line) for line in (report / "origins.jsonl").read_text().splitlines()]
    assert lines[0]["recordType"] == "metadata"
    assert len(lines[1:]) == 2
    for row in lines[1:]:
        assert_record(row)


def verify_csv(report):
    with (report / "origins.csv").open(newline="") as stream:
        reader = csv.DictReader(stream)
        assert reader.fieldnames[-1] == "reasoning_assertion_count"
        records = list(reader)
    assert len(records) == 2 and {row["file"] for row in records} == set(PATHS)
    for row in records:
        assert row["reasoning_assertion_count"] == "1"
        assert row["observed_code_evidence_count"] == "1"
        assert row["model_generated_reasoning_count"] == "0"
        assert row["automated_reasoning_present"] == "false"
        assert row["proof_confidence"] == "unverified"


def verify_sarif(report):
    results = [result for run in read_json(report / "origins.sarif")["runs"] for result in run["results"]]
    assert len(results) == 2
    paths = {unquote(row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]) for row in results}
    assert paths == set(PATHS)
    for row in results:
        fields = row["properties"]
        assert fields["kuzushiReasoningAssertionCount"] == 1
        assert fields["kuzushiObservedCodeEvidenceCount"] == 1
        assert fields["kuzushiModelGeneratedReasoningCount"] == 0
        assert fields["kuzushiAutomatedReasoningPresent"] is False


def verify_bundle(report):
    bundle = report / "origins-bundle"
    records = read_json(bundle / "manifest.json")["findings"]
    assert len(records) == 2 and {row["file"] for row in records} == set(PATHS)
    for row in records:
        assert row["reasoningAssertionCount"] == row["observedCodeEvidenceCount"] == 1
        assert row["modelGeneratedReasoningCount"] == 0
        assert row["automatedReasoningPresent"] is False
        text = (bundle / row["path"]).read_text()
        assert "reasoning assertion" in text and "observed code evidence" in text
        assert "model-generated reasoning" not in text


def verify_original_state(root, evidence):
    before = read_json(evidence / "before.json")
    current = facts(root)
    for key in ["counts", "sources", "context"]:
        assert current[key] == before[key], key
    for name, digest in before["results"].items():
        assert current["results"][name] == digest
    assert not (root / ".kuzushi/v3/campaigns").exists()
    assert not (evidence / "denied-fetch.jsonl").exists()
    return {name: digest for name, digest in current["results"].items() if name not in before["results"]}


def verify_exports(root, evidence):
    receipt = read_json(evidence / "export-receipts.json")
    assert verify_original_state(root, evidence) == receipt["results"]
    assert len(receipt["results"]) == 5
    for name in receipt["results"]:
        record = read_json((root / name).parent / "run.json")
        assert record["tool"] == "workspace:export-findings" and record["status"] == "completed"
        assert not record.get("llmCalls")
    report = root / ".kuzushi/reports"
    verify_json_formats(report)
    verify_csv(report)
    verify_sarif(report)
    verify_bundle(report)
    for name, digest in receipt["files"].items():
        assert hashlib.sha256((report / name).read_bytes()).hexdigest() == digest


def export(root, evidence, home):
    report = root / ".kuzushi/reports"
    destinations = {"json": "origins.json", "jsonl": "origins.jsonl", "csv": "origins.csv",
                    "sarif": "origins.sarif", "markdown-bundle": "origins-bundle"}
    for format_name, filename in destinations.items():
        execute(root, home, evidence, "export-" + format_name, "workspace:export-findings",
                {"format": format_name, "output": str(report / filename)})
    receipt = {"results": verify_original_state(root, evidence),
               "files": {str(path.relative_to(report)): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in report.rglob("*") if path.is_file()}}
    (evidence / "export-receipts.json").write_text(json.dumps(receipt, indent=2) + "\n")
    verify_exports(root, evidence)
