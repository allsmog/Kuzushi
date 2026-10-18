"""Owned synthetic lessons exported through the native Report surface, without inference."""
import hashlib
import csv
import json
import os
import sqlite3
import sys
from pathlib import Path
from reviewed_lessons import prepare
from rejected_context import execute


def seed(root, evidence):
    prepare(root, evidence)
    finding = json.loads((root / ".kuzushi/lesson-fixture.json").read_text())["findingId"]
    for state in ["draft", "accepted", "rejected", "retired"]:
        data = execute(root, Path(os.environ["HOME"]), evidence, state + "-draft", "findings:lesson-save", {
            "findingId": finding, "content": {"title": "Labeled " + state + " lesson",
                "text": "Inspect the recorded greeting. Unicode café and ``` remain inert.",
                "applicability": "Owned synthetic greeting review",
                "limitations": "Historical guidance only. No defect or current-source verdict is claimed."}})
        if state != "draft":
            execute(root, Path(os.environ["HOME"]), evidence, state + "-review", "findings:lesson-review", {
                "lessonRef": data["lessonRef"], "state": state, "note": "Synthetic report test; preserve historical limits."})
    rows = execute(root, Path(os.environ["HOME"]), evidence, "before-lessons", "findings:lessons", {})["rows"]
    (evidence / "expected-lessons.json").write_text(json.dumps(rows))
    (evidence / "ledger-before.json").write_text(json.dumps(ledger_counts(root)))


def ledger_counts(root):
    # WAL readers may need sidecars. query_only prohibits SQL writes.
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        return {table: db.execute("select count(*) from " + table).fetchone()[0]
            if table in tables else None
            for table in ["finding_observations", "review_decisions", "rekey_edges", "investigation_call_reservations"]}


def verify(root, evidence, stage):
    expected = json.loads((evidence / "expected-lessons.json").read_text())
    page = execute(root, Path(os.environ["HOME"]), evidence, stage + "-lessons", "findings:lessons", {})
    assert page["rows"] == expected
    assert ledger_counts(root) == json.loads((evidence / "ledger-before.json").read_text())
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    before = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(before["path"]).read_bytes()).hexdigest() == before["sha256"]
    reports = root / ".kuzushi/reports"
    if stage in ["json", "restart"]:
        records = json.loads((reports / "findings.json").read_text())["findings"]
        assert len(records) == 1 and records[0]["reviewDecision"] == "confirmed"
        assert_exported_lessons(records[0]["lessons"], expected)
    elif stage == "sarif":
        result = json.loads((reports / "report.sarif").read_text())["runs"][0]["results"][0]
        assert_exported_lessons(result["properties"]["kuzushiLessons"], expected)
    elif stage == "jsonl":
        rows = [json.loads(line) for line in (reports / "findings.jsonl").read_text().splitlines()]
        records = [row for row in rows if row.get("recordType") != "metadata"]
        assert len(records) == 1 and records[0]["reviewDecision"] == "confirmed"
        assert_exported_lessons(records[0]["lessons"], expected)
    elif stage == "bundle":
        body = (reports / "report/findings/F-0001.md").read_text()
        assert "## Reusable lessons" in body and "Unicode café and ```" in body
        assert all(saved["lessonRef"]["sha256"] in body for saved in expected)
        assert_exported_lessons(markdown_lessons(body), expected)
    elif stage == "csv":
        with (reports / "findings.csv").open() as source:
            rows = list(csv.DictReader(source))
        assert len(rows) == 1 and rows[0]["review_decision"] == "confirmed"
        assert "lessons" in rows[0]["format_omitted_fields"]
        assert not any(saved["lesson"]["content"]["text"] in str(rows) for saved in expected)
    elif stage == "vuln-findings":
        document = json.loads((reports / "VULN-FINDINGS.json").read_text())
        assert document["scan_completed"] is False
        assert len(document["findings"]) == 1 and "lessons" not in document["findings"][0]
        assert not any(saved["lesson"]["content"]["text"] in str(document) for saved in expected)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"stage": stage,
        "lessonStates": ["draft", "accepted", "rejected", "retired"], "providerRequests": 0,
        "sourceExecuted": False, "sourceAndActiveContextUnchanged": True,
        "findingObservationsAndDecisionsUnchanged": True}, indent=2) + "\n")


def assert_exported_lessons(rows, expected):
    assert len(rows) == len(expected) == 4
    assert sum(row["eligibleForContext"] for row in rows) == 1
    for row in rows:
        matching = next(saved for saved in expected if saved["lessonRef"] == row["lessonRef"])
        assert row["lesson"] == matching["lesson"]
        assert row["eligibleForContext"] == (matching["lesson"]["state"] == "accepted")
        assert row["eligibilityNote"]


def markdown_lessons(body):
    text = "\n".join(line[4:] for line in body.split("## Reusable lessons\n", 1)[1].splitlines()
        if line.startswith("    "))
    decoder, rows = json.JSONDecoder(), []
    while text.strip():
        row, end = decoder.raw_decode(text.lstrip())
        rows.append(row)
        text = text.lstrip()[end:]
    return rows


if __name__ == "__main__":
    action, target, output = sys.argv[1:]
    root, evidence = Path(target).resolve(), Path(output).resolve()
    if action == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, action)
