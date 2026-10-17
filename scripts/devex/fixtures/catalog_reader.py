"""Owned catalog reader and confirmation recovery, no live model or source execution."""
import json
import sys
from pathlib import Path

import taint_catalog as base
from secret_settings import save


def replay_command(evidence, name, run):
    (evidence / (name + "-command.txt")).write_text("replay " + run["runId"])


def latest(root, tool, predicate):
    rows = [(run, body) for run, body in base.results(root, tool) if predicate(body)]
    assert rows, tool
    return rows[-1]


def generated(root, evidence):
    base.inspect(root, evidence, "generated")
    run, body = latest(root, base.TOOL, lambda body: body.get("data", {}).get("status") == "draft")
    assert body["data"]["baseCatalogDigestRef"]
    replay_command(evidence, "replay-draft", run)
    save(evidence, "reader-draft", {"runId": run["runId"], "draftRef": body["data"]["draftRef"],
        "baseCatalogDigestRef": body["data"]["baseCatalogDigestRef"]})


def capture(evidence, suffix):
    paths = list(evidence.glob("*-" + suffix + ".txt"))
    assert len(paths) == 1, paths
    return paths[0].read_text()


def inspect_orientation(evidence, suffix):
    lines = capture(evidence, suffix).splitlines()
    assert "REPLAY · Result" in lines[0], lines[0]
    assert any("Ctrl+C exit" in line and "Tab receipt" in line for line in lines)
    assert any("PgUp/Dn read" in line for line in lines)
    assert any("rows " in line for line in lines)


def inspect_reader(root, evidence, stage):
    if stage == "inputs":
        run, body = latest(root, "taint-iris-next:catalog-read", lambda body: "frozenInput" in body.get("data", {}))
        assert body["data"]["sourceFreshnessVerified"] is False
        replay_command(evidence, "replay-inputs", run)
    elif stage == "pin-read":
        run, body = latest(root, "taint-iris-next:catalog-read", lambda body: body.get("data", {}).get("status") == "saved")
        assert body["data"]["sourceFreshnessVerified"] is False
        replay_command(evidence, "replay-pin", run)
    elif stage == "reader-pages":
        text = "\n".join(path.read_text() for path in evidence.glob("*result-reading*40x12.txt"))
        assert "priority 0" in text and "Active catalog at draft creation" in text
        source = "\n".join(path.read_text() for path in evidence.glob("*inputs-reading*40x12.txt"))
        assert "owned_input" in source and "explicitly absent" in source
        for suffix in ["result-reading-03-40x12", "inputs-reading-08-40x12"]:
            inspect_orientation(evidence, suffix)
    elif stage == "confirm-hidden":
        text = capture(evidence, "exact-acceptance")
        assert "CONFIRM" in text and "acknowledged: true" in text
        assert "Esc dismiss" not in text
    elif stage == "confirm-canceled":
        text = capture(evidence, "canceled-acceptance")
        assert "Esc dismiss" in text and "CONFIRM" not in text
        accepted = [body for _, body in base.results(root, "taint-iris-next:catalog-accept")
                    if body.get("data", {}).get("status") == "accepted"]
        assert not accepted
        assert len(base.calls(evidence)) == 2
    else:
        raise AssertionError(stage)
    save(evidence, stage + "-check", {"liveProviderRequests": 0, "interceptedRequests": len(base.calls(evidence)),
        "sourceExecuted": False, "stage": stage})


def main():
    root, evidence = map(Path, sys.argv[1:3])
    stage = sys.argv[3]
    if stage == "generated":
        generated(root, evidence)
    elif stage in ["inputs", "pin-read", "reader-pages", "confirm-hidden", "confirm-canceled"]:
        inspect_reader(root, evidence, stage)
    else:
        base.main()


if __name__ == "__main__":
    main()
