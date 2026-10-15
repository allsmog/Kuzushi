"""Real native source-review form on owned inert source; no provider work."""
import json
import sys
from pathlib import Path

from source_transition import seed, advance, LATER_SHA
from secret_settings import ledger, save
from catalog_dependencies import git, source_files


def seed_form(parent, evidence, home):
    seed(parent, evidence, home)
    (evidence / "review-reason.txt").write_text("Owned current source reviewed.\nInvestigation is explicitly deferred.\n")


def verify(parent, evidence):
    root = parent / "repository"
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations",
                               "investigation_work_attempts", "investigation_allowance_revisions"]}
        source = db.execute("select json_extract(payload_json,'$.reviewedSource') from finding_events "
                            "where json_extract(payload_json,'$.reviewedSource') is not null").fetchone()
        reason = db.execute("select rationale from review_decisions order by id desc limit 1").fetchone()[0]
    assert list(counts.values()) == [4, 2, 0, 0, 0], counts
    source = json.loads(source[0])
    assert source["sourceGit"]["sha"] == LATER_SHA and source["sourceGit"]["dirty"] is True
    assert source["citedFile"]["state"] == "captured"
    assert reason == (evidence / "review-reason.txt").read_text()
    reference = source["citedFile"]["blobHash"]
    blob = root / ".kuzushi/v3/objects/blake3" / reference[:2] / reference[2:4] / reference
    # Resolve the documented object store from the real receipt, with no live source fallback.
    if not blob.exists():
        candidates = list((root / ".kuzushi").glob("**/blake3/" + reference[:2] + "/" + reference[2:4] + "/" + reference))
        assert len(candidates) == 1
        blob = candidates[0]
    assert blob.read_bytes() == (root / "public-example.env").read_bytes()
    original = json.loads((evidence / "source-after.json").read_text())
    assert git(root, "rev-parse", "HEAD") == original["sha"] and source_files(root) == original["files"]
    save(evidence, "source-form-invariants", {"counts": counts, "reviewedSource": source,
         "providerRequests": 0, "sourceExecuted": False, "newCommits": 0})


if __name__ == "__main__":
    parent, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    action = sys.argv[3]
    if action == "seed":
        seed_form(parent, evidence, Path(sys.argv[4]).resolve())
    elif action == "advance":
        advance(parent, evidence)
    else:
        verify(parent, evidence)
