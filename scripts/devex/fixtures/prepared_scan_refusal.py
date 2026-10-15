"""Owned inert observations and an unapproved Scan with no network fallback."""
import sys
from pathlib import Path

from prepared_dispatch_refusal import seed, verify


if __name__ == "__main__":
    root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    stage = sys.argv[3]
    evidence.mkdir(parents=True, exist_ok=True)
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage, tool="agentic-sast:scan")
