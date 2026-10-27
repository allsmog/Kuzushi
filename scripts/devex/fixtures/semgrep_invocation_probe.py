"""Record exact arguments before replacing this probe with the installed scanner."""
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path


def install(evidence):
    engine = Path(shutil.which("semgrep")).resolve()
    probe = evidence / "semgrep-probe"
    probe.write_text("#!" + sys.executable + "\n" + Path(__file__).read_text())
    probe.chmod(0o700)
    metadata = {
        "engine": str(engine),
        "engineSha256": hashlib.sha256(engine.read_bytes()).hexdigest(),
        "probeSha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
        "interpreter": sys.executable,
        "log": str(evidence / "semgrep-invocations.jsonl"),
    }
    probe.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")
    return probe


def record_and_exec(probe):
    metadata = json.loads(probe.with_suffix(".json").read_text())
    row = {"pid": os.getpid(), "parentPid": os.getppid(), "cwd": os.getcwd(), "argv": sys.argv[1:]}
    descriptor = os.open(metadata["log"], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        payload = (json.dumps(row) + "\n").encode()
        assert os.write(descriptor, payload) == len(payload)
    finally:
        os.close(descriptor)
    os.execv(metadata["engine"], [metadata["engine"], *sys.argv[1:]])


if __name__ == "__main__":
    record_and_exec(Path(sys.argv[0]))
