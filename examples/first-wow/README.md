# Kuzushi First-Wow Demo

This demo runs the core workflow without real provider credentials or LLM
spend:

```text
doctor -> scan -> findings -> pr-comment
```

From the repository root:

```bash
examples/first-wow/run.sh
```

The script copies `server.js` to a temporary directory, prepends a demo-only
Semgrep fixture to `PATH`, runs the Rust CLI from source, persists findings in
the temporary target's `.kuzushi/v3/index.sqlite3`, prints the findings, and
writes a markdown PR/security review comment.

The fake scanner is intentionally small and inspectable. It does not pretend to
be Semgrep; it only makes the CLI workflow deterministic for first-run demos.
Its rows preserve scanner messages and redacted source locations, but remain at
the honest `signal_only` proof state until source-grounded review or verification
promotes them.
