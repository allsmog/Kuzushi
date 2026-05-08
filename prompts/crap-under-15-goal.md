# /goal: CRAP Under 15 Cleanup

Use this with Kuzushi's `/goal` command when you want an autonomous cleanup pass focused on CRAP complexity.

```text
Drive Kuzushi's Rust codebase to a state where every newly touched, introduced, or rewritten Rust function has CRAP < 15 as measured by `cargo crap`, repeatedly refactoring the highest-risk offenders into small, intention-revealing functions with focused tests, preserving all CLI/TUI behavior, persisted `.kuzushi` formats, module/tool contracts, model/runtime no-silent-fallback policy, and scan/shell/run parity, and do not stop until `cargo fmt --all --check`, `cargo check --workspace`, the relevant tests, and a final `cargo crap --workspace --threshold 15 --fail-regression` gate all pass or every remaining blocker is documented with exact file/function evidence.
```

Recommended verification commands:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo crap --workspace --threshold 15 --fail-regression
```

If you are comparing against a known-clean baseline, generate and use a baseline:

```bash
cargo crap --workspace --format json --output /tmp/kuzushi-crap-baseline.json
cargo crap --workspace \
  --threshold 15 \
  --baseline /tmp/kuzushi-crap-baseline.json \
  --fail-regression \
  --format human \
  --top 40
```
