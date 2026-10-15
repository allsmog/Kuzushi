# CRAP-Risk Gate

Kuzushi uses a strict proxy gate until true CRAP tooling is available for the
whole Rust workspace.

## Required Command

```bash
pnpm quality:crap-risk
```

CI runs this command in `.github/workflows/ci.yml`.

When `cargo llvm-cov` and `cargo crap` are available, `scripts/crap-gate.sh`
runs the real coverage-backed CRAP gate. Its default threshold is also 7;
raising it requires an explicit `KUZUSHI_CRAP_THRESHOLD` or `--threshold`
override and should be documented in the change.

## Score

The proxy score is:

```text
CRAP-risk = complexity + size_weight + side_effect_weight + coverage_gap + centrality_weight
```

The gate fails changed production Rust/JS/TS code when:

- CRAP-risk is greater than or equal to 7;
- function complexity is greater than 4;
- a function has more than 40 logical lines;
- a production file has more than 300 logical lines.

For tracked files that already exist, the proxy scores functions whose bodies
overlap the diff. Added and untracked files are scored in full, including the
file-size limit. This keeps the gate focused on new or modified code without
turning unrelated legacy functions in a touched file into a blocker.

The pinned terminal dependency has a separate authenticated baseline. Its
original crates.io archive checksum is fixed in
`scripts/vendored-terminal-baseline.mjs`; untouched package files must match
that archive. Identical upstream functions do not become local code merely
because the package is copied into the repository. New and modified functions
in the patched input files receive the same complexity, size and risk limits.
Their combined local production lines receive the 300-line file limit too.
The baseline tests reject archive replacement, unexpected upstream edits and
branchy local additions. See [terminal dependency maintenance](../../third-party/README.md).

## Weights

- `complexity`: one plus branch-like control-flow lines.
- `size_weight`: grows after 40 logical lines.
- `side_effect_weight`: filesystem, process, network, env, or similar effects.
- `coverage_gap`: changed production code without any changed test file.
- `centrality_weight`: scripts, binaries, lib/main, registry, runtime, renderer.

## Design Rules

- Keep side effects at adapters and edges.
- Split branchy parsing and formatting into pure helpers.
- Add focused tests for branchy changed behavior.
- Do not add exceptions for convenience.
- Do not claim the gate passed unless the command was run.

True CRAP tooling can provide additional evidence, but it cannot replace this
gate unless it enforces an equal or stricter threshold.
