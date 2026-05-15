# CRAP-Risk Gate

Kuzushi uses a strict proxy gate until true CRAP tooling is available for the
whole Rust workspace.

## Required Command

```bash
pnpm quality:crap-risk
```

CI runs this command in `.github/workflows/ci.yml`.

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
