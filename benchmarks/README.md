# Benchmark corpora

Setup scripts for the target repositories used when exercising Kuzushi
against known-vulnerable codebases. Each corpus lives under
`benchmarks/<name>/setup.sh`; the scripts are idempotent and skip
already-cloned repos.

```sh
pnpm setup:benchmarks list
pnpm setup:benchmarks govwa juice-shop
pnpm setup:benchmarks all
```

Cloned repos land in `benchmarks/<name>/repo/` (gitignored).

| Corpus            | Target                                    |
|-------------------|-------------------------------------------|
| `govwa/`          | Go vulnerable web application             |
| `juice-shop/`     | OWASP Juice Shop (Node/TypeScript)        |
| `owasp-benchmark/`| OWASP BenchmarkJava                       |
| `cve-corpus/`     | Real-CVE checkouts per `manifest.json`    |

Scan a corpus with the CLI, e.g.:

```sh
kuzushi run sast:scan --target benchmarks/govwa/repo
```

Score recall against curated oracles with the `kuzushi-eval` crate and the
`experiments/recall-eval/` harness (see `experiments/recall-eval/README.md`).

The former TypeScript scoring harness (SARIF ground-truth matcher, baseline
regression gate, provenance hasher) was removed with the repository's
TypeScript surface; its design is preserved in git history and in
`plans/017-truthful-benchmark-scoring.md`, `plans/018-benchmark-result-provenance.md`,
and `plans/036-executed-benchmark-provenance.md`.
