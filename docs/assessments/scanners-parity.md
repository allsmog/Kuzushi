# `src/scanners` Parity Gap Assessment

`src/scanners/` is runtime-orphaned from the packaged Rust CLI, but it still
has heavy TypeScript caller and test coverage. The migration ledger asserts
Rust parity for core scanner execution paths (`sast:scan`, `semgrep:scan`,
`codeql:scan`, `agentic-sast:scan`, and related rows), not for every
cross-cutting scanner helper below.

## Unasserted Behaviors

1. CodeQL database operation serialization.

   The TypeScript CodeQL runner keeps an in-process database creation lock and
   per-database operation queue to avoid concurrent CodeQL JVM file-lock
   failures (`src/scanners/run-codeql.ts:14`, `src/scanners/run-codeql.ts:21`,
   `src/scanners/run-codeql.ts:28`, `src/scanners/run-codeql.ts:169`,
   `src/scanners/run-codeql.ts:180`, `src/scanners/run-codeql.ts:245`). The
   Rust CodeQL path creates/reuses `.kuzushi/codeql-db` and runs analysis
   directly, but the cited scanner code has no equivalent per-database mutex in
   the execution path (`crates/kuzushi-core/src/scan.rs:353`,
   `crates/kuzushi-core/src/scan.rs:363`, `crates/kuzushi-core/src/scan.rs:369`,
   `crates/kuzushi-core/src/scan.rs:343`,
   `crates/kuzushi-core/src/scan.rs:345`). This is a parity gap for parallel
   CodeQL scan safety, even though single-scan execution is ported.

2. Rich TypeScript finding schema fields are not product-wide Rust columns.

   TypeScript findings carry scanner evidence, likelihood, impact, CWE,
   adjusted score, reachability, `taintPath`, proof state, engine provenance,
   corroborating signals, suppression reasons, blame, and actor fingerprints
   (`src/scanners/types.ts:40`, `src/scanners/types.ts:49`,
   `src/scanners/types.ts:51`, `src/scanners/types.ts:56`,
   `src/scanners/types.ts:60`, `src/scanners/types.ts:61`,
   `src/scanners/types.ts:62`, `src/scanners/types.ts:63`,
   `src/scanners/types.ts:64`, `src/scanners/types.ts:66`). Rust CodeQL
   normalization currently turns CodeQL flow evidence into message text and
   creates a core finding through `Finding::new_tool`
   (`crates/kuzushi-core/src/scan.rs:1165`,
   `crates/kuzushi-core/src/scan.rs:1170`), while static evidence indexing is a
   separate best-effort path (`crates/kuzushi-core/src/scan.rs:1076`,
   `crates/kuzushi-core/src/scan.rs:1111`,
   `crates/kuzushi-core/src/scan.rs:1113`). The migration ledger explicitly
   notes some TS-only fields are folded into messages, so this remains a gap
   for structured evidence consumers.

3. Deterministic false-positive suppression before triage is not asserted as a
   Rust scanner layer.

   TypeScript applies hard and soft false-positive rules for DoS/resource
   exhaustion, rate limiting, resource leaks, open redirects, test/docs paths,
   generated or vendored paths, and custom exclusions before LLM triage
   (`src/scanners/fp-filter.ts:38`, `src/scanners/fp-filter.ts:52`,
   `src/scanners/fp-filter.ts:58`, `src/scanners/fp-filter.ts:93`,
   `src/scanners/fp-filter.ts:99`, `src/scanners/fp-filter.ts:105`,
   `src/scanners/fp-filter.ts:119`, `src/scanners/fp-filter.ts:134`,
   `src/scanners/fp-filter.ts:190`). Rust static ranking does include a
   `noise_adjustment` factor and deterministic impact score
   (`crates/kuzushi-core/src/static_ranking.rs:33`,
   `crates/kuzushi-core/src/static_ranking.rs:46`,
   `crates/kuzushi-core/src/static_ranking.rs:120`), but that is ranking, not a
   documented pre-triage hard/soft suppression layer with suppression reasons.

4. LLM rescore batching/session behavior is not represented by a scanner parity
   row.

   TypeScript `llm-rescore` batches findings, reads file snippets, prefers a
   Batch API path, falls back to session/one-shot execution, and returns
   per-fingerprint keep/drop scores (`src/scanners/llm-rescore.ts:21`,
   `src/scanners/llm-rescore.ts:63`, `src/scanners/llm-rescore.ts:72`,
   `src/scanners/llm-rescore.ts:101`, `src/scanners/llm-rescore.ts:144`,
   `src/scanners/llm-rescore.ts:208`). Rust has explicit model requirements
   and structured runtime calls for agentic scanners
   (`crates/kuzushi-core/src/modules/agentic_sast.rs:267`,
   `crates/kuzushi-core/src/modules/agentic_sast.rs:288`,
   `crates/kuzushi-core/src/modules/agentic_sast.rs:302`), but no scanner
   parity row asserts the TS rescore windowing, batch cost optimization, or
   keep/drop filtering behavior.

## Recommendation

Keep `src/scanners/` as a migration fixture until the caller graph is retired.
Port only the specific gaps above if product requirements still need them in
the Rust path. Do not delete this directory while it still has direct callers
from `src/agents`, `src/bus`, `src/modules`, and reporting helpers.
