# Taint IRIS Next

`taint-iris-next` is Kuzushi's experimental, agent-forward taint hunting module inspired by the IRIS neuro-symbolic SAST paper.

Inspired by "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities" (Li, Dutta, Naik; ICLR 2025). This module adapts the paper's source/sink inference and taint-spec workflow to Kuzushi's context map, threat model, agent progress UI, and pluggable evidence backends. It is not affiliated with or endorsed by the IRIS authors.

References:

- https://openreview.net/forum?id=G3GvXMpzXM
- https://github.com/iris-sast/iris

## Positioning

The IRIS idea is to use LLMs to infer taint specifications, run static analysis to find whole-repo source-to-sink paths, and apply contextual analysis to filter false positives.

Kuzushi's adaptation keeps that source/sink and taint-spec workflow as inspiration, but drives the hunt from Kuzushi's context and threat-model modules. The intended flow is context/threat-model driven hunt planning, tree-sitter/ast-grep/Semgrep-style structural extraction, scoped agents, and optional CodeQL/Joern/language backends for deeper evidence.

The engine design also follows the concepts reviewed from `/Users/operator/Desktop/iris.pdf`: candidate API extraction, LLM taint-spec labeling, CodeQL-backed path detection, and contextual false-positive filtering.

## Engine V1

The public tool is `taint-iris-next:hunt`.

- `mode=plan` runs deterministic planning, candidate extraction, typed spec seeding, and optional backend path detection. It returns the ranked catalog, structural query seeds, candidates, labeled specs, evidence rows, backend choice, and the bounded prompt that hunt mode would send to the agent.
- `mode=hunt` runs the same deterministic prepass, then sends one bounded agent session the context summary, threat-model summary, CWE Candidate Catalog, candidate/spec counts, evidence bundles, and internal evidence tools.
- `backend=auto` uses structural extraction first. If `ast-grep`/tree-sitter support is available, V1 uses it for bounded parser-aware call candidates and falls back to `rg` for broad/token signals. If an existing CodeQL DB is present under `.kuzushi/codeql-db` or `.codeql/db`, V1 also runs read-only CodeQL analysis as corroboration and converts matching SARIF findings into catalog-scoped evidence rows.
- `backend=codeql` is opt-in and uses an existing DB only. If no DB exists, V1 falls back to structural evidence and reports a warning. It never creates a CodeQL database.
- If a DB exists but the CodeQL CLI is not installed, V1 keeps the structural evidence and reports the CLI problem explicitly.
- `backend=semgrep|joern|language` is reserved behind the same evidence interface; V1 falls back to structural evidence until those adapters land.

Caps keep the run bounded: `maxCatalogEntries`, `maxCandidatesPerCwe`, `maxEvidencePerCwe`, `maxFilesPerQuery`, `maxSpecsPerCwe`, `maxAgentFindings`, and `codeqlAnalyzeTimeoutMs`.

`minEvidenceLevel=linked` is the default. Raw structural hits are candidate evidence only; findings require either backend path evidence or a clearly linked source-to-sink/control story. Operators can tighten to `path` or loosen to `candidate`.

The module requires usable context or a file inventory. An empty threat model is a warning, not a blocker; `/threats regen dfd` improves ranking and triage but should not prevent structural-first hunts from producing candidates.

## CWE Reference

`taint-iris-next` owns a typed CWE catalog in `src/modules/taint-iris-next/cwe-reference.ts`. The deterministic prepass filters and ranks this catalog using detected languages, frameworks, data stores, entrypoints, and threat-model `relatedCwe` fields. The agent-facing prompt receives the bounded "CWE Candidate Catalog" section from this reference file and must cite catalog signals when selecting CWEs.

The catalog seeds structural extraction with source, sink, sanitizer, and backend-neutral query signals for common taint classes across mixed-language repos, including Rust, Ruby, JavaScript/TypeScript, Python, Go, Java, PHP, and C#.

## Data Flow

Deterministic:

- Load context snapshot and threat-model document when available.
- Inventory language hints when context is sparse.
- Filter and rank the full CWE catalog.
- Generate backend-neutral structural query seeds.
- Extract bounded candidate APIs with `ast-grep` when available and `rg` as guaranteed fallback: external API calls, internal function parameters, routes/handlers, sinks, sanitizers, and guard/policy anchors.
- Link lightweight same-file/function source-to-sink stories from variables, assignments, call arguments, return values, line proximity, and sanitizer/guard context. These become `linked` evidence; only CodeQL or a future graph backend produces `path` evidence.
- Seed IRIS-style typed specs: internal parameter source, external return source, external argument sink, sanitizer, propagator, or control-context guard.
- Split taint and non-taint/control CWE handling. Authorization classes such as `CWE-862` use guard/policy/path-context analysis rather than generic taint-path CodeQL.
- When Python CodeQL is selected and an existing DB plus CLI are available, generate per-CWE `@kind path-problem` queries from the typed specs, split large generated predicates into chunks, run read-only analysis, and map SARIF paths back to source/step/sink evidence rows under the requested scan target.
- Choose backend and record provenance without silently creating heavyweight databases.

Agentic:

- Choose final CWE themes from the provided catalog.
- Inspect candidates and generated specs through in-process evidence tools: `list_candidates`, `get_candidate_context`, `label_taint_specs`, `run_backend_query`, `get_path_context`, and `record_triage`.
- Refine source, sink, sanitizer, propagator, or guard specs.
- Contextually triage each path or linked story as `finding`, `candidate`, or `rejected` with rationale.
- Return strict JSON findings that cite catalog signals and declare the evidence level.

## Runtime Header

```text
┌─ Taint IRIS Next ───────────────────────────────────────────────────────────┐
│ inspired by IRIS, ICLR 2025 · Kuzushi agent-forward adaptation              │
│ context loaded · threat model loaded · structural trace · backend auto       │
└─────────────────────────────────────────────────────────────────────────────┘
```
