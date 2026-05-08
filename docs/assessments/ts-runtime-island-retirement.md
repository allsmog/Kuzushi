# TypeScript Runtime Island Retirement

This assessment covers the 17 audited TypeScript subsystem directories:

`src/strategies`, `src/governance`, `src/jobs`, `src/hooks`, `src/intel`,
`src/scoring`, `src/monorepo`, `src/sessions`, `src/migrations`,
`src/scheduler`, `src/analysis-support`, `src/crypto-behavioral`,
`src/poc-executor`, `src/prompts`, `src/discovery`, `src/scanners`, and
`src/knowledge`.

## Closure Result

The original audit treated these directories as absent from the packaged Rust
CLI runtime. That remains true for `bin.kuzushi`, which points at the Rust
wrapper. It is not true for the TypeScript library build: the directories are
still transitively reachable from public TypeScript entrypoints.

Import graph inputs:

- Source graph: `src/**/*.ts` plus `scripts/pi-agent-core-bridge.mjs`.
- Public roots: `src/index.ts`, `src/modules/index.ts`,
  `src/testing/index.ts`, and `scripts/pi-agent-core-bridge.mjs`.
- Resolution includes relative `.js` specifiers mapped back to TypeScript
  source files, matching the Node16 TypeScript build style used in this repo.

Measured closure:

| Metric | Count |
| --- | ---: |
| Source/bridge files in graph | 563 |
| Files under the 17 audited directories | 162 |
| Files reachable from public roots | 422 |
| Audited files reachable from public roots | 118 |
| Reverse-import closure from audited files | 440 |

Public-root reachability:

| Public root | Reachable files | Audited files reached |
| --- | ---: | ---: |
| `src/index.ts` | 16 | 4 |
| `src/modules/index.ts` | 408 | 118 |
| `src/testing/index.ts` | 37 | 6 |
| `scripts/pi-agent-core-bridge.mjs` | 1 | 0 |

The dominant retention point is `src/modules/index.ts`, because it still
exports TypeScript built-in module factories that import the legacy TS module,
scanner, prompt, knowledge, and orchestration graph. Preserving the public
module-authoring API is compatible with retirement; preserving every built-in
factory implementation is not.

Implementation result: the public TypeScript source under `src/` is now the
narrow SDK surface (`src/index.ts`, `src/modules/index.ts`,
`src/testing/index.ts`, schemas, module authoring helpers, host handles, and
test mocks). The original 17 directories and the TS-only reverse-import caller
graph were moved to `reference/ts-runtime-island/src/**`. Product code must not
import that fixture path.

## Directory Decisions

Status meanings:

- `PORTED`: the runtime behavior is covered by a Rust path with tests.
- `MOVED-TO-FIXTURE`: the TS source is retained only under an explicit
  reference/fixture path and is not imported by product TypeScript code.
- `INTENTIONALLY-DROPPED`: the behavior is deliberately not carried into the
  Rust product path; the reason is documented here.
- `DELETED`: no runtime, fixture, or public API need remains.

| Directory | Public files reached | Direct product callers | Decision | Notes |
| --- | ---: | ---: | --- | --- |
| `src/strategies` | 15 | 5 | `MOVED-TO-FIXTURE` | TS strategy orchestration is a migration reference. Rust static ranking and scan modules own the product path. |
| `src/governance` | 0 | 1 | `MOVED-TO-FIXTURE` | Rust spend, whitebox-static, and shell approval code own current product behavior. |
| `src/jobs` | 0 | 4 | `INTENTIONALLY-DROPPED` | TS background job manager belongs to the retired dispatcher island. No public Rust equivalent is promised yet. |
| `src/hooks` | 3 | 3 | `INTENTIONALLY-DROPPED` | TS pipeline hooks are retired with the TS bus/orchestrator. Rust approval/runtime policy should remain explicit. |
| `src/intel` | 1 | 2 | `MOVED-TO-FIXTURE` | Rust `ndiff` rows cover current CVE fetch/pattern behavior; old TS store/feed code is reference-only. |
| `src/scoring` | 4 | 11 | `MOVED-TO-FIXTURE` | Rust finding detail/static ranking own product scoring. TS composite scoring remains reference material. |
| `src/monorepo` | 3 | 5 | `MOVED-TO-FIXTURE` | Rust repository inventory/static context cover the current scan path; TS monorepo scan is retired. |
| `src/sessions` | 0 | 2 | `INTENTIONALLY-DROPPED` | TS dispatcher sessions are not a current Rust product promise. |
| `src/migrations` | 12 | 1 | `MOVED-TO-FIXTURE` | Rust findings/workspace schema owns product persistence. TS SQLite migrations remain historical schema fixtures only. |
| `src/scheduler` | 3 | 5 | `INTENTIONALLY-DROPPED` | Scheduled TS runs are not part of the Rust CLI/TUI product surface yet. |
| `src/analysis-support` | 4 | 9 | `MOVED-TO-FIXTURE` | Rust code index/repository inventory cover the current product path; TS indexing helpers are reference-only. |
| `src/crypto-behavioral` | 4 | 3 | `INTENTIONALLY-DROPPED` | No current Rust product workflow promises TS crypto behavioral harness generation. |
| `src/poc-executor` | 4 | 7 | `INTENTIONALLY-DROPPED` | Rust sandbox/verify primitives remain; TS Docker PoC executor is retired. |
| `src/prompts` | 19 | 26 | `MOVED-TO-FIXTURE` | Rust prompt overrides and per-tool prompt builders own runtime behavior. TS prompt subsystem remains reference-only unless explicitly ported. |
| `src/discovery` | 13 | 12 | `MOVED-TO-FIXTURE` | Rust `context:build` and repository inventory own current discovery behavior. |
| `src/scanners` | 15 | 97 | `MOVED-TO-FIXTURE` | Rust `scan`, `semgrep`, `codeql`, secret/IaC, and agentic scan paths own runtime scanner behavior. TS helpers remain parity fixtures. |
| `src/knowledge` | 18 | 7 | `MOVED-TO-FIXTURE` | Rust artifact/workspace surfaces are current. TS knowledge registry remains reference-only. |

## Scanner Gap Decisions

The scanner parity gaps in `docs/assessments/scanners-parity.md` are resolved
for this retirement pass as follows:

| Gap | Decision | Reason |
| --- | --- | --- |
| CodeQL database operation serialization | `INTENTIONALLY-DROPPED` for TS retirement | The Rust CLI currently executes CodeQL through the Rust scanner path. If parallel CodeQL DB safety is needed, it should be added as a Rust mutex/queue around `CodeqlScanner`, not retained through `src/scanners/run-codeql.ts`. |
| Rich TS finding schema fields | `INTENTIONALLY-DROPPED` as TS schema parity | Rust finding detail, proof state, and message/evidence rendering are the product contract. Additional columns should be added through Rust migrations, not by keeping TS scanner types in the runtime graph. |
| Deterministic false-positive suppression before triage | `INTENTIONALLY-DROPPED` as a TS layer | Rust static ranking/noise adjustment exists. A future hard/soft suppression feature should be a Rust finding-ranking or scan-filter layer with explicit reasons. |
| LLM rescore batching/session behavior | `INTENTIONALLY-DROPPED` | This was a TS scanner optimization. Rust model-backed tools must keep explicit model/runtime selection and should add batching only through Rust runtime abstractions. |

## Prompt Gap Decisions

The prompt parity gaps in `docs/assessments/prompts-parity.md` are resolved for
this retirement pass as follows:

| Gap | Decision | Reason |
| --- | --- | --- |
| Template rendering with filters/loops/conditionals/sanitization | `MOVED-TO-FIXTURE` | Runtime prompt overrides in Rust are raw operator files. Reintroducing a template language would be new product scope and should be designed in Rust. |
| Layered prompt tool-policy resolution | `INTENTIONALLY-DROPPED` as TS prompt behavior | Rust uses explicit `AgentToolPolicy`, whitebox-static policy, and approval/sandbox surfaces. Tool policy must not silently merge from TS prompt metadata. |
| Language-specific tuning/few-shot assembly | `MOVED-TO-FIXTURE` | The TS profiles are useful reference data. Rust agentic prompts currently use bounded repo inventory/snippets; any few-shot layer should be ported deliberately. |
| Prompt module reports and stability tests | `MOVED-TO-FIXTURE` | These are prompt-quality fixtures, not current Rust runtime behavior. |

## Required Code Shape

Retirement is complete only when:

1. The original 17 `src/<subsystem>` paths no longer exist as product source.
2. Any retained TypeScript reference material lives under an explicit fixture or
   reference path that is excluded from `tsconfig.json`.
3. Product TypeScript source does not import retired fixture/reference paths.
4. Public docs do not present fixture/reference paths as current operator
   implementation targets.
5. `src/modules/index.ts` preserves module-authoring exports and either keeps
   built-in factory symbols as documented compatibility stubs or removes them
   with an explicit migration note.

The enforcement hook is `pnpm check:retired-ts-runtime`, which is also included
in `pnpm check:docs`.
