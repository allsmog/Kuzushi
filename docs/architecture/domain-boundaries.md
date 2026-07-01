# Domain Boundaries

Kuzushi uses light domain boundaries to keep security behavior explicit. This
is not a request to add enterprise layers. Prefer small, behavior-preserving
helpers and tests over generic repositories, factories, or traits.

The port-level boundary contract is
[`docs/architecture/kuzushi-boundaries.md`](./kuzushi-boundaries.md). For
"where do I edit this?" and focused commands, see
[`docs/devex/new-contributor-map.md`](../devex/new-contributor-map.md).

## Findings Domain

Owner files:
`crates/kuzushi-core/src/findings/`, findings presentation helpers under
`crates/kuzushi-core/src/findings/presentation/`, and CLI findings/report
paths.

Vocabulary:
`Finding`, `Fingerprint`, `Severity`, `TriageVerdict`, `ProofLevel`,
`VerificationOutcome`, `Suppression`, `ExploitChain`, alias (`F-0001`), and
dedupe key.

Invariants:
fingerprints and aliases stay deterministic; SQLite migrations preserve old
stores; proof state must not overclaim empirical validation; JSON output stays
machine-readable.

Allowed dependencies:
scanner/tool outputs may create findings; CLI/TUI/reporting may read findings;
verification and patching may attach outcomes.

Forbidden dependencies:
findings persistence must not call LLM providers, shell renderers, or scanner
subprocesses directly.

Extension points:
add a field only with migration/tests; add report labels in reporting helpers;
add CLI/TUI views by reading store APIs.

Belongs here:
filtering by severity/verdict/source, alias resolution, PR-comment finding
selection, proof-state labels.

Belongs elsewhere:
running Semgrep, selecting scan tasks, prompting a model, applying patches.

## Module / Tool Domain

Owner files:
`crates/kuzushi-core/src/modules/`, `src/modules/types.ts`,
`src/modules/define.ts`, `src/modules/loader.ts`, and `src/modules/registry.ts`.

Vocabulary:
`CopilotModule`, `ModuleTool`, `DagTool`, `ExecutionContext`,
`ToolExecutionContext`, module id, tool name, hidden DAG node, and option spec.

Invariants:
tool names use `<moduleId>:<action>`; hidden DAG tools do not surface in
operator lists; headless tools avoid shell-only behavior; model choice comes
from context/config, not literals.

Allowed dependencies:
modules may call scan engines, findings store, runtime handles, and workspace
handles through narrow context APIs.

Forbidden dependencies:
module contracts must not leak concrete shell classes, bypass runtime/model
enforcement, or change persisted `.kuzushi` formats casually.

Extension points:
add a tool descriptor, implement executor, register module, add focused
registry tests, and update docs if public.

Belongs here:
tool input validation, registry dispatch, DAG descriptor registration, module
option metadata.

Belongs elsewhere:
terminal key handling, CI workflow text, scanner subprocess internals.

## Scan / Run Domain

Owner files:
`crates/kuzushi-core/src/scan/`,
`crates/kuzushi-core/src/modules/application/sast_scan/`,
`crates/kuzushi-cli/src/main.rs`, and scan worker/artifact readers.

Vocabulary:
`RunId`, `RunArtifact`, `ScanEngine`, `TaskSelection`, `ScanSummary`, engine,
task, scan mode, and run artifact.

Invariants:
scan/shell/run converge on the same tool dispatch path; scan artifacts under
`.kuzushi/runs/<runId>/` remain readable; `--ci` output is deterministic and
line-oriented.

Allowed dependencies:
scan orchestration may call module tools, scanner engines, findings store,
spend limits, and runtime-backed post-processing when explicitly configured.

Forbidden dependencies:
scan should not silently choose models, invent missing external binaries, or
write shell-only state.

Extension points:
add a scan engine, add a task selector mapping, add artifacts with tests, and
update mode-parity docs if a mode differs.

Belongs here:
Semgrep/CodeQL/secret scan execution, task filtering, scan summaries, CI event
lines.

Belongs elsewhere:
finding alias presentation, TUI layout, module manifest validation.

## Runtime / Model Domain

Owner files:
`crates/kuzushi-core/src/runtime/policy/no_silent_fallback.rs`,
`crates/kuzushi-core/src/agent_router/`, Rust runtime bridge wiring,
`crates/kuzushi-core/src/modules/resolve_tool_model.rs`,
`scripts/check-model-safety.mjs`, and no-fallback tests.

Vocabulary:
`AgentRuntime`, `ModelSpec`, provider, backend, transport retry,
fallback-consent, runtime compatibility, and bridge command.

Invariants:
Kuzushi never silently switches runtime, provider, or model. Same-model
transport retries are allowed. Configured incompatible pairs fail.

Allowed dependencies:
runtime adapters may read config, env, explicit tool model, and bridge options.

Forbidden dependencies:
feature modules must not hardcode fallback model literals or mutate operator
model choice.

Extension points:
add a provider/backend by extending enforcement, adapter dispatch, config
validation, docs, and no-fallback tests together.

Belongs here:
provider compatibility checks, stale-model warnings, batch-to-sequential
same-model fallback.

Belongs elsewhere:
finding severity ranking, TUI command parsing, scanner JSON parsing.

## Shell / TUI Domain

Owner files:
`crates/kuzushi-tui/src/app/`,
`crates/kuzushi-tui/src/commands/`,
`crates/kuzushi-tui/src/renderer/`,
`crates/kuzushi-tui/src/renderer/plain/`, and
`crates/kuzushi-tui/src/theme/mod.rs`.

Vocabulary:
`ShellView`, `ShellCommand`, `ViewTransition`, `PlainOutput`, hotkey,
scripted output, and command spec.

Invariants:
Ratatui is the interactive shell; plain output remains useful without ANSI or
box drawing; command specs are the source of truth; shell-only features are
documented as intentional asymmetries.

Allowed dependencies:
TUI may call CLI/core command services, module registry, findings readers, and
workspace state through supported handles.

Forbidden dependencies:
do not add React/Ink/TSX UI paths or a second TypeScript command router.

Extension points:
add a `ShellView`, parse/help entry, reducer/key handling, Ratatui rendering,
plain output, and focused tests.

Belongs here:
slash command parsing, view state transitions, rendering findings aliases,
plain/scripted shell output.

Belongs elsewhere:
scanner process execution, model enforcement, persisted schema migrations.

## Ambiguous Terms To Avoid

- "copilot" when the user-facing meaning is a security-native code agent.
- "validated" unless runtime verification or an equivalent empirical check ran.
- "scan output" when the artifact is specifically persisted findings,
  run summary, PR comment markdown, or CI event lines.
- "module" when the change is only a scan engine or only a shell view.

## Where DDD Should Stop

Do not add repositories for every table, traits for every struct, service
layers around single functions, factories without construction complexity, or
newtypes that do not prevent a real bug. The useful boundary is ownership:
clear files, clear vocabulary, explicit invariants, and focused tests.
