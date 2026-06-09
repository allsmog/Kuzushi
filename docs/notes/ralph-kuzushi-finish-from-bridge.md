# Ralph Loop Prompt: Kuzushi Finish From Bridge Gaps

You are working in `/Users/operator/VibeCode/open-sourced/kuzushi`.

This is the single canonical Ralph prompt for the remaining Kuzushi work after
the Rust/pi-agent-core migration.

The migration itself is complete and pushed. Do not restart the migration. Do
not use the old `.ralph/ralph-tasks.md` checklist. That file may contain
already-completed migration tasks and can cause a false one-iteration
completion.

Run this prompt in normal Ralph mode, not `--tasks` mode.

## Mission

Finish Kuzushi from the bridge gaps forward:

1. Bridge useful legacy operator affordances into the Rust shell/core.
2. Finish Rust terminal UX repair and final Ink/React runtime cleanup.
3. Add Kuzushi `whitebox-static` mode as an additive static-only analysis mode.

Work in that order. Do not start Stage 2 until Stage 1 is complete, committed,
and pushed. Do not start Stage 3 until Stage 2 is complete, committed, and
pushed.

Final completion marker, only after all three stages are done:

```text
<promise>KUZUSHI_FINISH_FROM_BRIDGE_COMPLETE</promise>
```

## Current Ground Truth

- Rust is the primary product path.
- `bin/kuzushi-rs.mjs` and the Rust binary are the package CLI path.
- The TypeScript/Ink shell is a legacy reference unless a specific task proves
  retained code is still required for non-runtime tests or libraries.
- Useful legacy operator behavior must be ported or intentionally accounted for
  before final deletion.
- Do not call the whitebox work by a competitor name. The Kuzushi feature name
  is `whitebox-static`.

## Progress Files

Read or create these files:

- `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md` for Stage 1.
- `RALPH_RUST_UX_PROGRESS.md` for Stage 2.
- `progress/kuzushi-whitebox-static.progress.md` for Stage 3.

Each iteration must update the active progress file with:

- task attempted
- files changed
- tests/checks run
- result
- remaining work
- blockers or repo facts that contradicted this prompt

## Ralph Iteration Rules

Each iteration must:

1. Inspect `git status --short`.
2. Read the active progress file.
3. Pick the highest-priority incomplete task in the active stage.
4. Implement one coherent slice.
5. Add focused tests/snapshots where feasible.
6. Run the smallest relevant checks first.
7. Update the active progress file.
8. Commit only after checks pass.
9. Push the branch after each successful commit.
10. Exit unless every task in every stage is complete.

If Ralph injects a "Current tasks from `.ralph/ralph-tasks.md`" block, stop and
rerun without `--tasks`.

Do not emit `<promise>KUZUSHI_FINISH_FROM_BRIDGE_COMPLETE</promise>` until:

- Stage 1 says no bridge gaps remain.
- Stage 2 says no UX/Ink runtime work remains.
- Stage 3 says no whitebox-static work remains.
- Relevant full checks pass.
- All commits are pushed.

## Global Guardrails

- Do not reintroduce Ink/React into the primary CLI runtime.
- Do not delete TypeScript/Ink code until useful behavior is ported to Rust or
  the retention/deletion reason is documented.
- Do not invent fake commands. Help must match routed behavior.
- Do not weaken runtime/model enforcement or no-silent-model-fallback behavior.
- Do not leak credentials into subprocess environments.
- Do not make network calls in tests.
- Do not add a network-only vector DB dependency.
- Preserve `.kuzushi/v2/` state compatibility.
- Keep terminal UX dense, readable at 80 columns, and operator-oriented.
- Do not break non-TTY, CI, piped, or strict plain output.
- Keep each iteration small enough to review.

## Full Checks

Use focused checks per task. Before declaring each stage complete, run the
relevant subset. Before the final promise, run:

```sh
cargo fmt --all
cargo test --workspace
cargo build --workspace
pnpm check
pnpm typecheck
pnpm build
pnpm test:e2e
pnpm build:native
pnpm verify:pack
```

`pnpm check` may print existing warnings while exiting successfully. Treat the
exit code as the gate unless the active task is cleaning warnings.

# Stage 1: Rust Bridge Gaps

Start here.

Goal: bridge practical operator affordances from the legacy TypeScript/Ink shell
into the Rust shell/core. This is not Ink preservation and not a new migration.

Inspect first:

- `crates/kuzushi-tui/src/commands.rs`
- `crates/kuzushi-tui/src/renderer.rs`
- `crates/kuzushi-core/src/modules.rs`
- `crates/kuzushi-core/src/config.rs`
- `src/copilot/shell-commands.ts`
- `src/copilot/shell.ts`
- `src/copilot/options.ts`
- `src/modules/_shared/artifact-kb/store.ts`
- `src/modules/threat-model/kb-index.ts`
- `tests/ui/__snapshots__/component-snapshots.test.tsx.snap`

## BG-001: Bridge-Gap Progress File And Command Parity Audit

Acceptance:

- Create `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md`.
- List current Rust shell commands and legacy TS commands.
- Classify each legacy command as port now, already covered, intentionally
  removed, or deferred with reason.
- Include file/line references for parser/help facts.
- Add a Rust test or snapshot encoding the intended Rust shell command surface.

## BG-002: Rust Tool Option Metadata

Acceptance:

- Add Rust `OptionSpec` or equivalent with name, type, description, required,
  advanced/evasion flag, default, enum choices, and validation/coercion basics.
- Expose option specs for visible tools.
- Keep descriptor serialization backward-compatible or update tests
  intentionally.
- Tests cover bool, int, float, path/string, enum, required missing, defaults,
  and invalid values.

## BG-003: Rust Datastore And Option Precedence

Acceptance:

- Store session/global/workspace/module option values or a documented subset.
- Test deterministic precedence.
- Set options affect subsequent `run`, focused-module run, and scan paths where
  applicable.
- Persistent scope writes only after explicit command.
- No model fallback is introduced through option precedence.

## BG-004: `show options` / `/options` / `set`

Acceptance:

- Route `options`, `/options`, `show options`, `/show options`,
  `show options <tool>`, `show advanced`, `show missing`, `set`, `/set`, and
  supported `setg`/`unset`/`unsetg`.
- Render an 80-column readable options table.
- Unknown options show closest valid names and the next command.
- Help includes these commands only after they route.

## BG-005: SAST Task Picker And Task Options

Acceptance:

- Route `/tasks`, `tasks`, `/task block <id>`, `/task allow <id>`,
  `/task toggle [id]`, `/task mode auto|manual|toggle`, and `/task reset`.
- Task state maps to Rust `sast:scan` or scan task selection.
- Task options appear in `show options`.
- Unknown task IDs list valid IDs and do not mutate state.

## BG-006: Knowledge Base Attachments View

Acceptance:

- Route `/kb`, `kb`, `attachments`, `attach <path-or-url>`, `detach <id>`,
  and `reparse <id>` for supported modules.
- Support at least `context`, `threat-model`, `carlini-threat-hunt`, and
  `x-ray` where Rust artifacts exist.
- Store locally under `.kuzushi/v2/` or a documented compatible path.
- Reject unsafe paths. URL attachments are metadata-only unless an explicit
  offline import path exists.

## BG-007: Artifact Knowledge DB / Search

Acceptance:

- Add local/offline knowledge DB abstraction for indexed artifact chunks.
- Default implementation is SQLite FTS or equivalent deterministic search.
- Index context snapshots, threat-model/Randori artifacts, X-Ray artifacts,
  Carlini outputs, and run summaries where available.
- Record source path, module id, run id, content hash, title, summary, body,
  refs, metadata, and indexed time.
- Tests cover index, re-index, search, stale source hash, and missing DB.

## BG-008: Use Knowledge DB In Agentic Rust Tools

Acceptance:

- Rust prompt builders or `ToolExecutionContext` can retrieve relevant KB
  snippets.
- At least two modules use the shared KB path, preferably
  `carlini-threat-hunt`, `x-ray`, or `threat-model`.
- Missing KB degrades clearly and does not fail the tool.

## BG-009: Context Commands

Acceptance:

- Route `/context`, `context`, `/context build`, `/context regen <slice>`, and
  `/context status`.
- Display current context snapshot if present.
- `/context build` dispatches `context:build` and writes the expected artifact.
- Unsupported slices return actionable messages.

## BG-010: Workspace Import/Export And Status

Acceptance:

- Expose workspace status and at least one export path for findings or evidence.
- Unsupported import/export formats fail actionably and are not advertised as
  complete.
- Tests cover no workspace and export to a temp path.

## BG-011: Auth, Provider, Backend, Model, And Cost Commands

Acceptance:

- Route `/auth`, `/provider`, `/backend`, `/model`, and `/cost` or accurate
  replacements.
- `/model` remains no-silent-fallback safe.
- `/auth` never prints secrets.
- `/cost` reports known cost or clearly says unavailable/stubbed.

## BG-012: Ask/Agent Chat Contract

Acceptance:

- Support `/ask <question>`, `ask <question>`, and `?text` if intended.
- Bare unknown prose remains deterministic and does not silently route to model.
- Agent mode is visible while a question is active.
- Tests cover `/ask`, `ask`, `?question`, lone `?`, and unknown prose.

## BG-013: History, Clear, Load, Resume/Pause, Story

Acceptance:

- `/history` and `/clear` work.
- `/load <specifier>` loads modules if Rust supports it or fails with a precise
  dynamic-loading-not-supported message.
- `/resume`, `/pause`, and `/story` either work or are documented as
  intentionally absent with replacements.

## BG-014: Completion And Help Parity

Acceptance:

- Completion includes slash commands, bare aliases, module IDs, tool IDs,
  option names, task IDs, finding aliases, run IDs, and config keys where state
  is available.
- Help is grouped by workflow: navigation, run/scan, options/tasks, context/KB,
  findings/evidence, auth/config/model, session.
- Drift tests fail if help advertises a command the parser does not route.

## BG-015: Plain/Non-TTY Bridge Output

Acceptance:

- Options, tasks, KB listing, context status, workspace status, and config/model
  commands have plain output or clear CLI equivalents.
- Strict plain output has no ANSI or box drawing.
- Tests cover options table, KB list, and context status in plain mode.

## BG-016: Final Bridge Gate

Acceptance:

- `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md` says no bridge gaps remain.
- `rg -n "show options|/options|/kb|/tasks|/task|/context|/auth|/cost|/history|/load" README.md crates tests`
  shows Rust docs/tests, not only legacy TS refs.
- Full checks pass.
- Commit and push the final bridge-gap state.

Record this marker in the bridge progress file only:

```text
KUZUSHI_BRIDGE_GAPS_PHASE_DONE
```

# Stage 2: Rust Terminal UX Repair And Ink Runtime Cleanup

Start only after Stage 1 is complete, committed, pushed, and recorded.

Goal: make the Rust CLI/Ratatui shell the only operator-facing CLI/TUI path,
fix rough terminal UX, and remove Ink/React from runtime CLI execution.

Inspect first:

- `package.json`
- `bin/kuzushi-rs.mjs`
- `Cargo.toml`
- `crates/kuzushi-cli/src/main.rs`
- `crates/kuzushi-core/src/config.rs`
- `crates/kuzushi-core/src/findings.rs`
- `crates/kuzushi-core/src/modules.rs`
- `crates/kuzushi-core/src/scan.rs`
- `crates/kuzushi-core/src/workspace.rs`
- `crates/kuzushi-openai/src/lib.rs`
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-tui/src/commands.rs`
- `crates/kuzushi-tui/src/renderer.rs`
- `crates/kuzushi-tui/src/theme.rs`
- `scripts/pi-agent-core-bridge.mjs`
- `tests/e2e/run-smoke.sh`
- `README.md`
- `RELEASING.md`

## UX-001: Remove Ink/React From Runtime CLI Packaging

Acceptance:

- `package.json` `bin.kuzushi` resolves to `bin/kuzushi-rs.mjs`.
- Normal CLI execution does not require Ink/React.
- `pnpm verify:pack` proves packaged CLI includes the native Rust binary.
- Retained TS is documented as reference-only, test-only, or non-CLI library.

## UX-002: Delete Or Isolate Legacy Ink UI Code

Acceptance:

- Remove no-longer-needed Ink/React UI components/tests.
- Temporarily retained TS UI is labeled legacy/reference-only and cannot be
  imported by the package CLI runtime.
- Remove unused Ink/React dependencies once no retained code needs them.

## UX-003: Fix Shell Redraw And Prompt Overlap

Acceptance:

- Command log stays directly above the prompt.
- Input, errors, and output do not overlap.
- `/exit`, `exit`, and `/exitj` render clearly.
- Prompt remains readable at 80 columns.
- Add Ratatui snapshots or renderer tests.

## UX-004: Improve Exit And Unknown Command Handling

Acceptance:

- `/exit` and `exit` are supported if intended.
- Unknown slash commands show a concise next action.
- Unknown free-form text is deterministic and not silent model chat.

## UX-005: Visible Startup Progress And First-Run Path

Acceptance:

- Bare `kuzushi` and `kuzushi shell --target .` show feedback for slow init.
- First-run state tells the user exactly how to get the first finding.
- Suggested commands are real Rust commands.

## UX-006: Rust Doctor / Preflight

Acceptance:

- `kuzushi doctor` or equivalent checks config, state dir writability, findings
  DB openability, scanner binaries, pi-agent-core bridge, and model/provider
  compatibility.
- Failures are actionable and do not corrupt workspaces.

## UX-007: Input Mode Clarity

Acceptance:

- Prompt/status shows shell, module, agent, plan, or run routing mode.
- Help documents `?`, `?text`, `/ask`, and `ask <text>` if supported.

## UX-008: Honest Abort State

Acceptance:

- Ctrl+C during subprocess or pi-agent-core work reports abort requested or
  equivalent.
- UI does not claim a process was killed unless guaranteed.

## UX-009: Slash Command Taxonomy And Drift Tests

Acceptance:

- Help is grouped into operator-friendly categories.
- Cataloged and routed commands cannot drift silently.
- Missing aliases are implemented, removed from help, or documented absent.

## UX-010: Tab Completion For High-Value Arguments

Acceptance:

- Slash commands complete by prefix.
- At least three argument contexts complete: module ids, finding aliases, run
  ids, workspace names, task ids, or config keys.

## UX-011: Findings Row/Card Density

Acceptance:

- Default rows show alias, severity, verdict, confidence, proof/static state,
  CWE, engine/source, title, location, evidence preview, and next action where
  available.
- 80-column snapshots remain readable.

## UX-012: Stable Finding Aliases

Acceptance:

- Same finding has same alias across scan, findings, open/detail, replay, and
  trace where applicable.
- Fingerprints are secondary metadata.

## UX-013: Better Empty States And Errors

Acceptance:

- No findings, no workspace, unknown module/tool, unknown task, missing scanner,
  and internal shell-state errors include the next real command.

## UX-014: Explicit Plain / Screen-Reader / Low-Bandwidth Mode

Acceptance:

- Users can force line-oriented, no-animation, no-ANSI output by flag or env.
- Piped/non-TTY output is readable.
- Strict plain output contains no ANSI escapes or box drawing.

## UX-015: Final Ink/React Removal Gate

Acceptance:

- `rg -n "ink|react" package.json src tests crates README.md RELEASING.md` has
  no runtime CLI dependency surprises.
- Package scripts, npm wrapper, e2e tests, docs, and help point at Rust CLI.
- `pnpm verify:pack` passes.
- `RALPH_RUST_UX_PROGRESS.md` lists removed TS/Ink files, retained TS files,
  and why retained files are not CLI runtime.
- Commit and push before Stage 3.

Record this marker in the UX progress file only:

```text
KUZUSHI_UX_PHASE_DONE
```

# Stage 3: Kuzushi Whitebox Static Mode

Start only after Stage 2 is complete, committed, pushed, and recorded.

Goal: add additive `whitebox-static` mode to Kuzushi. It must work with the
Rust CLI/core already migrated. It must not fork Kuzushi, remove existing
scan/triage/verify/patch capabilities, or redesign terminal UX.

The mode is:

- static-only
- no active exploitation
- no HTTP replay
- no fuzzing
- no live target scanning
- no PoC generation or execution
- no runtime exploitability claims
- source-grounded static evidence only

Reuse first:

- `context:build` output for repository inventory and file indexing.
- threat-model/Randori artifacts for assets, trust boundaries, and stories.
- X-Ray artifacts for architecture, entry points, invariants, and readiness.
- Semgrep, CodeQL, agentic SAST, taint, taint-next, systems-hunt, and Carlini
  findings as evidence inputs.
- Existing findings DB and scan-run artifact locations.
- Existing Rust pi-agent-core runtime bridge and no-silent-model-fallback
  enforcement.

Deliverables:

- `tasks/kuzushi-whitebox-static.prd.json`
- `progress/kuzushi-whitebox-static.progress.md`
- `scripts/ralph-kuzushi-whitebox-static.sh`
- `evals/kuzushi-whitebox-static/run.ts`
- `docs/kuzushi-whitebox-static.md`

Wire:

```json
"eval:kuzushi-whitebox-static": "tsx evals/kuzushi-whitebox-static/run.ts"
```

## Whitebox Hard Rules

- No active exploitation, HTTP replay, fuzzing, live scanning, PoC generation,
  or PoC execution in whitebox-static mode.
- No default Bash/shell execution tool in whitebox-static agent tools.
- No scanner subprocess should inherit credential-shaped env vars.
- No vulnerability claim may persist without verified source evidence.
- No `runtime exploitable` claim in whitebox-static mode.
- Use `statically confirmed`, `statically rejected`, or
  `needs runtime evidence`.
- If source evidence is insufficient, say so.
- Do not change terminal UX except small command/flag wiring.

## WB-001: Add Explicit Whitebox-Static Mode

Acceptance:

- A mode/preset disables verify, PoC harness, PoC execution, dynamic analysis,
  crypto behavioral testing, patching, and auto-patching within that mode.
- Test proves whitebox mode cannot enable execution proof states accidentally.

## WB-002: Remove Shell Execution From Default Whitebox Agent Tools

Acceptance:

- Default whitebox tools are read-only repo tools only.
- Test fails if Bash, shell execution, Write, or patch/edit tools appear.

## WB-003: Scrub Scanner Subprocess Environments

Acceptance:

- Semgrep and CodeQL subprocesses use scrubbed env helper or Rust equivalent.
- Dependency prefetch subprocesses use scrubbed env or are disabled offline.
- Tests prove `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and `DATABASE_URL` are
  not visible to scanner subprocesses.

## WB-004: Add Static Proof Taxonomy

Acceptance:

- Add `signal_only`, `code_cited`, `source_sink_linked`,
  `sanitizer_checked`, `statically_confirmed`, `statically_rejected`,
  `needs_runtime_evidence`.
- Whitebox findings cannot be execution-confirmed.

## WB-005: Add Static Evidence Graph

Acceptance:

- Add evidence nodes and edges.
- Node kinds: `code_span`, `scanner_signal`, `source`, `sink`,
  `dataflow_step`, `sanitizer`, `guard`, `attack_surface`, `triage_claim`,
  `report_claim`.
- Edge kinds: `supports`, `derived_from`, `flows_to`, `guarded_by`,
  `sanitized_by`, `contradicts`, `reported_as`.
- Test insert/fetch/link/hash stability.

## WB-006: Add Source Span Extractor

Acceptance:

- Given repo root, file path, start line, and end line, return snippet and hash.
- Reject traversal outside repo root.
- Tests cover valid file, missing file, binary-ish file, bad line range, and
  out-of-repo path.

## WB-007: Normalize Semgrep Findings Into Static Evidence

Acceptance:

- Each Semgrep signal creates `scanner_signal` and `code_span` evidence nodes.
- Signal links to code span.
- Semgrep signals are not true positives by default.

## WB-008: Normalize CodeQL SARIF Code Flows Into Static Evidence

Acceptance:

- CodeQL SARIF creates scanner signal, code span, and dataflow step nodes.
- Adjacent flow locations link with `flows_to` edges.
- No exploitability claim is made.

## WB-009: Build Deterministic Repository Inventory

Acceptance:

- Inventory detects languages, manifests, likely frameworks, entrypoints,
  routes/controllers, dependency manifests, config files, and generated/vendor
  paths.
- No LLM or package manager execution.
- Tests for Node, Python, Go, Rust, and mixed fixtures.

## WB-010: Build Source/Sink/Sanitizer/Guard Registry

Acceptance:

- Versioned registry with language, framework, kind, symbol/path pattern, CWE,
  and rationale.
- Matching is deterministic.
- Registry match alone is not vulnerability proof.

## WB-011: Add Attack-Surface Map From Source

Acceptance:

- Produce source-derived attack surfaces: HTTP routes, RPC handlers, CLI
  entrypoints, background jobs, deserialization points, file upload/parse paths,
  auth boundaries, DB query boundaries, and command execution boundaries.
- Start with Node/Express fixtures.
- No live app execution.

## WB-012: Add Static Proof Validator

Acceptance:

- A statically confirmed finding requires source/entrypoint evidence,
  sink/security-sensitive operation evidence, path explanation or local/direct
  reason, sanitizer/guard assessment, verified code citations, assumptions, and
  missing evidence.
- Invalid true-positive claims are downgraded to `needs_runtime_evidence` or
  `needs_review`.

## WB-013: Constrain LLM Triage To Whitebox Schema

Acceptance:

- Schema includes verdict, staticProofState, source, sink, path,
  sanitizerAssessment, guardAssessment, citations, assumptions, missingEvidence,
  triggerNarrative, impactNarrative, recommendedFix.
- Prompt forbids payloads, PoCs, exploit execution, and runtime exploitability
  claims.
- Test checks forbidden terms.

## WB-014: Verify LLM Citations Before Persistence

Acceptance:

- File exists under repo root.
- Lines exist.
- Snippet matches.
- Out-of-repo and stale citations fail.
- `statically_confirmed` cannot persist with unverified citations.

## WB-015: Prioritize Findings By Static Impact

Acceptance:

- Ranking considers attack-surface reachability, source/sink class, data
  sensitivity hint, privilege boundary, sanitizer absence, framework context,
  CodeQL flow length/quality, and confidence.
- Ranking is deterministic before LLM adjustment.
- Tests prove high-impact static-flow issue outranks generic scanner noise.

## WB-016: Add Static Trigger/Impact Narratives

Acceptance:

- Reports can include static trigger path, potential impact, and evidence
  limits.
- Test fails if narrative says `exploited`, `confirmed exploit`, or includes
  PoC payloads.

## WB-017: Add Variant Search From Statically Confirmed Findings

Acceptance:

- Derive reusable pattern from confirmed evidence.
- Search sibling files/routes/functions for same source/sink/missing-guard
  shape.
- Variants start as `signal_only` or `code_cited`, not confirmed.

## WB-018: Add Candidate Semgrep Rule Synthesis

Acceptance:

- Generate candidate rule only from statically confirmed findings.
- Validate against positive and negative fixtures.
- Candidate rules remain disabled until tests pass.

## WB-019: Add Whitebox False-Positive Memory

Acceptance:

- Suppression requires evidence, scope, reason, author, timestamp, expiration.
- Suppression invalidates if snippet hash changes.
- Suppressed findings still appear in audit/report mode.

## WB-020: Add Diff-Aware Whitebox PR Mode

Acceptance:

- Compute changed files/line ranges from `diffBase`.
- Expand context to relevant callers/callees/routes.
- Tag findings new/existing/fixed/changed-context.
- No remote git provider required.

## WB-021: Add Deterministic Eval Harness

Acceptance:

- `pnpm eval:kuzushi-whitebox-static` runs local fixtures.
- Scores detection, groundedness, proof completeness, FP rejection,
  prioritization, narrative quality, cost, and latency.
- Hard fail on shell execution, network call, PoC generation, fabricated
  citation, uncited claim, or runtime exploitability claim.

## WB-022: Add Whitebox Demo Fixture

Acceptance:

- Fixture includes one true static source-to-sink bug, one sanitized false
  positive, one needs-runtime-evidence authz case, one sibling variant, and one
  misleading scanner-noise case.
- E2E test runs inventory, scanner evidence, static triage, proof validation,
  prioritization, and report/SARIF.
- No network, shell execution, PoC, replay, or active verification.

## Whitebox PRD Requirements

`tasks/kuzushi-whitebox-static.prd.json` must include `branchName:
kuzushi-whitebox-static`, mission, nonGoals, globalInvariants,
fastGlobalChecks, slowGlobalChecks, and WB-001 through WB-022 with id, title,
priority, why, targets, acceptance, storyGate, forbidden, and `passes: false`.

## Whitebox Script Requirements

`scripts/ralph-kuzushi-whitebox-static.sh` must:

- Read `tasks/kuzushi-whitebox-static.prd.json`.
- Read `progress/kuzushi-whitebox-static.progress.md`.
- Pick the first incomplete story by priority.
- Write `.ralph/current-kuzushi-whitebox-static-prompt.md`.
- Invoke the coding agent via `AI_CMD_BIN` and `AI_CMD_ARGS`.
- Run the story gate and fast global checks.
- Run `pnpm eval:kuzushi-whitebox-static` if present.
- Mark `passes: true` only after gates pass.
- Append progress.
- Commit with message `ralph:whitebox-static complete <story-id> - <story-title>`.
- Push after the commit.

## Whitebox Eval Requirements

`evals/kuzushi-whitebox-static/run.ts` can start as a deterministic stub with
fixture checks. It must define hard failures:

- `shell_tool_call`
- `network_call`
- `poc_generation`
- `fabricated_citation`
- `uncited_claim`
- `runtime_exploitability_claim`

## Whitebox Docs Requirements

`docs/kuzushi-whitebox-static.md` must explain:

- whitebox mode is static-only
- zero-harness repo ingest
- attack-surface map
- source-grounded static proof
- prioritized high-impact findings
- trigger/impact narratives
- static evidence limits
- runtime exploitability is not assessed in whitebox mode

# Final Acceptance

The whole finish loop is done only when:

- Stage 1 bridge gaps are complete, committed, pushed, and recorded.
- Stage 2 UX/Ink cleanup is complete, committed, pushed, and recorded.
- Stage 3 whitebox-static is complete, committed, pushed, and recorded.
- Full checks pass.
- The final response includes the final pushed commit SHA and verification
  summary.

Only then emit:

```text
<promise>KUZUSHI_FINISH_FROM_BRIDGE_COMPLETE</promise>
```

# Suggested Ralph Command

Run this from the repo root. Do not add `--tasks`.

```sh
cd /Users/operator/VibeCode/open-sourced/kuzushi

RALPH_CODEX_ARGS='-c model=gpt-5.5 -c model_reasoning_effort=xhigh' \
ralph \
  --prompt-file ./ralph-kuzushi-finish-from-bridge.md \
  --agent codex \
  --model gpt-5.5 \
  --completion-promise KUZUSHI_FINISH_FROM_BRIDGE_COMPLETE \
  --max-iterations 80
```
