# Ralph Loop Prompt: Kuzushi Post-Migration Work

You are working in `/Users/operator/VibeCode/open-sourced/kuzushi`.

Kuzushi is an open-source AI cybersecurity copilot. The Rust/pi-agent-core migration is already complete and pushed on branch `incoming-changes` at commit `f17dc699859d2e618c3452ff3c20c2b907a12d80`.

Do not restart the migration inventory loop. Do not port TypeScript modules again. Treat the current Rust workspace, npm wrapper, and `docs/rust-migration-status.md` as ground truth.

This prompt drives only the remaining post-migration work:

1. Rust Terminal UX Repair and final Ink/React CLI removal.
2. Kuzushi Rust Whitebox Static Mode.

Run those phases in that order. Do not start whitebox-static work until the Rust UX/Ink-removal phase is committed and pushed.

## Ralph Rules

Each iteration must:

1. Inspect the repo and current git status.
2. Read or create the relevant progress file:
   - `RALPH_RUST_UX_PROGRESS.md` for Phase 1.
   - `progress/kuzushi-whitebox-static.progress.md` for Phase 2.
3. Pick the highest-priority incomplete task in the active phase.
4. Implement one coherent slice, not a broad rewrite.
5. Add or update focused tests/snapshots where feasible.
6. Run the smallest relevant checks, then broader checks if practical.
7. Commit only after checks pass.
8. Push the branch after each successful commit.
9. Update the progress file with:
   - task attempted
   - files changed
   - tests/checks run
   - result
   - remaining work
   - blockers or repo facts that contradicted this prompt

Do not emit a final completion promise until both phases are complete, checks pass, progress files say there is no remaining work, and all commits are pushed.

Final marker, only after both phases are fully complete:

```text
<promise>KUZUSHI_POST_MIGRATION_COMPLETE</promise>
```

If any work remains, summarize the next exact task and continue later. Do not use the old generic migration completion marker.

## Global Guardrails

- Rust is the primary product path.
- `bin/kuzushi-rs.mjs` and the Rust binary must remain the package CLI path.
- Do not reintroduce Ink/React into the primary CLI.
- Do not weaken runtime/model enforcement or no-silent-fallback behavior.
- Do not remove existing commands without aliases, docs updates, and tests.
- Do not break scan/shell/run parity.
- Do not break non-TTY, CI, or piped output.
- Do not introduce network-only dependencies for terminal UX.
- Do not call external services in tests.
- Preserve existing `.kuzushi` state/artifact compatibility unless a task explicitly changes it and records the compatibility decision.
- Keep each iteration small enough to review.

## Required Baseline Checks

Use focused checks for each story. Before declaring a phase complete, run:

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

`pnpm check` may report existing warnings while still exiting successfully. Treat the exit code as the gate unless the active task is specifically cleaning those warnings.

# Phase 1: Rust Terminal UX Repair And Ink Removal

Start here. Do not begin Phase 2 until this phase is complete, committed, and pushed.

## Phase 1 Goal

Make the Rust CLI/Ratatui shell the only operator-facing CLI/TUI path, fix the rough terminal UX issues discovered after migration, and remove Ink/React from runtime CLI execution.

The product is for security operators: pentesters, blue-team engineers, AppSec reviewers, and compliance auditors. They live in terminals, tolerate density, and have low tolerance for ambiguity, cute copy, dead air, hidden modes, or broken redraw behavior.

Primary Rust surfaces:

- `kuzushi`
- `kuzushi shell --target .`
- `kuzushi scan .`
- `kuzushi run <tool>`
- `kuzushi findings`
- `kuzushi modules`
- `kuzushi tools`
- `kuzushi config`

Legacy TypeScript/Ink files may be read as reference only. They must not remain required for the package CLI runtime.

## Phase 1 Files To Inspect First

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
- Rust integration tests under `crates/kuzushi-cli/tests/`
- `README.md`
- `RELEASING.md`

Legacy reference-only areas, if still present:

- `src/copilot/shell.ts`
- `src/copilot/shell-commands.ts`
- `src/ui/`
- `tests/ui/`
- Ink/React dependencies in `package.json`

## Phase 1 Tasks

### UX-001: Remove Ink/React From Runtime CLI Packaging

Acceptance:

- `package.json` `bin.kuzushi` resolves to `bin/kuzushi-rs.mjs`.
- The npm package does not require Ink/React for normal CLI execution.
- `pnpm verify:pack` proves the packaged CLI includes the native Rust binary.
- Retained TypeScript, if any, is documented as reference-only, test-only, or non-CLI library code.
- README and release notes do not advertise Ink as the current CLI runtime.

### UX-002: Delete Or Isolate Legacy Ink UI Code

Acceptance:

- Remove Ink/React UI components and tests that are no longer needed.
- If TypeScript UI files must remain temporarily, move or label them as legacy/reference-only and ensure package runtime cannot import them from the CLI path.
- Remove unused Ink/React dependencies once no retained code needs them.
- Update tests and package files accordingly.

### UX-003: Fix Shell Redraw And Prompt Overlap

Problem examples:

- Command output can collide with the prompt line.
- Errors such as unknown commands can leave stale prompt text on-screen.
- The command log/status area can feel cramped or visually ambiguous.

Acceptance:

- Command log stays directly above the prompt.
- User input, errors, and command output do not overlap.
- `/exit`, `exit`, and accidental nearby typos such as `/exitj` render clearly.
- Prompt remains readable at 80 columns.
- Add Ratatui buffer snapshots or renderer tests.

### UX-004: Improve Exit And Unknown Command Handling

Acceptance:

- `/exit` and `exit` are both supported if the shell already intends both.
- Unknown slash commands show a concise next action.
- Unknown free-form text is deterministic and does not silently become model chat.
- Error copy fits 80 columns and does not produce redraw artifacts.

### UX-005: Visible Startup Progress And First-Run Path

Acceptance:

- Bare `kuzushi` and `kuzushi shell --target .` show immediate feedback if initialization takes more than about 500ms.
- First-run state tells the user exactly how to get the first finding.
- Suggested commands are real Rust commands.
- No noisy onboarding for established workspaces.

### UX-006: Rust Doctor / Preflight

Acceptance:

- `kuzushi doctor` or the closest Rust command checks config loading, state directory writability, findings DB openability, scanner binaries, pi-agent-core bridge availability, and model/provider compatibility.
- Failures are actionable.
- Existing workspaces are not corrupted.

### UX-007: Input Mode Clarity

Acceptance:

- Prompt or status line makes routing mode obvious: shell, module, agent, plan, or run.
- Focused module prompt remains readable.
- Help documents `?`, `?text`, `/ask`, and `ask <text>` behavior if supported.

### UX-008: Honest Abort State

Acceptance:

- Ctrl+C during subprocess or pi-agent-core work reports `abort requested` or equivalent.
- UI does not claim a subprocess is killed unless the code guarantees it.
- Subprocess-backed executors preserve cancellation tests.

### UX-009: Slash Command Taxonomy And Drift Tests

Acceptance:

- Help is grouped into operator-friendly categories.
- Cataloged commands and routed commands cannot drift silently.
- Missing aliases are either implemented, removed from help, or documented as intentionally absent.

### UX-010: Tab Completion For High-Value Arguments

Acceptance:

- Slash commands still complete by prefix.
- At least three argument contexts complete: module ids after `use`, finding aliases after `open`, run ids after `replay` or `trace`, workspace names, task ids, or config keys.
- Completion remains fast and tested where separable.

### UX-011: Findings Row/Card Density

Acceptance:

- Default finding rows show stable alias, severity, verdict, confidence, proof/static state if available, CWE if available, engine/source, title, location, evidence preview, and next action.
- Findings without optional fields render cleanly.
- Severity is not communicated by color alone.
- 80-column snapshots remain readable.

### UX-012: Stable Finding Aliases

Acceptance:

- The same finding has the same alias across live scan, findings list, open/detail, replay, and trace where applicable.
- Raw fingerprints remain secondary metadata.
- Collision handling does not break primary display.

### UX-013: Better Empty States And Errors

Acceptance:

- No findings, no workspace, unknown module/tool, unknown task, missing scanner, and internal shell-state errors all include the next real command.
- Empty states remain concise and readable under `NO_COLOR`.

### UX-014: Explicit Plain / Screen-Reader / Low-Bandwidth Mode

Acceptance:

- Users can force line-oriented, no-animation, no-ANSI output through a flag or environment variable.
- Piped/non-TTY output remains readable.
- Strict plain output contains no ANSI escapes or box drawing.

### UX-015: Final Ink/React Removal Gate

Acceptance:

- `rg -n "ink|react" package.json src tests crates README.md RELEASING.md` has no runtime CLI dependency surprises.
- Package scripts, npm wrapper, e2e tests, docs, and help all point at the Rust CLI.
- `pnpm verify:pack` passes.
- `RALPH_RUST_UX_PROGRESS.md` contains a deletion/retention list:
  - TS/Ink files removed
  - TS files intentionally retained
  - why each retained file is not part of the CLI runtime
- Commit and push the Phase 1 result before starting Phase 2.

Phase 1 completion marker to record inside the progress file only:

```text
KUZUSHI_UX_PHASE_DONE
```

Do not emit a promise tag for Phase 1; Ralph should continue to Phase 2 only after the pushed commit is recorded.

# Phase 2: Kuzushi Rust Whitebox Static Mode

Start only after Phase 1 is complete, committed, pushed, and recorded in `RALPH_RUST_UX_PROGRESS.md`.

Do not call this work by any competitor name. The product name is Kuzushi and the feature name is `whitebox-static`.

## Phase 2 Goal

Add an additive whitebox static-analysis mode to Kuzushi. It must work with the Rust CLI/core already migrated. It must not fork Kuzushi into a separate analyzer, remove existing scan/triage/verify/patch capabilities, or redesign the terminal UI.

The target mode is:

- static-only
- no active exploitation
- no HTTP replay
- no fuzzing
- no live target scanning
- no PoC generation or execution
- no runtime exploitability claims
- source-grounded static evidence only

The mode should help Kuzushi move from scanner signals plus agent triage toward:

- zero-harness repository ingest
- source-defined attack-surface mapping
- source-grounded evidence normalization
- high-impact issue prioritization
- business-logic and security-invariant reasoning
- trigger and impact narratives with verified file:line citations
- fewer, stronger findings

## Phase 2 Reuse Rules

Before adding new whitebox-static code, first look for an existing Rust capability to reuse or extend:

- Use `context:build` output for repository inventory and file indexing.
- Use threat-model/Randori artifacts for assets, trust boundaries, and attacker stories.
- Use X-Ray artifacts for architecture, entry points, invariants, or project-readiness context.
- Use Semgrep, CodeQL, agentic SAST, taint, taint-next, systems-hunt, and Carlini findings as inputs to evidence normalization.
- Use the existing findings DB and scan-run artifact locations.
- Use pi-agent-core only through the existing Rust runtime bridge and no-silent-model-fallback enforcement.

Do not duplicate context, Randori, threat-model, X-Ray, taint/CWE selection, scanner normalization, or findings persistence unless a story proves the current implementation cannot support the requirement.

## Phase 2 Deliverables

Create and maintain:

- `tasks/kuzushi-whitebox-static.prd.json`
- `progress/kuzushi-whitebox-static.progress.md`
- `scripts/ralph-kuzushi-whitebox-static.sh`
- `evals/kuzushi-whitebox-static/run.ts`
- `docs/kuzushi-whitebox-static.md`

Wire the eval in `package.json` as:

```json
"eval:kuzushi-whitebox-static": "tsx evals/kuzushi-whitebox-static/run.ts"
```

## Phase 2 Hard Rules

- No active exploitation.
- No HTTP replay.
- No fuzzing.
- No live target scanning.
- No PoC generation or execution in whitebox-static mode.
- No default Bash/shell execution tool in whitebox-static agent tools.
- No scanner subprocess should inherit credential-shaped environment variables.
- No vulnerability claim may persist unless it has verified source evidence.
- No `runtime exploitable` claim in whitebox-static mode.
- Use `statically confirmed`, `statically rejected`, or `needs runtime evidence`.
- If source evidence is insufficient, say so.
- Do not change the terminal UX in this phase except for small wiring needed to expose an existing command/flag.

## Phase 2 Stories

Create `tasks/kuzushi-whitebox-static.prd.json` with `branchName: kuzushi-whitebox-static`, mission, nonGoals, globalInvariants, fastGlobalChecks, slowGlobalChecks, and these stories. Each story must include id, title, priority, why, targets, acceptance, storyGate, forbidden, and `passes: false`.

### WB-001: Add Explicit Whitebox-Static Mode

Acceptance:

- A mode/preset exists that disables verify, PoC harness, PoC execution, dynamic analysis, crypto behavioral testing, patching, and auto-patching within that mode.
- Test proves whitebox mode cannot enable execution proof states accidentally.

### WB-002: Remove Shell Execution From Default Whitebox Agent Tools

Acceptance:

- Default whitebox shell/agent tools include read-only repo tools only.
- Test fails if Bash, shell execution, Write, or patch/edit tools appear in whitebox default tools.

### WB-003: Scrub Scanner Subprocess Environments

Acceptance:

- Semgrep and CodeQL subprocesses use the existing scrubbed-env helper or an equivalent Rust helper.
- Dependency prefetch subprocesses either use scrubbed env or are disabled in offline whitebox mode.
- Tests prove `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and `DATABASE_URL` are not visible to scanner subprocesses.

### WB-004: Add Static Proof Taxonomy

Acceptance:

- Add static proof states: `signal_only`, `code_cited`, `source_sink_linked`, `sanitizer_checked`, `statically_confirmed`, `statically_rejected`, `needs_runtime_evidence`.
- Whitebox findings cannot be marked execution-confirmed.

### WB-005: Add Static Evidence Graph

Acceptance:

- Add static evidence nodes and edges.
- Node kinds: `code_span`, `scanner_signal`, `source`, `sink`, `dataflow_step`, `sanitizer`, `guard`, `attack_surface`, `triage_claim`, `report_claim`.
- Edge kinds: `supports`, `derived_from`, `flows_to`, `guarded_by`, `sanitized_by`, `contradicts`, `reported_as`.
- Test insert/fetch/link/hash stability.

### WB-006: Add Source Span Extractor

Acceptance:

- Given repo root, file path, start line, and end line, return snippet and hash.
- Reject path traversal outside repo root.
- Tests cover valid file, missing file, binary-ish file, bad line range, and out-of-repo path.

### WB-007: Normalize Semgrep Findings Into Static Evidence

Acceptance:

- Each Semgrep signal creates `scanner_signal` and `code_span` evidence nodes.
- Signal links to code span.
- Semgrep signals are not true positives by default.

### WB-008: Normalize CodeQL SARIF Code Flows Into Static Evidence

Acceptance:

- CodeQL SARIF creates scanner signal, code span, and dataflow step nodes.
- Adjacent flow locations link with `flows_to` edges.
- No exploitability claim is made.

### WB-009: Build Deterministic Repository Inventory

Acceptance:

- Inventory detects languages, manifests, likely frameworks, entrypoints, routes/controllers, dependency manifests, config files, and generated/vendor paths.
- No LLM.
- No package manager execution.
- Tests for Node, Python, Go, Rust, and mixed fixtures.

### WB-010: Build Source/Sink/Sanitizer/Guard Registry

Acceptance:

- Versioned registry with language, framework, kind, symbol/path pattern, CWE, and rationale.
- Matching is deterministic.
- Registry match alone is not vulnerability proof.

### WB-011: Add Attack-Surface Map From Source

Acceptance:

- For supported frameworks, produce source-derived attack surfaces: HTTP routes, RPC handlers, CLI entrypoints, background jobs, deserialization points, file upload/parse paths, auth boundaries, DB query boundaries, and command execution boundaries.
- Start with Node/Express fixtures.
- No live app execution.

### WB-012: Add Static Proof Validator

Acceptance:

- A statically confirmed finding requires source/entrypoint evidence, sink/security-sensitive operation evidence, propagation/path explanation or local/direct reason, sanitizer/guard assessment, verified code citations, assumptions, and missing evidence.
- Invalid true-positive claims are downgraded to `needs_runtime_evidence` or `needs_review`.

### WB-013: Constrain LLM Triage To Whitebox Schema

Acceptance:

- Schema includes verdict, staticProofState, source, sink, path, sanitizerAssessment, guardAssessment, citations, assumptions, missingEvidence, triggerNarrative, impactNarrative, recommendedFix.
- Prompt forbids payloads, PoCs, exploit execution, and runtime exploitability claims.
- Test checks forbidden terms.

### WB-014: Verify LLM Citations Before Persistence

Acceptance:

- File exists under repo root.
- Lines exist.
- Snippet matches.
- Out-of-repo and stale citations fail.
- `statically_confirmed` cannot persist with unverified citations.

### WB-015: Prioritize Findings By Static Impact

Acceptance:

- Ranking considers attack-surface reachability, source/sink class, data sensitivity hint, privilege boundary, sanitizer absence, framework context, CodeQL flow length/quality, and confidence.
- Ranking is deterministic before LLM adjustment.
- Tests prove a high-impact static-flow issue outranks generic scanner noise.

### WB-016: Add Static Trigger/Impact Narratives

Acceptance:

- Each report can include static trigger path, potential impact, and evidence limits.
- Test fails if narrative says `exploited`, `confirmed exploit`, or includes PoC payloads.

### WB-017: Add Variant Search From Statically Confirmed Findings

Acceptance:

- Derive reusable pattern from confirmed evidence.
- Search sibling files/routes/functions for the same source/sink/missing-guard shape.
- Variants start as `signal_only` or `code_cited`, not confirmed.

### WB-018: Add Candidate Semgrep Rule Synthesis

Acceptance:

- Generate candidate rule only from statically confirmed findings.
- Validate against positive and negative fixtures.
- Candidate rules remain disabled until tests pass.

### WB-019: Add Whitebox False-Positive Memory

Acceptance:

- Suppression requires evidence, scope, reason, author, timestamp, and expiration.
- Suppression invalidates if snippet hash changes.
- Suppressed findings still appear in audit/report mode.

### WB-020: Add Diff-Aware Whitebox PR Mode

Acceptance:

- Compute changed files/line ranges from `diffBase`.
- Expand context to relevant callers/callees/routes.
- Tag findings as new, existing, fixed, or changed-context.
- No remote git provider required.

### WB-021: Add Deterministic Eval Harness

Acceptance:

- `pnpm eval:kuzushi-whitebox-static` runs local fixtures.
- Scores detection, groundedness, proof completeness, false-positive rejection, prioritization, narrative quality, cost, and latency.
- Hard fail on shell execution, network call, PoC generation, fabricated citation, uncited claim, or runtime exploitability claim.

### WB-022: Add Whitebox Demo Fixture

Acceptance:

- Fixture includes one true static source-to-sink bug, one sanitized false positive, one needs-runtime-evidence authz case, one sibling variant, and one misleading scanner-noise case.
- E2E test runs inventory, scanner evidence, static triage, proof validation, prioritization, and report/SARIF.
- No network, shell execution, PoC, replay, or active verification.

## Phase 2 Script Requirements

`scripts/ralph-kuzushi-whitebox-static.sh` must:

- Read `tasks/kuzushi-whitebox-static.prd.json`.
- Read `progress/kuzushi-whitebox-static.progress.md`.
- Pick the first incomplete story by priority.
- Write `.ralph/current-kuzushi-whitebox-static-prompt.md`.
- Invoke the coding agent via `AI_CMD_BIN` and `AI_CMD_ARGS`.
- Run the story gate.
- Run fast global checks.
- Run `pnpm eval:kuzushi-whitebox-static` if present.
- Mark `passes: true` only after gates pass.
- Append progress.
- Commit with message `ralph:whitebox-static complete <story-id> - <story-title>`.
- Push after the commit.

## Phase 2 Eval Requirements

`evals/kuzushi-whitebox-static/run.ts` can start as a deterministic stub with fixture checks. It must define hard failures:

- `shell_tool_call`
- `network_call`
- `poc_generation`
- `fabricated_citation`
- `uncited_claim`
- `runtime_exploitability_claim`

## Phase 2 Docs Requirements

`docs/kuzushi-whitebox-static.md` must explain:

- whitebox mode is static-only
- zero-harness repo ingest
- attack-surface map
- source-grounded static proof
- prioritized high-impact findings
- trigger/impact narratives
- static evidence limits
- runtime exploitability is not assessed in whitebox mode

## Final Acceptance

The whole post-migration loop is done only when:

- Phase 1 UX/Ink cleanup is complete, committed, and pushed.
- Phase 2 whitebox-static is complete, committed, and pushed.
- Relevant full checks pass.
- `RALPH_RUST_UX_PROGRESS.md` says no UX work remains.
- `progress/kuzushi-whitebox-static.progress.md` says no whitebox work remains.
- The final response includes the final pushed commit SHA and verification summary.

Only then emit:

```text
<promise>KUZUSHI_POST_MIGRATION_COMPLETE</promise>
```

