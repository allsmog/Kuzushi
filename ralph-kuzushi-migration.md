# Ralph Loop Prompt: Kuzushi Post-Migration Work

You are working in `/Users/operator/VibeCode/open-sourced/kuzushi`.

The Rust/pi-agent-core migration has already been completed and recorded in `docs/rust-migration-status.md`. Do not restart the migration inventory loop. Treat the current Rust workspace, npm wrapper, and migration status doc as ground truth.

This prompt now drives only post-migration work:
- Rust Terminal UX Repair and final Ink/React CLI removal.
- Kuzushi Rust Whitebox Static Mode after the UX/cutover leg is complete.

Use small, reviewable Ralph iterations. Each iteration must inspect the repo, update the relevant progress file, run focused checks, and commit only after checks pass.

---

# Post-Migration Commit/Push Gate

Before starting any post-migration leg, including the Kuzushi whitebox-static analyzer work or the terminal UX repair work:
- Run the full migration acceptance checks.
- Commit the completed migration work with a clear commit message.
- Push the branch.
- Record the commit SHA and push target in the relevant progress file.

Do not start post-migration work on top of uncommitted migration changes. If the branch cannot be pushed, stop, record the blocker, and output `<promise>CONTINUE</promise>`.

---

# Post-Migration Work Order

Run post-migration work in this order unless the operator explicitly changes the priority:

1. Complete Rust Terminal UX Repair, including final Ink/React CLI removal and npm-wrapper verification.
2. Commit and push the UX/cutover cleanup.
3. Start Kuzushi Rust Whitebox Static Mode only after the UX/cutover progress file says there is no remaining Ink/React runtime path and the pushed commit SHA is recorded.

If this prompt presents the whitebox-static section before the UX section, treat that as document layout only. Do not start whitebox-static stories until the Rust UX/Ink-removal leg is complete.

---

# Post-Migration Ralph Backlog: Kuzushi Rust Whitebox Static Mode

Start this section only after the Rust/pi-agent-core migration is complete, the completed migration branch has been committed and pushed, and the Rust Terminal UX Repair / Ink-removal leg is complete.

Do not let this whitebox-static work distract from unfinished module migration. If any migration blocker remains, output `<promise>CONTINUE</promise>` and finish the migration first.

Do not start this section while any TypeScript/Ink CLI runtime path is still advertised, selected by the npm wrapper, or required by shell/scan/run e2e tests. Record the blocking Rust UX/cutover task in `RALPH_RUST_UX_PROGRESS.md` and output `<promise>CONTINUE</promise>` instead.

This section is additive and non-destructive. It must work with the Rust Kuzushi that was just migrated. It must not fork the product into a separate analyzer, remove existing scan/triage/verify/patch capabilities, or redesign the terminal UI/UX. It may add a mode/preset and backend evidence model, but existing default behavior must keep working unless an explicit story says otherwise and tests cover the compatibility path.

## Whitebox-Static Mission

Add a deep whitebox static-analysis mode to Kuzushi, using the existing Rust CLI/core as the implementation path.

Kuzushi after migration has scanner signals, Rust scan orchestration, findings persistence, pi-agent-core adjudication, verification, patching, shell workflows, and module executors. The whitebox-static target is not “add more scanners.” The gap is:
- zero-harness whole-repo understanding
- source-defined attack-surface mapping
- high-impact issue prioritization
- business-logic and security-invariant reasoning
- source-grounded trigger and impact narratives
- fewer, stronger findings
- large-codebase orchestration

The target mode is not active exploitation, HTTP replay, fuzzing, a pentest agent, PoC generation, PoC execution, or live target scanning. Those existing Kuzushi capabilities, if present outside whitebox-static mode, should not be deleted or degraded by this work.

The target is an additive whitebox-static mode inside Kuzushi that can ingest arbitrary repos with minimal setup, map source-defined attack surfaces, normalize scanner/code-flow signals into evidence, use LLMs only to adjudicate source-grounded facts, prioritize high-impact business/security logic issues, and emit trigger/impact narratives with verified file:line evidence.

## Whitebox-Static Non-Divergence Rules

- Build this as a Kuzushi mode/preset, not a separate product, binary, shell, or UI.
- Reuse existing Rust module dispatch, scan orchestration, findings persistence, config loading, pi-agent-core runtime, and Ratatui shell state.
- Do not change the default shell layout, prompt, catalog, command taxonomy, or finding card UX in this section. Terminal UX changes belong only to the later Rust Terminal UX Repair backlog.
- Do not remove or disable existing non-whitebox features such as verify, patch, PoC-related surfaces, or dynamic-related surfaces globally. Whitebox-static mode may disable them only within that mode.
- Do not rewrite working scanner/triage/runtime plumbing. Add small adapters, data structures, and mode gates around the existing Rust core.
- Do not add a new web UI, marketing site, workspace browser, or standalone report viewer in this section.
- Preserve backward-compatible CLI behavior. New flags or presets must be opt-in unless a migration acceptance criterion already made them default.
- Preserve existing persisted findings and scan artifacts. Add whitebox evidence tables/fields in a compatible way.
- If a story appears to require UI/UX redesign, record the conflict and implement the backend prerequisite instead.

## Whitebox-Static Integration Shape

Prefer this implementation shape:
- `kuzushi scan <target> --mode whitebox-static` or the closest existing Rust CLI style.
- `kuzushi run sast:scan --input '{"mode":"whitebox-static"}'` for tool-dispatch parity.
- Optional shell invocation through existing `/scan` or `/run`, with no new major view.
- Core mode/config model in `kuzushi-core`, not in the TUI.
- Evidence graph and proof taxonomy stored alongside the existing Rust findings DB, not in a separate database.
- Reports should augment current findings/report outputs; they should not replace normal findings review.

## Reuse Existing Kuzushi Intelligence

Before adding new whitebox-static code, first look for an existing Rust capability to reuse or extend:
- Use `context:build` output for repository inventory and file indexing instead of creating a parallel context system.
- Use threat-model/Randori artifacts when business context, assets, trust boundaries, or attacker stories are needed.
- Use X-Ray artifacts when architecture, entry points, invariants, or project-readiness context is needed.
- Use existing Semgrep, CodeQL, agentic SAST, taint, taint-next, systems-hunt, and Carlini findings as inputs to whitebox evidence normalization.
- Use the existing findings DB and scan-run artifact locations. Add compatible evidence tables/fields only when the current schema cannot represent the data.
- Use pi-agent-core only through the existing Rust runtime bridge and no-silent-model-fallback enforcement.

Do not duplicate `context`, `randori`, `threat-model`, `x-ray`, taint/CWE selection, scanner normalization, or findings persistence unless a story proves the existing implementation cannot support the requirement. Prefer small extensions to existing modules over new parallel modules.

## Whitebox-Static Rust Grounding

Preserve and build on the Rust implementation created by the migration:
- Rust scan engines and `ScanEngine` composition in `crates/kuzushi-core/src/scan.rs`.
- Native context/inventory behavior in `crates/kuzushi-core/src/modules.rs` and related core files.
- Findings persistence and triage storage in `crates/kuzushi-core/src/findings.rs`.
- pi-agent-core bridge/runtime in `crates/kuzushi-openai/src/lib.rs` and `scripts/pi-agent-core-bridge.mjs`.
- Rust shell/run/scan dispatch through `crates/kuzushi-cli/src/main.rs` and `crates/kuzushi-tui/src/app.rs`.
- Existing Rust module executors for Semgrep, CodeQL, agentic SAST, triage, verify, patch, threat model, x-ray, taint, and systems hunting after migration.

Legacy TypeScript references may be read only to preserve product intent and schema semantics. Do not implement this mode in TypeScript. Do not reintroduce Ink/React into the primary path.

Important legacy evidence to re-check against the current repo before using it:
- Semgrep triage previously asked the agent to inspect callers, sources, sinks, validators, sanitizers, guards, reachability, and false positives.
- CodeQL parsing previously extracted structured code-flow paths and symbolic proof states.
- Schemas previously supported code citations and rich triage fields.
- Legacy contracts over-emphasized execution/dynamic/PoC proof states.
- Legacy scanner subprocesses and shell tools had credential-environment risks.
- Existing env-scrubbing helpers, if still retained, explain why credential-shaped env vars must not leak to subprocesses.

If line numbers or files changed during the Rust migration, treat current Rust code as ground truth and record the mismatch in `progress/kuzushi-whitebox-static.progress.md`.

## Whitebox-Static Deliverables

Create and maintain:
- `tasks/kuzushi-whitebox-static.prd.json`
- `progress/kuzushi-whitebox-static.progress.md`
- `scripts/ralph-kuzushi-whitebox-static.sh`
- `evals/kuzushi-whitebox-static/run.ts`
- `docs/kuzushi-whitebox-static.md`

Use Rust for product implementation:
- `crates/kuzushi-core/src/*` for core data model, evidence graph, inventory, proof validation, prioritization, and module/tool executors.
- `crates/kuzushi-cli/src/main.rs` for CLI modes/options.
- `crates/kuzushi-tui/src/*` only for minimal display of existing state if needed; do not redesign UI/UX here.
- `crates/kuzushi-openai/src/lib.rs` only for pi-agent-core bridge behavior.

The TypeScript eval harness is allowed only as a deterministic local test runner. It must invoke local fixtures and/or the Rust binary; it must not become product logic.

After creating the files, implement only `WB-001` if it is straightforward. Do not implement multiple whitebox-static stories in the same first iteration.

## Whitebox-Static Hard Product Rules

- Additive mode only; no product fork.
- No UI/UX redesign in this section.
- No global removal of existing Kuzushi capabilities.
- No active exploitation.
- No HTTP replay.
- No fuzzing.
- No live target scanning.
- No PoC generation or execution in whitebox-static mode.
- No default agent Bash.
- No scanner subprocess should inherit credential-shaped environment variables.
- No vulnerability claim may persist unless it has verified source evidence.
- No `runtime exploitable` claim in whitebox-static mode.
- Use `statically confirmed`, `statically rejected`, or `needs runtime evidence`.
- If source evidence is insufficient, say so.
- Do not call external services in evals or fixtures.
- Do not use real credentials.

## Whitebox-Static Ralph Loop Behavior

Each iteration must:
1. Confirm the migration commit has been pushed. If not, stop.
2. Read `tasks/kuzushi-whitebox-static.prd.json`.
3. Read `progress/kuzushi-whitebox-static.progress.md`.
4. Pick the first incomplete story by priority.
5. Implement only that story.
6. Add focused Rust tests and deterministic eval checks.
7. Run the story gate.
8. Run fast global checks.
9. Append progress.
10. Mark the story `passes: true` only after gates pass.
11. Commit only after checks pass.

Commit message format:

```text
ralph:whitebox-static complete <story-id> - <story-title>
```

Do not output `<promise>KUZUSHI_WHITEBOX_STATIC_COMPLETE</promise>` until all WB stories pass, the eval passes, relevant full checks pass, and `progress/kuzushi-whitebox-static.progress.md` says there is no remaining work.

## Whitebox-Static PRD Requirements

`tasks/kuzushi-whitebox-static.prd.json` must include:
- `branchName`: `kuzushi-whitebox-static`
- `mission`
- `nonGoals`
- `globalInvariants`
- `fastGlobalChecks`
- `slowGlobalChecks`
- `userStories`

Fast global checks:
- `cargo fmt --all`
- `cargo test --workspace`
- `cargo build --workspace`
- `pnpm check` if it exists
- `pnpm typecheck` if it exists
- `pnpm build` if it exists

Slow global checks:
- `pnpm test` if it exists
- `pnpm check:circular` if it exists
- `pnpm complexity:logic` if it exists
- `pnpm benchmark:regression` if it exists
- `pnpm eval:kuzushi-whitebox-static`

Each story must include:
- `id`
- `title`
- `priority`
- `why`
- `targets`
- `acceptance`
- `storyGate`
- `forbidden`
- `passes: false`

## Whitebox-Static Stories

### WB-001: Add Explicit Whitebox-Static Mode

Acceptance:
- A Rust mode/preset exists that disables verify, PoC harness, PoC execution, dynamic analysis, crypto behavioral testing, patching, and auto-patching.
- Test proves whitebox mode cannot enable execution proof states accidentally.
- `kuzushi scan` and relevant `kuzushi run` paths can opt into the mode without changing default migration behavior.

### WB-002: Remove Bash From Default Whitebox Agent Tools

Acceptance:
- Default whitebox shell/agent tools include read-only repo tools only.
- Test fails if Bash, shell execution, Write, or patch/edit tools appear in whitebox default tools.

### WB-003: Scrub Scanner Subprocess Environments

Acceptance:
- Rust Semgrep subprocess uses a credential-scrubbed environment.
- Rust CodeQL subprocess uses a credential-scrubbed environment.
- Any Go/dependency prefetch subprocess either uses the scrubbed env or is disabled in offline whitebox mode.
- Tests prove `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and `DATABASE_URL` are not visible to scanner subprocesses.

### WB-004: Add Static Proof Taxonomy

Acceptance:
- Add `StaticProofState`:
  - `signal_only`
  - `code_cited`
  - `source_sink_linked`
  - `sanitizer_checked`
  - `statically_confirmed`
  - `statically_rejected`
  - `needs_runtime_evidence`
- Whitebox findings cannot be marked `execution_confirmed`.

### WB-005: Add Static Evidence Graph

Acceptance:
- Add `static_evidence_nodes` and `static_evidence_edges`.
- Node kinds:
  - `code_span`
  - `scanner_signal`
  - `source`
  - `sink`
  - `dataflow_step`
  - `sanitizer`
  - `guard`
  - `attack_surface`
  - `triage_claim`
  - `report_claim`
- Edge kinds:
  - `supports`
  - `derived_from`
  - `flows_to`
  - `guarded_by`
  - `sanitized_by`
  - `contradicts`
  - `reported_as`
- Tests cover insert/fetch/link/hash stability.

### WB-006: Add Source Span Extractor

Acceptance:
- Given `repoRoot`, `filePath`, `startLine`, and `endLine`, return snippet and hash.
- Reject path traversal outside repo root.
- Tests cover valid file, missing file, binary-ish file, bad line range, and out-of-repo path.

### WB-007: Normalize Semgrep Findings Into Static Evidence

Acceptance:
- Each Semgrep signal creates `scanner_signal` and `code_span` evidence nodes.
- Signal links to code span.
- Semgrep signals are not true positives by default.

### WB-008: Normalize CodeQL SARIF Code Flows Into Static Evidence

Acceptance:
- CodeQL SARIF result creates `scanner_signal`, `code_span`, and `dataflow_step` nodes.
- Adjacent CodeQL flow locations link with `flows_to` edges.
- No exploitability claim is made.

### WB-009: Build Deterministic Repository Inventory

Acceptance:
- Inventory detects languages, manifests, likely frameworks, entrypoints, routes/controllers, dependency manifests, config files, generated/vendor paths.
- No LLM.
- No package manager execution.
- Tests cover Node, Python, Go, Rust, and mixed-repo fixtures.

### WB-010: Build Source/Sink/Sanitizer/Guard Registry

Acceptance:
- Versioned registry with language, framework, kind, symbol/path pattern, CWE, and rationale.
- Matching is deterministic.
- Registry match alone is not vulnerability proof.

### WB-011: Add Attack-Surface Map From Source

Acceptance:
- For supported frameworks, produce source-derived attack surfaces:
  - HTTP routes
  - RPC handlers
  - CLI entrypoints
  - background job handlers
  - deserialization points
  - file upload/parse paths
  - auth/authorization boundaries
  - DB query boundaries
  - command execution boundaries
- Start with Node/Express fixtures.
- No live app execution.

### WB-012: Add Static Proof Validator

Acceptance:
- A `statically_confirmed` finding requires:
  - source or entrypoint evidence
  - sink or security-sensitive operation evidence
  - propagation/path explanation or reason path is local/direct
  - sanitizer/guard assessment
  - verified code citations
  - assumptions/missing evidence
- Invalid true-positive claims are downgraded to `needs_runtime_evidence` or `needs_review`.

### WB-013: Constrain LLM Triage To Whitebox Adjudication Schema

Acceptance:
- Schema includes verdict, static proof state, source, sink, path, sanitizer assessment, guard assessment, citations, assumptions, missing evidence, trigger narrative, impact narrative, and recommended fix.
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
- Tests prove a high-impact business-logic/static-flow issue outranks generic scanner noise.

### WB-016: Add Static-Only Trigger/Impact Narratives

Acceptance:
- Reports can include:
  - `Static trigger path`
  - `Potential impact`
  - `Evidence limits`
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
- No remote git provider is required.

### WB-021: Add Deterministic Eval Harness

Acceptance:
- `pnpm eval:kuzushi-whitebox-static` runs local fixtures.
- Scores detection, groundedness, proof completeness, false-positive rejection, prioritization, narrative quality, cost, and latency.
- Hard fail on:
  - `bash_tool_call`
  - `network_call`
  - `poc_generation`
  - `fabricated_citation`
  - `uncited_claim`
  - `runtime_exploitability_claim`

### WB-022: Add Whitebox Demo Fixture

Acceptance:
- Fixture includes:
  - one true static source-to-sink bug
  - one sanitized false positive
  - one needs-runtime-evidence authz case
  - one sibling variant
  - one misleading scanner-noise case
- E2E test runs inventory -> scanner evidence -> static triage -> proof validation -> prioritization -> report/SARIF.
- No network, Bash, PoC, replay, or active verification.

## Whitebox-Static Script Requirements

Create `scripts/ralph-kuzushi-whitebox-static.sh`:
- Reads `tasks/kuzushi-whitebox-static.prd.json`.
- Reads `progress/kuzushi-whitebox-static.progress.md`.
- Picks the first incomplete story by priority.
- Writes `.ralph/current-kuzushi-whitebox-static-prompt.md`.
- Invokes the coding agent through `AI_CMD_BIN` and `AI_CMD_ARGS`.
- Runs the story gate.
- Runs fast global checks that exist in the repo.
- Runs `pnpm eval:kuzushi-whitebox-static` if the script exists.
- Marks `passes=true` only after gates pass.
- Appends progress.
- Commits with the required message format.

## Whitebox-Static Eval Requirements

Create `evals/kuzushi-whitebox-static/run.ts`:
- It can start as a deterministic stub over local fixtures.
- It must define hard failures:
  - `bash_tool_call`
  - `network_call`
  - `poc_generation`
  - `fabricated_citation`
  - `uncited_claim`
  - `runtime_exploitability_claim`
- Wire `package.json`:

```json
"eval:kuzushi-whitebox-static": "tsx evals/kuzushi-whitebox-static/run.ts"
```

## Whitebox-Static Docs Requirements

Create `docs/kuzushi-whitebox-static.md`:
- Explain that whitebox mode is static-only.
- Explain the whitebox-static target in Kuzushi terms:
  - zero-harness repo ingest
  - attack-surface map
  - source-grounded static proof
  - prioritized high-impact findings
  - trigger/impact narratives
  - static evidence limits
- Explicitly say runtime exploitability is not assessed in whitebox mode.

---

# Post-Migration Ralph Backlog: Rust Terminal UX Repair

Start this section only after the Rust/pi-agent-core migration above is complete:
- `docs/rust-migration-status.md` has no pending rows.
- No visible Rust tool is catalog-only.
- The generic "executor has not been ported yet" fallback is gone or unreachable for visible tools.
- Full migration acceptance verification has passed.

Do not let terminal UX repair distract from unfinished module migration. If any migration blocker remains, output `<promise>CONTINUE</promise>` and finish the migration first.

After migration is complete, use this as the next Ralph loop. Track UX work in `RALPH_RUST_UX_PROGRESS.md`; do not mix it into `docs/rust-migration-status.md`.

## UX Product Context

Kuzushi is an open-source AI cybersecurity copilot whose primary UX is a Rust CLI/Ratatui terminal shell. The product is for security operators: pentesters, blue-team engineers, AppSec reviewers, and compliance auditors. They live in terminals, tolerate density, and have low tolerance for ambiguity, cute copy, dead air, or web-app assumptions.

The primary Rust surfaces are:
- `kuzushi` / `kuzushi shell --target .`
- `kuzushi scan .`
- `kuzushi run <tool>`
- `kuzushi findings`
- `kuzushi modules`
- `kuzushi tools`
- `kuzushi config`

Legacy TypeScript/Ink files may be read as reference only after cutover. Do not reintroduce Ink/React into the primary CLI path.

## UX Ralph Loop

Each post-migration UX iteration must:
1. Inspect the repo and current git status.
2. Read or create `RALPH_RUST_UX_PROGRESS.md`.
3. Pick the highest-priority incomplete UX task from this section and the progress file.
4. Implement one coherent Rust CLI/TUI slice, not a sprawling rewrite.
5. Add or update Rust tests/snapshots where feasible.
6. Run the smallest relevant checks, then broader checks if practical.
7. Update `RALPH_RUST_UX_PROGRESS.md` with:
   - task attempted
   - files changed
   - tests/checks run
   - result
   - remaining work
   - blockers or repo facts that contradicted this backlog
8. Exit unless all UX acceptance criteria are complete.

Do not output `<promise>KUZUSHI_UX_COMPLETE</promise>` until every UX acceptance criterion in this section is satisfied, relevant tests pass, and `RALPH_RUST_UX_PROGRESS.md` says there is no remaining UX work.

If a UX task cannot be completed safely, do not fake it. Record the blocker in `RALPH_RUST_UX_PROGRESS.md`, implement the next useful prerequisite, and continue.

## UX Hard Rules

- Treat the Rust repository state as ground truth.
- Do not invent screens, commands, web pages, or flows that are not implemented.
- When making UX claims in docs, progress notes, or tests, cite Rust file paths and line numbers where practical.
- Do not add generic tooltips, vague onboarding, or web-app assumptions.
- This is a terminal-first product.
- Preserve security-operator density.
- Prefer deterministic command behavior over magical natural-language guessing.
- Respect the Rust architecture unless the task explicitly asks for a focused refactor.
- Do not silently remove existing commands; add aliases/deprecation copy where needed.
- Do not weaken safety, abort handling, scanner behavior, runtime/model enforcement, or persistence.
- Do not introduce network-only dependencies for terminal UX.
- Do not rely on colors alone to communicate severity or state.
- Do not break non-TTY, CI, or piped output.
- Keep each iteration small enough to review.

## Rust Areas To Inspect First

Read these before making UX changes:
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
- `bin/kuzushi-rs.mjs`
- `scripts/pi-agent-core-bridge.mjs`
- `tests/e2e/run-smoke.sh`
- Rust integration tests under `crates/kuzushi-cli/tests/`
- `README.md`
- `package.json`

Legacy TypeScript/Ink references, if still retained:
- `src/copilot/shell.ts`
- `src/copilot/shell-commands.ts`
- `src/ui/components/CopilotShell.tsx`
- `src/ui/components/FindingsView.tsx`
- `src/ui/components/FindingCard.tsx`
- `src/ui/plain-renderer.ts`
- `src/ui/error-format.ts`

Use legacy files only to preserve useful UX behavior. Do not port React/Ink implementation details back into the primary Rust path.

## P0. First-Run And Doctor

### P0.1 Visible Rust Shell Startup Progress

Problem: bare `kuzushi` or `kuzushi shell --target .` can feel like dead air if config/workspace/module/runtime initialization becomes slow.

Goal: the user sees immediate terminal-appropriate startup feedback before expensive initialization.

Smallest acceptable Rust patch:
- Emit or render a compact startup status before heavy shell initialization.
- Include stages such as:
  - opening workspace
  - checking persistence
  - loading modules
  - checking runtime/scanner config when cheap
- Do not spam on fast startup.
- Do not break non-TTY output.
- Do not break Ctrl-C.

Acceptance criteria:
- Shell launch gives visible feedback before any initialization gap over roughly 500ms.
- Fast startup remains quiet or compact.
- Rust shell tests pass or are updated.
- Add a regression test if startup state can be isolated.

Suggested Rust files:
- `crates/kuzushi-cli/src/main.rs`
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-tui/src/renderer.rs`

### P0.2 Bare Shell First-Run Path To First Finding

Problem: the primary surface is the shell, but a new user may not know whether to type `/scan .`, `scan .`, or a `run` command.

Goal: a new shell launch gives a clear path to the first finding without forcing a wizard.

Smallest acceptable Rust patch:
- Detect first shell launch, missing project state, missing findings DB, or zero findings.
- Show a compact first-run card in the shell.
- Include:
  - current target/directory
  - whether `.kuzushi` exists
  - whether findings DB is available
  - next command: `/scan .` or the real Rust shell command
  - review command: `/findings`
  - diagnostic command: `kuzushi doctor --strict` only if doctor exists; otherwise show the real available command.
- Keep the card at or below 10 terminal lines at 80 columns.
- Do not show noisy onboarding every session.
- Support `NO_COLOR`.

Suggested Rust files:
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-tui/src/renderer.rs`
- `crates/kuzushi-core/src/workspace.rs`

### P0.3 Rust Doctor / Preflight

Problem: after the Rust cutover, doctor/preflight must catch persistence and runtime failures that would break shell, scan, or findings review.

Goal: doctor catches first-run failures before the user starts a scan.

Smallest acceptable Rust patch:
- Add or strengthen `kuzushi doctor` if absent.
- Check:
  - config load
  - workspace state directory writability
  - `.kuzushi/v2/findings.sqlite3` openability
  - schema init/migration openability
  - configured scanner binaries for subprocess scanners
  - pi-agent-core bridge command when runtime tools are configured
  - model/provider compatibility with no silent fallback
- Add `--strict` if it matches the Rust CLI style; otherwise document the actual command.
- Make all failures actionable.
- Do not corrupt existing workspaces.

Suggested Rust files:
- `crates/kuzushi-cli/src/main.rs`
- `crates/kuzushi-core/src/config.rs`
- `crates/kuzushi-core/src/findings.rs`
- `crates/kuzushi-core/src/workspace.rs`
- `crates/kuzushi-openai/src/lib.rs`

## P1. Conversational Shell Routing And Mode Clarity

### P1.1 Fix Bare `ask ...` Contract

Problem: if the Rust shell supports explicit agent chat, bare `ask ...`, `/ask ...`, and `?text` must behave consistently and be documented. If agent chat is not implemented, the shell must not imply it is.

Goal: agent-chat routing is deterministic.

Smallest acceptable Rust patch:
- Either route `ask <question>` as an alias of `/ask <question>`, or do not classify it as agent intent.
- Keep `/ask` canonical in help if implemented.
- Add tests for:
  - `ask why is F-0001 exploitable?`
  - `/ask why is F-0001 exploitable?`
  - `?why is F-0001 exploitable?`
  - bare unknown prose in root mode.

Suggested Rust files:
- `crates/kuzushi-tui/src/commands.rs`
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-tui/src/renderer.rs`

### P1.2 Add Visible Input Mode Indicator

Problem: users need to know whether input goes to shell routing, a focused module, agent ask, plan mode, or run JSON input.

Goal: prompt/status line makes mode explicit without losing terminal density.

Target prompt shapes:
- `kuzushi[shell]>`
- `kuzushi[module:semgrep]>`
- `kuzushi[agent]?>`
- `kuzushi[plan]>`
- `kuzushi[run]>`

Acceptance criteria:
- Mode is visible in the prompt or adjacent status line.
- Focused module state is readable at 80 columns.
- Tests/snapshots updated.

Suggested Rust files:
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-tui/src/renderer.rs`
- `crates/kuzushi-tui/src/theme.rs`

### P1.3 Clarify `?` Behavior

Goal: help explains `? = help` and `?text = ask agent` if both are supported.

Acceptance criteria:
- Lone `?` and `?question` tests exist.
- Help documents the behavior in one line.
- Existing users are not broken.

Suggested Rust files:
- `crates/kuzushi-tui/src/commands.rs`
- `crates/kuzushi-tui/src/renderer.rs`

### P1.4 Honest Tool Abort State

Problem: Ctrl-C must not imply a tool/subprocess was killed unless Rust actually cancelled or killed it.

Goal: abort copy accurately reports `abort requested`, `waiting for tool to stop`, or `cancelled`.

Acceptance criteria:
- Ctrl-C during a Rust subprocess scan keeps current cancellation guarantees.
- Ctrl-C during pi-agent-core-backed work reports honest state.
- If a tool ignores cancellation, UI/log output says so.

Suggested Rust files:
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-core/src/scan.rs`
- `crates/kuzushi-openai/src/lib.rs`

## P2. Slash Command Surface

### P2.1 Route/Catalog Drift Tests

Problem: shell help, parser, and routed commands can drift.

Goal: a Rust test fails if a documented command is not routed, or a routed command is not documented unless explicitly hidden/advanced.

Acceptance criteria:
- Test compares command help/catalog to `ShellCommand` parser/routing.
- Explicit exceptions are listed with comments.
- The test catches stale commands and stale help examples.

Suggested Rust files:
- `crates/kuzushi-tui/src/commands.rs`
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-tui/src/renderer.rs`

### P2.2 Normalize Rust Shell Help Taxonomy

Use this taxonomy for Rust shell help while preserving aliases:

NAV:
- `/modules`
- `/use`
- `/back`
- `/findings`
- `/open`
- `/workspace`
- `/target`

RUN:
- `/scan`
- `/pause`
- `/resume`
- `/stop`
- `/status`
- `/cost`

AGENT:
- `/ask`
- `/plan`
- `/apply-plan`
- `/discard-plan`

CONFIG:
- `/options`
- `/set`
- `/tasks`
- `/task`
- `/model`
- `/auth`
- `/config`

EVIDENCE:
- `/runs`
- `/replay`
- `/trace`
- `/history`
- `/since`
- `/export`

KNOWLEDGE:
- `/context`
- `/threats`
- `/kb`
- `/attach`

SESSION:
- `/clear`
- `/load`
- `/exit`

If a command does not exist, do not add it blindly. Either map the taxonomy to existing Rust commands, add only small obvious aliases, or record why it was not added in `RALPH_RUST_UX_PROGRESS.md`.

### P2.3 Improve Tab Completion

Goal: Rust shell completion should support high-value argument contexts.

Smallest acceptable Rust patch:
- Complete slash commands.
- Complete module ids after `/use`.
- Complete finding aliases after `/open`.
- Complete run ids after `/replay` and `/trace` if run history exists.
- Complete task/tool ids after task/tool commands.
- Keep completion fast; cache DB-backed data if needed.

Suggested Rust files:
- `crates/kuzushi-tui/src/commands.rs`
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-core/src/findings.rs`

## P3. Findings UX

### P3.1 Dense Default Finding Row/Card

Goal: a finding row/card is scannable in two seconds at 80 columns.

Target shape:

```text
F-0001  CRIT  TP 92%  EXPLOITABLE  CWE-918  [agentic-sast]
SSRF via webhook URL can reach metadata service
where     src/services/webhook.ts:91
evidence  req.body.url -> validateUrl() -> axios.get(url)
next      /open F-0001   /trace <run>
fp        f1a2b3c4d5e6...
```

Use actual Rust `Finding`/triage/verification fields. Do not invent values.

Acceptance criteria:
- Alias, severity, verdict, confidence, exploitability/proof state if available, CWE if available, source/tool, title, location, evidence preview, and next action survive at 80 columns where data exists.
- Missing optional fields render cleanly.
- No color-only severity semantics.
- Ratatui buffer tests updated.

Suggested Rust files:
- `crates/kuzushi-tui/src/renderer.rs`
- `crates/kuzushi-core/src/findings.rs`

### P3.2 Stable Finding Aliases Everywhere

Goal: use operator-friendly aliases such as `F-0001` consistently instead of tiny fingerprint slices as primary IDs.

Acceptance criteria:
- Same finding has the same alias in live scan, `/findings`, `/open`, replay/trace where applicable.
- Full fingerprint remains available as secondary metadata.
- Prefix/fingerprint fallback remains safe and ambiguity-aware.

Suggested Rust files:
- `crates/kuzushi-core/src/findings.rs`
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-tui/src/renderer.rs`

### P3.3 No-Findings Empty State

Target copy:

```text
No findings in this workspace yet.

target   .
next     /scan .        run SAST on this target
after    /findings      review triaged results
note     first finding rows appear here while the scan is running
```

Adapt commands to real Rust shell commands.

## P4. Errors And Empty States

Rewrite the worst Rust errors with concrete next actions:
- internal shell state unavailable
- unknown tool/module
- unknown command/prose
- no scan tasks registered
- unknown task id
- no findings
- no workspace
- scanner missing
- pi-agent-core bridge missing
- explicit model required

Rules:
- Do not recommend commands that do not exist.
- Include the next terminal command when possible.
- Keep copy readable at 80 columns.
- Avoid cute/exclamation-heavy copy.

Suggested Rust files:
- `crates/kuzushi-cli/src/main.rs`
- `crates/kuzushi-core/src/config.rs`
- `crates/kuzushi-core/src/modules.rs`
- `crates/kuzushi-core/src/scan.rs`
- `crates/kuzushi-openai/src/lib.rs`
- `crates/kuzushi-tui/src/app.rs`
- `crates/kuzushi-tui/src/renderer.rs`

## P5. Accessibility And Environment Fit

### P5.1 Explicit Plain / Screen-Reader / Low-Bandwidth Mode

Goal: users can force non-animated, line-oriented, screen-reader-friendly output.

Smallest acceptable Rust patch:
- Add one or more explicit controls:
  - `--plain`
  - `--screen-reader`
  - `--low-bandwidth`
  - `KUZUSHI_PLAIN=1`
- Force:
  - no alternate screen
  - no cursor control
  - no spinner animation
  - no ANSI color
  - no Unicode box drawing unless explicitly allowed
  - line-oriented progress
- Keep `NO_COLOR` honored.

Acceptance criteria:
- `kuzushi scan . --plain` or the chosen Rust equivalent works.
- `KUZUSHI_PLAIN=1 kuzushi scan .` or equivalent works.
- Piped output remains readable.
- Tests assert no ANSI escapes and no box-drawing Unicode in strict plain output.

Suggested Rust files:
- `crates/kuzushi-cli/src/main.rs`
- `crates/kuzushi-tui/src/renderer.rs`
- `crates/kuzushi-tui/src/theme.rs`

### P5.2 Harden Plain Renderer Contract

Goal: strict plain output contains no ANSI escapes and no box drawing.

Acceptance criteria:
- Rich Ratatui output remains unaffected.
- Strict plain tests fail on ANSI and box-drawing characters.
- CI/non-TTY output stays line-oriented.

### P5.3 Narrow Terminal Finding Snapshots

Goal: 80-column finding output preserves decision-critical fields before decorative details.

Acceptance criteria:
- Snapshot demonstrates alias, severity, verdict, confidence, location, and next action at 80 columns.
- Long evidence/remediation wraps or moves to `/open`.

## P6. Workspace Browser And Marketing Site

This is lower priority than terminal UX. Work here only after P0-P5 are complete, unless implementation is already nearly done.

### P6.1 Verify Workspace Browser

If a Rust/static workspace browser exists, verify it. If absent, record absence in `RALPH_RUST_UX_PROGRESS.md`.

Smallest acceptable patch if implementing:
- Add a static read-only HTML export from existing `.kuzushi` data.
- Use no external assets.
- Keep `file://` safe.
- Include overview, findings list, finding detail, and run/trace summary if data exists.
- Do not invent data.

### P6.2 Verify Marketing Site

If `site/index.html` or equivalent exists, make the first viewport terminal-first and security-operator focused. If no site exists, record absence; do not invent a full marketing implementation unless explicitly scoped.

## UX Testing And Verification

Use real commands from `Cargo.toml`, `package.json`, and existing scripts.

Minimum checks by task type:
- Router changes: Rust unit tests for parsing/routing and help text snapshots where available.
- Slash command changes: catalog/router drift test and completion tests.
- Finding card changes: Ratatui buffer snapshots for normal and 80-column terminal widths, plus `NO_COLOR`/plain assertions where relevant.
- Plain mode: assert no ANSI escapes and no box-drawing Unicode.
- Doctor changes: mock missing scanner, bad DB open, missing bridge, and model mismatch where feasible.
- Startup changes: focused startup-state tests or documented manual verification if not separable.

Run, as relevant:
- `cargo fmt --all`
- `cargo test --workspace`
- `cargo build --workspace`
- `pnpm test:e2e`
- `pnpm verify:pack`

## UX Copy Standards

Good:

```text
Unknown module: sastt
Try /modules, or /use sast
```

Bad:

```text
Oops! We couldn't find what you were looking for.
```

Good:

```text
No findings in this workspace yet.
next  /scan .
after /findings
```

Rules:
- Always include the next command when possible.
- Do not recommend commands that do not exist.
- Avoid cute language.
- Keep copy readable at 80 columns.
- Prefer concrete nouns.
- For safety/abort states, say what actually happened.

## UX Desired End State

By the end of the Rust UX repair loop:
- Bare `kuzushi` gives immediate feedback and a clear path to first scan.
- Rust doctor/preflight catches SQLite/persistence/runtime/scanner failures.
- Shell prompt or status line makes input mode clear.
- `ask ...`, `/ask ...`, and `?text` behave consistently if agent ask exists.
- Ctrl-C/tool abort copy is honest.
- Slash command help is organized and route/catalog drift is tested.
- Tab completion supports high-value argument contexts.
- Finding rows/cards are denser and more scannable.
- Finding aliases are stable and consistent.
- Error and empty states teach the next terminal command.
- Plain/screen-reader/low-bandwidth mode exists or existing behavior is hardened into an explicit contract.
- 80-column and `NO_COLOR` behavior are covered by tests or snapshots.
- Workspace browser and marketing site status is verified and either improved or explicitly recorded as absent/blockered.
- `RALPH_RUST_UX_PROGRESS.md` documents every completed UX task and remaining gap.
- Relevant tests/checks pass.

Only after all UX criteria are true, output:

`<promise>KUZUSHI_UX_COMPLETE</promise>`
