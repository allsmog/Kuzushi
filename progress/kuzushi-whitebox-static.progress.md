# Kuzushi Whitebox-Static Progress

Stage: 3 - Kuzushi whitebox-static mode
Active story: WB-022 - Add whitebox demo fixture
Status: WB-021 pushed in iteration 53; WB-022 pending

## Stage 3 Checklist

- WB-001 Add explicit whitebox-static mode: complete in iteration 29.
- WB-002 Remove shell execution from default whitebox agent tools: complete in iteration 30.
- WB-003 Scrub scanner subprocess environments: complete in iteration 31.
- WB-004 Add static proof taxonomy: complete in iteration 32.
- WB-005 Add static evidence graph: complete in iteration 33.
- WB-006 Add source span extractor: complete in iteration 34.
- WB-007 Normalize Semgrep findings into static evidence: complete in iteration 35.
- WB-008 Normalize CodeQL SARIF code flows into static evidence: complete in iteration 36.
- WB-009 Build deterministic repository inventory: complete in iteration 37.
- WB-010 Build source/sink/sanitizer/guard registry: complete in iteration 38.
- WB-011 Add attack-surface map from source: complete in iteration 39.
- WB-012 Add static proof validator: complete in iteration 40.
- WB-013 Constrain LLM triage to whitebox schema: complete in iteration 41.
- WB-014 Verify LLM citations before persistence: complete in iteration 42.
- WB-015 Prioritize findings by static impact: complete in iteration 43.
- WB-016 Add static trigger/impact narratives: complete in iteration 44.
- WB-017 Add variant search from statically confirmed findings: complete in iteration 45.
- WB-018 Add candidate Semgrep rule synthesis: complete in iteration 46.
- WB-019 Add whitebox false-positive memory: complete and pushed in iteration 49.
- WB-020 Add diff-aware whitebox PR mode: complete in iteration 51.
- WB-021 Add deterministic eval harness: complete in iteration 53.
- WB-022 Add whitebox demo fixture: pending.

## Iteration Log

### Iteration 53 - WB-021

- Task attempted: add a deterministic, fixture-driven whitebox-static eval
  harness with local passing and expected-hard-failure fixtures.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `evals/kuzushi-whitebox-static/run.ts`
  - `evals/kuzushi-whitebox-static/fixtures/harness-cases.json`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,260p' progress/kuzushi-whitebox-static.progress.md`
  - `sed -n '1,260p' tasks/kuzushi-whitebox-static.prd.json`
  - `pnpm eval:kuzushi-whitebox-static`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `git diff --check`
- Result: implementation complete and pushed to `origin/main` as `9e1e49e`.
  `evals/kuzushi-whitebox-static/run.ts`
  now loads local JSON fixtures, computes deterministic scores for detection,
  groundedness, proof completeness, false-positive rejection, prioritization,
  narrative quality, cost, and latency, and exits nonzero if a passing fixture
  contains shell execution, network calls, PoC generation, fabricated
  citations, uncited confirmed claims, or runtime exploitability claims. The
  fixture set also includes expected-bad cases for each hard failure so the
  detectors are exercised. WB-021 is marked `passes: true` in the PRD after
  the story gate and fast whitebox checks passed.
- Remaining work: WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies, then
    removed the symlink before committing.

### Iteration 51 - WB-020

- Task attempted: add diff-aware whitebox PR mode that uses local git diff
  data from `diffBase`, expands nearby static context, tags current and fixed
  findings, and writes a run artifact without requiring a remote git provider.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `docs/kuzushi-whitebox-static.md`
  - `evals/kuzushi-whitebox-static/run.ts`
  - `crates/kuzushi-core/src/diff_scope.rs`
  - `crates/kuzushi-core/src/lib.rs`
  - `crates/kuzushi-core/src/modules.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,280p' progress/kuzushi-whitebox-static.progress.md`
  - `sed -n '1,260p' tasks/kuzushi-whitebox-static.prd.json`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core whitebox_diff`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static`
- Result: implementation complete and pushed to `origin/main` as `5b596c6`.
  `diff_scope.rs` now computes changed files, added/modified/deleted line
  ranges from local `git diff`, expands context to nearby routes, callers, and
  callees, and tags findings as `new`, `existing`, `fixed`, or
  `changed-context`. Whitebox `sast:scan` accepts `diffBase` and writes
  `.kuzushi/runs/<runId>/whitebox-diff-scope.json`, includes the report in tool
  JSON as `whiteboxDiff`, and states that no remote provider is required.
  WB-020 is marked `passes: true` in the PRD after the story gate and fast
  whitebox checks passed.
- Remaining work: WB-021 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies. The
    first eval wrapper used zsh's read-only `status` variable after the eval
    itself passed; the eval was rerun with a safe wrapper and passed, then the
    symlink was removed before commit.

### Iteration 49 - WB-019 Push Gate

- Task attempted: complete the required push gate for the already-local
  WB-019 false-positive memory commit before starting WB-020.
- Files changed:
  - `progress/kuzushi-whitebox-static.progress.md`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,260p' progress/kuzushi-whitebox-static.progress.md`
  - `git show --stat --oneline --decorate HEAD`
  - `git diff --stat origin/main..HEAD`
  - `git push origin HEAD:main`
- Result: complete. The local WB-019 implementation commit
  `4704589 ralph:whitebox-static complete WB-019 - Add whitebox false-positive memory`
  was pushed to `origin/main`.
- Remaining work: WB-020 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.

### Iteration 47 - WB-019

- Task attempted: add whitebox-static false-positive memory with explicit
  evidence, scope, author, reason, creation/expiration timestamps, snippet-hash
  invalidation, and audit/report visibility.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `evals/kuzushi-whitebox-static/run.ts`
  - `docs/kuzushi-whitebox-static.md`
  - `crates/kuzushi-core/src/whitebox_suppressions.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-core/src/lib.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,180p' progress/kuzushi-whitebox-static.progress.md`
  - `rg -n "suppression|suppress|false.?positive|fingerprint|snippetHash|snippet_hash|staticProofState|StaticProofState|whitebox" crates/kuzushi-core/src crates/kuzushi-cli/src tests evals docs tasks -g '!target'`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core whitebox_suppressions`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static`
  - `git diff --check`
- Result: implementation complete and locally committed. `whitebox_suppressions.rs` now stores
  suppression records under `.kuzushi/v2/whitebox-suppressions.json`, requires
  non-empty evidence/scope/reason/author and a future expiration, builds records
  from verified source spans, and evaluates active, stale, and expired
  suppressions without filtering findings out of audit/report visibility.
  Whitebox `sast:scan` now writes a `whitebox-suppressions.json` run artifact
  with active matches, stale hash-invalidated records, expired records, and an
  explicit note that suppressed findings remain visible. WB-019 is marked
  `passes: true` in the PRD after the story gate passed.
- Remaining work: push the local WB-019 commit, then continue with WB-020
  through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.
  - `git push origin HEAD:main` failed with `Could not resolve host:
    github.com`, so the required push has not completed from this sandbox.

### Iteration 46 - WB-018

- Task attempted: add deterministic candidate Semgrep rule synthesis from
  statically confirmed whitebox-static findings, including positive/negative
  fixture validation and disabled-by-default rule artifacts.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `evals/kuzushi-whitebox-static/run.ts`
  - `docs/kuzushi-whitebox-static.md`
  - `crates/kuzushi-core/src/semgrep_rule_synthesis.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-core/src/lib.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,260p' progress/kuzushi-whitebox-static.progress.md`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core semgrep_rule_synthesis`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `git diff --check`
  - `pnpm eval:kuzushi-whitebox-static`
- Result: implementation complete. `semgrep_rule_synthesis.rs` now derives
  candidate Semgrep rules only from findings whose static proof state is
  `statically_confirmed`, validates candidates against positive and negative
  fixtures, and leaves every generated rule disabled. Passing validation marks a
  candidate `readyForManualEnable`; it does not enable the rule. Whitebox
  `sast:scan` now writes `.kuzushi/runs/<runId>/candidate-semgrep-rules.json`,
  includes `candidateSemgrepRules` in tool JSON, and summarizes disabled
  candidates in shell output. The eval now checks the candidate-rule
  implementation, and WB-018 is marked `passes: true` in the PRD after the
  story gate and fast whitebox checks passed.
- Remaining work: WB-019 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.

### Iteration 45 - WB-017

- Task attempted: add deterministic whitebox-static variant search from
  statically confirmed findings without letting variants inherit confirmation.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `evals/kuzushi-whitebox-static/run.ts`
  - `docs/kuzushi-whitebox-static.md`
  - `crates/kuzushi-core/src/variant_ndiff.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-core/src/lib.rs`
- Tests/checks run:
  - `git status --short --branch` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,220p' progress/kuzushi-whitebox-static.progress.md`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core whitebox_variants`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `git diff --check`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean nested clone
- Result: implementation complete. `variant_ndiff.rs` now derives reusable
  source/sink/missing-guard patterns only from `statically_confirmed` findings
  and their static evidence, scans sibling source files deterministically, and
  emits whitebox variant candidates as `code_cited` findings that explicitly
  require independent validation. Guarded sibling candidates are skipped, and
  non-confirmed findings do not seed patterns. Whitebox `sast:scan` now writes
  `.kuzushi/runs/<runId>/static-variants.json`, includes `staticVariants` in
  tool JSON, and never marks variants confirmed by inheritance. WB-017 is
  marked `passes: true` in the PRD after the story gate and fast whitebox
  checks passed.
- Remaining work: WB-018 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies and then
    removed it before commit.

### Iteration 44 - WB-016

- Task attempted: add source-grounded static trigger, potential impact, and
  evidence-limit narratives for whitebox-static reports without exploit/PoC
  language.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `evals/kuzushi-whitebox-static/run.ts`
  - `crates/kuzushi-core/src/static_narrative.rs`
  - `crates/kuzushi-core/src/static_ranking.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-core/src/lib.rs`
- Tests/checks run:
  - `git status --short --branch` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,180p' progress/kuzushi-whitebox-static.progress.md`
  - `rg -n "triggerNarrative|impactNarrative|narrative|static trigger|impact|evidence limits|ProofNarrative|report" crates/kuzushi-core/src evals docs tasks -g '!docs/architecture.svg'`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core static_narrative`
  - `cargo test -p kuzushi-core whitebox_static_sast_mode_disables_execution_and_patch_paths`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `git diff --check`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean nested clone
- Result: implementation complete. `static_narrative.rs` now builds a
  deterministic narrative report containing `staticTriggerPath`,
  `potentialImpact`, and `evidenceLimits` for whitebox-static findings, ordered
  by static ranking when available. It rejects `exploited`, `confirmed
  exploit`, PoC, payload, replay, fuzzing, and live-target language. Whitebox
  `sast:scan` now writes `.kuzushi/runs/<runId>/static-narratives.json`,
  includes the report in tool JSON as `staticNarratives`, and records the
  artifact path. The eval now checks for the static narrative implementation.
  WB-016 is marked `passes: true` in the PRD after the story gate and fast
  whitebox checks passed.
- Remaining work: WB-017 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies and then
    removed it before commit.
  - The first eval wrapper command failed after the eval itself passed because
    `status` is a read-only zsh variable; it was rerun with `exit_code` and
    passed.

### Iteration 43 - WB-015

- Task attempted: add deterministic whitebox-static finding prioritization so
  source-grounded, high-impact static flows rank ahead of generic scanner
  noise.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/static_ranking.rs`
  - `crates/kuzushi-core/src/lib.rs`
  - `crates/kuzushi-core/src/modules.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,240p' progress/kuzushi-whitebox-static.progress.md`
  - `rg -n "WB-015|priority|prioriti|rank|staticProof|StaticProof|attackSurface|static impact|confidence|CodeQL|flow" tasks/kuzushi-whitebox-static.prd.json crates/kuzushi-core/src evals docs tests -S`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core static_ranking`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean nested clone
- Result: implementation complete. `static_ranking.rs` now scores findings with
  deterministic factors for severity, static proof state, attack-surface
  reachability, source/sink class, data sensitivity, privilege boundary,
  sanitizer or guard absence, framework context, CodeQL flow quality,
  confidence, and scanner-noise penalties. `sast:scan` writes
  `.kuzushi/runs/<runId>/static-ranking.json` in `whitebox-static` mode and
  includes the ranking in the tool result. Tests prove a CodeQL-backed
  source-to-sink SQL flow reachable from an Express route outranks a critical
  generic Semgrep noise finding, ties are deterministic, and sanitized or
  statically rejected findings are downranked. WB-015 is marked `passes: true`
  in the PRD after the story gate and fast whitebox checks passed.
- Remaining work: WB-016 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies and then
    removed it before commit.

### Iteration 42 - WB-014

- Task attempted: verify whitebox-static LLM citations before agentic SAST
  findings persist, and ensure `statically_confirmed` claims with fabricated,
  stale, out-of-repo, or bad-line citations are downgraded.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/static_proof_validator.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-core/src/lib.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,240p' progress/kuzushi-whitebox-static.progress.md`
  - `rg -n "whitebox|citation|StaticProofClaim|triage|missingEvidence|statically_confirmed|staticProofState" crates/kuzushi-core/src/modules.rs crates/kuzushi-core/src/whitebox_static.rs`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core whitebox_citations`
  - `cargo test -p kuzushi-core static_proof_validator`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean nested clone
- Result: implementation complete. The static proof validator can now parse
  the whitebox triage schema directly, verify citation files and line ranges
  under the repo root, compare exact snippets and snippet hashes, and reject
  out-of-repo, stale, or fabricated citations. `agentic-sast:scan` now runs
  this validation in `whitebox-static` mode before findings are inserted into
  the findings DB; invalid `statically_confirmed` claims are persisted only as
  `needs_runtime_evidence` with citation-validation issues in the finding
  message. WB-014 is marked `passes: true` in the PRD after the story gate and
  fast whitebox checks passed.
- Remaining work: WB-015 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies and then
    removed it before commit.

### Iteration 41 - WB-013

- Task attempted: constrain model-backed whitebox-static agentic SAST triage to
  a static-only, source-grounded schema and forbid dynamic/exploitative output
  in the prompt contract.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/whitebox_static.rs`
  - `crates/kuzushi-core/src/modules.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,260p' progress/kuzushi-whitebox-static.progress.md`
  - `sed -n '1,260p' tasks/kuzushi-whitebox-static.prd.json`
  - `rg -n "WB-013|whitebox_triage_prompt|staticProofState|prompt" crates/kuzushi-core/src crates/kuzushi-core/tests tests evals docs tasks progress`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core whitebox_triage_prompt`
  - `cargo fmt --all --check`
  - `git diff --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean nested clone
- Result: implementation complete. `whitebox_static.rs` now owns the
  whitebox-static triage system prompt and prompt block with a JSON schema
  containing `verdict`, `staticProofState`, `source`, `sink`, `path`,
  sanitizer/guard assessments, citations, assumptions, missing evidence,
  trigger/impact narratives, and recommended fixes. The prompt forbids
  payloads, PoCs, exploit execution, HTTP replay, fuzzing, live target
  scanning, and runtime exploitability claims. `agentic-sast:scan` uses this
  contract only in `whitebox-static` mode, while standard mode keeps the
  existing schema. The agentic normalizer now accepts the new schema fields,
  preserves static proof state, and falls back to cited/source/sink locations.
  WB-013 is marked `passes: true` in the PRD after the story gate and fast
  whitebox checks passed.
- Remaining work: WB-014 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 3 state. This iteration continued in the
    nested clone to avoid resetting or overwriting the primary worktree.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies and then
    removed it before commit.

### Iteration 40 - WB-012

- Task attempted: add a strict static proof validator for
  `statically_confirmed` whitebox claims.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/static_proof_validator.rs`
  - `crates/kuzushi-core/src/lib.rs`
- Tests/checks run:
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,120p' progress/kuzushi-whitebox-static.progress.md`
  - `sed -n '1,260p' crates/kuzushi-core/src/attack_surface.rs`
  - `rg -n "StaticProofState|NeedsReview|needs_review|TriageVerdict|statically_confirmed|needs_runtime_evidence|staticProof" crates/kuzushi-core/src/findings.rs crates/kuzushi-core/src/whitebox_static.rs crates/kuzushi-core/src/modules.rs crates/kuzushi-core/src/source_span.rs`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core static_proof_validator`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean nested clone
- Result: implementation complete. `static_proof_validator.rs` now verifies
  source citations against repo-root files, checks optional snippet/hash
  freshness, and gates `statically_confirmed` claims on source or entrypoint
  evidence, sink/security-sensitive operation evidence, a path explanation or
  local/direct reason, sanitizer and guard assessments, verified citations,
  explicit assumptions, and explicit missing-evidence limits. Invalid
  confirmed claims are downgraded to `needs_runtime_evidence` with
  `needs_review`; forbidden runtime exploitability language is rejected.
  WB-012 is marked `passes: true` in the PRD after focused story tests and the
  fast whitebox checks passed.
- Remaining work: WB-013 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The first WB-011 implementation attempt in this iteration was superseded by
    a pushed remote WB-011 commit (`9d44d3b`). The duplicate local commit was
    skipped during rebase, and this WB-012 work continued from clean
    `origin/main`.
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, so this iteration continued in the
    clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies and then
    removed it before commit.

### Iteration 39 - WB-011

- Task attempted: add a deterministic whitebox-static attack-surface map from
  repository source without live app execution.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/attack_surface.rs`
  - `crates/kuzushi-core/src/lib.rs`
  - `crates/kuzushi-core/src/modules.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,260p' progress/kuzushi-whitebox-static.progress.md`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core attack_surface`
  - `cargo test -p kuzushi-core dispatches_context_build_snapshot`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean nested clone
- Result: implementation complete. `attack_surface.rs` now builds a
  deterministic source-derived map with `http_route`, `rpc_handler`,
  `cli_entrypoint`, `background_job`, `deserialization_point`,
  `file_upload_parse_path`, `auth_boundary`, `db_query_boundary`, and
  `command_execution_boundary` surfaces. Node/Express fixtures cover routes,
  GraphQL/RPC, uploads, auth middleware, parser boundaries, DB calls, command
  execution, background jobs, and CLI arguments, while verifying that package
  scripts are not executed. `context:build` now embeds `attackSurfaceMap` and
  projects routes, background jobs, data stores, and service boundaries into
  the app model. WB-011 is marked `passes: true` in the PRD after the story
  gate and fast whitebox checks passed.
- Remaining work: WB-012 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files. This iteration continued in the
    clean nested clone at `/tmp/kuzushi-ux2-clone.PJaRge` after fast-forwarding
    it to `origin/main`.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies and then
    removed it before commit.

### Iteration 38 - WB-010

- Task attempted: add a deterministic source/sink/sanitizer/guard registry for
  whitebox-static proof construction.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/static_registry.rs`
  - `crates/kuzushi-core/src/lib.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,180p' progress/kuzushi-whitebox-static.progress.md`
  - `rg -n "WB-009|WB-010|passes" tasks/kuzushi-whitebox-static.prd.json progress/kuzushi-whitebox-static.progress.md`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core static_registry`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean nested clone
- Result: implementation complete. `static_registry.rs` now exposes a
  versioned default registry with source, sink, sanitizer, and guard entries
  for TypeScript/Express, Python/Flask, Go, and Rust. Entries carry language,
  optional framework, kind, pattern type, symbol/path/text pattern, CWE list,
  and rationale. Deterministic matching returns `signal_only` matches with
  `vulnerability_proof: false`, so registry matches cannot become standalone
  vulnerability proof. WB-010 is marked `passes: true` in the PRD after the
  story gate and fast whitebox checks passed.
- Remaining work: WB-011 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files. This iteration continued in the
    clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    to avoid resetting or overwriting the primary worktree.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies and then
    removed it before commit.
  - The first eval wrapper command failed after the eval itself passed because
    `status` is a read-only zsh variable; it was rerun with `exit_code` and
    passed.

### Iteration 37 - WB-009

- Task attempted: build a deterministic repository inventory for
  whitebox-static mode without LLM, network, package-manager, or shell
  execution.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/repository_inventory.rs`
  - `crates/kuzushi-core/src/lib.rs`
  - `crates/kuzushi-core/src/modules.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean nested clone
  - `sed -n '1,220p' progress/kuzushi-whitebox-static.progress.md`
  - `rg -n '"id": "WB-|passes' tasks/kuzushi-whitebox-static.prd.json`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core repository_inventory`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core dispatches_context_build_snapshot`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean nested clone
- Result: implementation complete. `build_repository_inventory` now walks the
  repository deterministically and records languages, source files, manifests,
  dependency manifests, config files, likely frameworks, entrypoints,
  routes/controllers, and generated/vendor paths without invoking any LLM,
  package manager, shell, or network path. Native `context:build` now embeds
  the inventory and maps detected static routes into `appModel.routes` for
  later whitebox stages. WB-009 is marked `passes: true` in the PRD after the
  story gate and fast whitebox checks passed.
- Remaining work: WB-010 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files, while the clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    contains the active pushed Stage 2 and WB-001 through WB-008 state. This
    iteration continued in the clean nested clone to avoid resetting or
    overwriting the primary worktree.
  - The nested clone does not have its own `node_modules`; the eval used a
    temporary symlink to the primary checkout's installed dependencies and then
    removed it before commit.

### Iteration 36 - WB-008

- Task attempted: normalize CodeQL SARIF code-flow evidence into the shared
  whitebox-static evidence graph without making exploitability claims.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/lib.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-core/src/scan.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean isolated clone
  - `sed -n '1,260p' RALPH_RUST_BRIDGE_GAPS_PROGRESS.md`
  - `sed -n '1,220p' RALPH_RUST_UX_PROGRESS.md`
  - `sed -n '1,260p' progress/kuzushi-whitebox-static.progress.md`
  - `cargo fmt --all`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core codeql_static_evidence`
  - `cargo test -p kuzushi-core normalizes_codeql_sarif_to_findings`
  - `cargo test -p kuzushi-core dispatches_codeql_scan_and_persists_findings`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static`
  - `cargo test -p kuzushi-core codeql`
- Result: implementation complete. CodeQL scanner execution can now return
  SARIF artifacts alongside normalized findings, while normal `codeql:scan`
  behavior remains unchanged. In `whitebox-static` mode, direct `codeql:scan`
  and native scan-run indexing stamp CodeQL findings as `signal_only`, persist
  `scanner_signal`, `code_span`, and `dataflow_step` nodes, and link adjacent
  SARIF flow locations with `flows_to` edges. Scanner signal metadata records
  `truePositiveByDefault: false`; no runtime exploitability claim is added.
  WB-008 is marked `passes: true` in the PRD after the story gate and fast
  whitebox checks passed. The implementation was committed and pushed to
  `origin/main` as `6cd3355`.
- Remaining work: WB-009 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files. This iteration created and worked
    in a clean nested clone at
    `/Users/operator/VibeCode/open-sourced/kuzushi/.codex-active/kuzushi-stage3`
    because the `apply_patch` tool rejected direct edits to `/private/tmp`.
  - GitHub network resolution failed from the primary checkout earlier in this
    iteration (`Could not resolve host: github.com`), but the final push from
    the nested clean clone succeeded.

### Iteration 35 - WB-007

- Task attempted: normalize Semgrep scanner signals into the static evidence
  graph without treating Semgrep output as true-positive proof.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/static_evidence.rs`
  - `crates/kuzushi-core/src/scan.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-core/src/lib.rs`
  - `crates/kuzushi-tui/src/app.rs`
- Tests/checks run:
  - `git status --short` in the primary checkout
  - `git status --short --branch` in the clean isolated clone
  - `sed -n '1,260p' RALPH_RUST_BRIDGE_GAPS_PROGRESS.md`
  - `sed -n '1,220p' RALPH_RUST_UX_PROGRESS.md`
  - `sed -n '1,260p' progress/kuzushi-whitebox-static.progress.md`
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core semgrep_static_evidence`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core semgrep`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean clone
  - `cargo test -p kuzushi-core`
- Result: implementation complete. `index_semgrep_findings_as_static_evidence`
  now creates one `scanner_signal` node, one source-verified `code_span` node,
  and one `derived_from` edge per Semgrep finding. The normalizer records
  `truePositiveByDefault: false` and `staticProofState: signal_only`, and
  whitebox SAST native scans index Semgrep evidence before findings persist.
  Direct `semgrep:scan` also stamps `signal_only` and indexes evidence when
  explicitly invoked with `mode=whitebox-static` or `whiteboxStatic=true`.
  WB-007 is marked `passes: true` in the PRD after the story gate and fast
  whitebox checks passed.
- Remaining work: WB-008 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files. This iteration continued in the
    clean isolated clone at `/tmp/kuzushi-ux2-clone.PJaRge`, which contains the
    active pushed Stage 2 and WB-001 through WB-006 state.
  - The isolated clone still does not have its own `node_modules`; the eval
    used a temporary symlink to the primary checkout's installed dependencies,
    then removed the symlink before commit.

### Iteration 34 - WB-006

- Task attempted: add the whitebox-static source span extractor used for
  source-grounded citations.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/source_span.rs`
  - `crates/kuzushi-core/src/lib.rs`
- Tests/checks run:
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core source_span`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the nested clean clone
- Result: implementation complete. The new extractor resolves
  repo-relative or in-repo absolute paths, rejects parent traversal and
  out-of-repo resolutions, rejects missing/non-file/binary-ish/non-UTF-8
  sources, validates 1-based inclusive line ranges, and returns a normalized
  snippet plus the shared static content hash. WB-006 is marked `passes: true`
  in the PRD after the story gate and fast whitebox checks passed.
- Remaining work: WB-007 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files. This iteration continued in the
    clean isolated clone at `/tmp/kuzushi-ux2-clone.PJaRge`, which contains the
    active pushed Stage 2 and WB-001 through WB-005 state.

### Iteration 33 - WB-005

- Task attempted: add the durable static evidence graph primitive for
  whitebox-static proof nodes and relationships.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/static_evidence.rs`
  - `crates/kuzushi-core/src/lib.rs`
- Tests/checks run:
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core static_evidence`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean clone
- Result: implementation complete. `StaticEvidenceStore` now writes
  `.kuzushi/v2/static-evidence.sqlite3` with hash-stable evidence nodes and
  edges. Node kinds match the whitebox specification (`code_span`,
  `scanner_signal`, `source`, `sink`, `dataflow_step`, `sanitizer`, `guard`,
  `attack_surface`, `triage_claim`, `report_claim`) and edge kinds match
  (`supports`, `derived_from`, `flows_to`, `guarded_by`, `sanitized_by`,
  `contradicts`, `reported_as`). Tests cover insert, fetch, link, workspace
  path, hash stability, and rejection of mutated/unhashed evidence bodies.
  WB-005 is marked `passes: true` in the PRD after the story gate and fast
  whitebox checks passed.
- Remaining work: WB-006 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files. This iteration continued in the
    clean isolated clone at `/tmp/kuzushi-ux2-clone.PJaRge`, which contains the
    active pushed Stage 2 and WB-001 through WB-004 state.

### Iteration 32 - WB-004

- Task attempted: add the Rust static proof taxonomy and prevent whitebox-static
  findings from carrying execution-confirmed proof states.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/findings.rs`
  - `crates/kuzushi-core/src/whitebox_static.rs`
  - `crates/kuzushi-core/src/lib.rs`
  - `crates/kuzushi-core/src/scan.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-core/src/carlini_threat_hunt.rs`
  - `crates/kuzushi-core/src/systems_hunt.rs`
  - `crates/kuzushi-core/src/pr_comment.rs`
  - `crates/kuzushi-tui/src/app.rs`
- Tests/checks run:
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core static_proof`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-core scanner_env`
  - `cargo test -p kuzushi-core semgrep`
  - `cargo test -p kuzushi-core`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `cargo test -p kuzushi-tui app::tests::chain_alias_format_is_two_digit_zero_padded`
  - `cargo fmt --all --check`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean clone
- Result: implementation complete. `Finding` now has an optional
  `staticProofState` backed by a nullable `.kuzushi/v2/findings.sqlite3`
  `static_proof_state` column. The taxonomy includes `signal_only`,
  `code_cited`, `source_sink_linked`, `sanitizer_checked`,
  `statically_confirmed`, `statically_rejected`, and
  `needs_runtime_evidence`; execution proof states are rejected by the
  taxonomy and downgraded to `needs_runtime_evidence` when they arrive through
  whitebox-static proof-state input. Native whitebox-static scanner findings
  are stored as `signal_only`, and whitebox agentic findings are stamped with
  static proof states without changing non-whitebox module modes such as
  `taint-iris-next` `hunt`.
- Remaining work: WB-005 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files. This iteration continued in the
    clean isolated clone at `/tmp/kuzushi-ux2-clone.PJaRge`, which contains the
    active pushed Stage 2 and WB-001 through WB-003 state.
  - The isolated clone still does not have its own `node_modules`; the eval
    used a temporary symlink to the primary checkout's installed dependencies,
    then removed the symlink before commit.

### Iteration 31 - WB-003

- Task attempted: scrub Rust scanner subprocess environments so static scanner
  children do not inherit credential-shaped operator environment variables.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/scan.rs`
- Tests/checks run:
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core scanner_env`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-core semgrep`
  - `cargo test -p kuzushi-core codeql`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean clone
- Result: implementation complete. Semgrep and CodeQL subprocess launches now
  call a shared scrubbed scanner environment helper that clears inherited env
  and only restores a narrow non-secret allowlist. Focused fake-scanner tests
  set `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and `DATABASE_URL` in the parent
  process and prove those names are absent in both Semgrep and every CodeQL
  child invocation. The existing Rust dependency-hygiene scanner remains
  deterministic/offline and does not spawn dependency prefetch subprocesses.
  WB-003 is marked `passes: true` in the PRD after the story gate and focused
  checks passed.
- Remaining work: WB-004 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files. This iteration continued in the
    clean isolated clone at `/tmp/kuzushi-ux2-clone.PJaRge`, which contains the
    active pushed Stage 2 and WB-001/WB-002 state.
  - The isolated clone still does not have its own `node_modules`; the eval
    used a temporary symlink to the primary checkout's installed dependencies,
    then removed the symlink before commit.

### Iteration 30 - WB-002

- Task attempted: remove shell/write execution from default whitebox agent
  tools by making the Rust agent query contract carry an explicit
  `whitebox-static` tool policy and teaching the pi-agent-core bridge to build
  only read-only repository tools for that profile.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `crates/kuzushi-core/src/runtime.rs`
  - `crates/kuzushi-core/src/whitebox_static.rs`
  - `crates/kuzushi-core/src/lib.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-core/src/carlini_threat_hunt.rs`
  - `crates/kuzushi-core/src/systems_hunt.rs`
  - `crates/kuzushi-core/src/patch.rs`
  - `crates/kuzushi-core/src/threat_model.rs`
  - `crates/kuzushi-core/src/variant_ndiff.rs`
  - `crates/kuzushi-core/src/x_ray.rs`
  - `crates/kuzushi-openai/src/lib.rs`
  - `crates/kuzushi-tui/src/app.rs`
  - `scripts/pi-agent-core-bridge.mjs`
- Tests/checks run:
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core whitebox_agent_tools`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-core`
  - `cargo test -p kuzushi-openai`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `node --check scripts/pi-agent-core-bridge.mjs`
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean clone
- Result: complete. `AgentQueryRequest` now carries an `AgentToolPolicy`;
  whitebox-static SAST agent requests use the read-only `Read`, `Glob`, `Grep`,
  and `LS` policy, and validation rejects `Bash`, shell execution, `Write`,
  edit, patch, and non-repo-read-only tools. The Node bridge constructs only
  those read-only repo tools for the whitebox profile and blocks forbidden or
  unexpected tool calls before execution. The full core suite also passes after
  separating SAST `mode=standard|whitebox-static` from taint-next
  `mode=plan|hunt`. WB-002 is marked `passes: true` in the PRD after the story
  gate and focused checks passed. The implementation commit was pushed to
  `origin/main` as `ac4bd30`.
- Remaining work: WB-003 through WB-022.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale with staged Stage 2 files. This iteration continued in the
    clean isolated clone at `/tmp/kuzushi-ux2-clone.PJaRge`, which contains the
    active pushed Stage 2 and WB-001 state.
  - The isolated clone still does not have its own `node_modules`; the eval
    used a temporary symlink to the primary checkout's installed dependencies,
    then removed the symlink before commit.

### Iteration 29 - WB-001

- Task attempted: create the Stage 3 whitebox-static scaffolding and add an
  explicit Rust `whitebox-static` SAST mode gate that disables verification,
  PoC/dynamic/crypto-behavioral execution toggles, patching, auto-patching,
  and execution proof states before `sast:scan` dispatch continues.
- Files changed:
  - `tasks/kuzushi-whitebox-static.prd.json`
  - `progress/kuzushi-whitebox-static.progress.md`
  - `scripts/ralph-kuzushi-whitebox-static.sh`
  - `evals/kuzushi-whitebox-static/run.ts`
  - `docs/kuzushi-whitebox-static.md`
  - `package.json`
  - `crates/kuzushi-core/src/whitebox_static.rs`
  - `crates/kuzushi-core/src/lib.rs`
  - `crates/kuzushi-core/src/modules.rs`
  - `crates/kuzushi-cli/src/main.rs`
  - `crates/kuzushi-cli/tests/cutover_cli.rs`
- Tests/checks run:
  - `cargo fmt --all`
  - `cargo test -p kuzushi-core whitebox`
  - `cargo test -p kuzushi-cli --test cutover_cli whitebox`
  - `pnpm eval:kuzushi-whitebox-static` (failed before the script change because
    the direct `tsx` CLI tried to listen on an IPC pipe and hit `EPERM`)
  - `TMPDIR=/private/tmp pnpm eval:kuzushi-whitebox-static` (same direct `tsx`
    IPC failure)
  - `node --import tsx evals/kuzushi-whitebox-static/run.ts` (initially exposed
    missing exact docs phrases, then passed after docs wording was updated)
  - `pnpm eval:kuzushi-whitebox-static` with the primary checkout's
    `node_modules` temporarily symlinked into the clean clone
  - `cargo fmt --all --check`
  - `bash -n scripts/ralph-kuzushi-whitebox-static.sh`
  - `node -e "JSON.parse(require('fs').readFileSync('tasks/kuzushi-whitebox-static.prd.json','utf8'))"`
- Result: complete. `sast:scan` now accepts `mode: "whitebox-static"` and the
  Rust CLI exposes `kuzushi scan --mode whitebox-static`. The mode sanitizes
  verification, PoC/harness execution, dynamic analysis, crypto behavioral
  testing, patching, auto-patching, runtime exploitability claims, and
  execution proof states before SAST dispatch, then records a static-only policy
  object in run output and artifacts. The Stage 3 PRD, progress file,
  automation script, eval stub, and docs now exist; WB-001 is marked
  `passes: true` in the PRD after focused gates passed.
- Remaining work: commit and push WB-001, then start WB-002.
- Blockers or repo facts that contradicted this prompt:
  - The primary checkout under `/Users/operator/VibeCode/open-sourced/kuzushi`
    remains stale at the Stage 1 bridge commit with staged Stage 2 changes.
    Stage 2 completion and the active pushed state are in the clean isolated
    clone at `/tmp/kuzushi-ux2-clone.PJaRge`, so this Stage 3 slice continues
    there to preserve the ordered commit/push gates.
  - The prompt requested wiring `eval:kuzushi-whitebox-static` directly to
    `tsx evals/kuzushi-whitebox-static/run.ts`, but the direct `tsx` CLI cannot
    open its IPC pipe in this sandbox (`listen EPERM`). The package script uses
    the same loader through `node --import tsx ...` so `pnpm
    eval:kuzushi-whitebox-static` is runnable.
