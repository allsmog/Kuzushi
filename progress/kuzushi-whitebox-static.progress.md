# Kuzushi Whitebox-Static Progress

Stage: 3 - Kuzushi whitebox-static mode
Active story: WB-004 - Add static proof taxonomy
Status: WB-003 complete in this workspace; commit/push pending

## Stage 3 Checklist

- WB-001 Add explicit whitebox-static mode: complete in iteration 29.
- WB-002 Remove shell execution from default whitebox agent tools: complete in iteration 30.
- WB-003 Scrub scanner subprocess environments: complete in iteration 31.
- WB-004 Add static proof taxonomy: pending.
- WB-005 Add static evidence graph: pending.
- WB-006 Add source span extractor: pending.
- WB-007 Normalize Semgrep findings into static evidence: pending.
- WB-008 Normalize CodeQL SARIF code flows into static evidence: pending.
- WB-009 Build deterministic repository inventory: pending.
- WB-010 Build source/sink/sanitizer/guard registry: pending.
- WB-011 Add attack-surface map from source: pending.
- WB-012 Add static proof validator: pending.
- WB-013 Constrain LLM triage to whitebox schema: pending.
- WB-014 Verify LLM citations before persistence: pending.
- WB-015 Prioritize findings by static impact: pending.
- WB-016 Add static trigger/impact narratives: pending.
- WB-017 Add variant search from statically confirmed findings: pending.
- WB-018 Add candidate Semgrep rule synthesis: pending.
- WB-019 Add whitebox false-positive memory: pending.
- WB-020 Add diff-aware whitebox PR mode: pending.
- WB-021 Add deterministic eval harness: pending.
- WB-022 Add whitebox demo fixture: pending.

## Iteration Log

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
- Remaining work: commit and push WB-003, then start WB-004.
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
