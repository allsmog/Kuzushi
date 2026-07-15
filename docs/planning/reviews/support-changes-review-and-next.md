# Support-changes review + cleanup plan

> **Historical review — superseded:** file-existence and UI-contract claims in
> this review describe the 2026-07-09 tree. In particular, the depth-stack
> Workbench path it records was deleted by the Cockpit Spine cutover.

Reviewed: 2026-07-09, uncommitted working tree at `4ce19401d5`.
Scope: the "supporting" changes — deps (`package.json`/`pnpm-lock.yaml`),
docs (`AGENTS.md`, the DevEx proof-loop playbook, doc-comment
wording), the `kuzushi run` target-resolver unification, the WorkbenchCache
harness-file read, two clippy `useless_vec` fixes, and the new DevEx tmux
harness (`scripts/devex/`, `.claude/skills/tui-devex-audit/`, `.gitignore`).

Everything below was verified against the working tree (commands run, tests
executed, journeys replayed), not just read.

---

## TASK 1 — Findings

### F1 (HIGH, CI-blocking): deps bump breaks the `verify-pack` contract

`scripts/verify-pack.mjs:152-210` hardcodes expected `package.json` ranges
**and** exact pnpm-lock root resolution strings. The bump was not mirrored
there. Confirmed by running it:

```
$ node scripts/verify-pack.mjs
package artifact contract failed:
- pnpm-lock dependencies.undici version must be 7.22.0
- package dependencies.undici must be ^7.22.0
- package devDependencies.vitest must be ^3.0.5
- package devDependencies.@vitest/coverage-v8 must be ^3.0.5
- pnpm-lock devDependencies.vitest version must be 3.2.4(...)
- pnpm-lock devDependencies.@vitest/coverage-v8 version must be 3.2.4(...)
- pnpm-lock dependencies.@langchain/{anthropic,core,langgraph,mcp-adapters,openai} + langchain
  version must be ...(ws@8.20.1)...   [6 lines — ws suffix gone from the new lock]
```

12 violations total. `verify:pack` runs as the `verify-pack` job in
`.github/workflows/ci.yml:218`, so committing the deps change as-is turns CI
red. Fix is mechanical: update `expectedPackageDependencies` (undici
`^7.28.0`), the devDependency expectations (vitest / `@vitest/coverage-v8`
`^3.2.7`), and `expectedPnpmLockfileRootDependencyVersions` (undici `7.28.0`,
vitest `3.2.7(...)`, and the six langchain resolution strings without the
`(ws@8.20.1)` suffix).

### F2 (INFO, verify intent): the `pnpm.overrides` ws "pin" actually *evicts* ws

Before: `ws@8.20.1` was installed as openai's auto-installed optional peer
(every langchain resolution string carried `(ws@8.20.1)`). After the override
`"ws@>=8.0.0 <8.21.0": ">=8.21.0"`, ws is **absent from the resolved graph
entirely** — no `ws@` package entry in `pnpm-lock.yaml`, nothing in
`node_modules/.pnpm` (ws 8.21.0 does exist on npm; pnpm simply stopped
materializing the optional peer instead of upgrading it). This is *safe* for
Kuzushi:

- the bridge's MCP transports are stdio-only (`scripts/langgraph-bridge/mcp.mjs:53,84`);
- nothing in `src/` or `scripts/` imports `ws`;
- openai-SDK realtime/WebSocket features are unused.

If the override was meant to *upgrade* ws for an advisory, note the actual
effect is removal — which satisfies the advisory too, but is a different
mechanism than the override implies. No action needed beyond F1 (whose
expected lock strings encode this).

### F3 (LOW): deps risk assessment — everything else is quiet

- **undici `7.22.0 → 7.28.0`** (minor): no direct consumer in repo code — the
  only `undici` references outside the manifest are verify-pack's own
  expectations. No API boundary crossed.
- **vitest `3.2.4 → 3.2.7`, vite `7.3.1 → 7.3.6`** (patch): dev-only. The
  full JS suite passes on the new toolchain: 10 files, **95 tests, all green**
  (`pnpm vitest run`, 1.06s).
- **langchain family**: versions unchanged (`core 1.2.1`, `langgraph 1.4.7`,
  `anthropic 1.5.1`, `openai 1.5.3`, `mcp-adapters 1.1.3`, `langchain 1.5.2`)
  — only the ws peer suffix moved.
- **Is the bridge runtime exercised by the JS tests?** Partially. The
  langgraph-bridge tests import the pure helper modules
  (`oauth-models.mjs`, `oauth-login.mjs`, `schema.mjs`, `mcp.mjs` config) plus
  `@langchain/core` message classes. The actual agent-loop entry
  (`scripts/langgraph-bridge.mjs`, `model.mjs` network paths) is **not**
  integration-tested in JS — it's exercised through the Rust dynamic-loader
  path. Since the langchain versions didn't move, transitive-bump exposure for
  the untested surface is effectively nil this round; the residual risk pattern
  (a future transitive bump breaking the untested bridge entry) is real but
  out of scope for this diff.

### F4 (LOW, doc bug): AGENTS.md gained a dangling leaked header

`AGENTS.md` now ends with a bare `## Imported Claude Cowork project
instructions` section header with nothing under it — that string is the
header the Claude context assembler injects when rendering project memory; it
leaked into the tracked file. Since `CLAUDE.md -> AGENTS.md`, it will also
echo back into every future agent context. Delete the line.

Related cosmetic churn: `package.json` `description` had its literal em-dash
rewritten to the `—` JSON escape — semantically identical, but a tool
artifact worth reverting to keep the diff honest.

### F5 (verified GOOD): target-resolver unification is behavior-preserving

- `resolve_run_target(global)` = `target_or_global(None, global)` =
  `None.or(global)` = `global` — an identity over the previous pass-through in
  `run_tool_command` (`crates/kuzushi-cli/src/application/run_tool.rs:22-26`).
  `Command::Run` declares no command-level `--target`, so the `None` slot is
  structurally truthful.
- **No-silent-cwd-fallback intact**: `run_tool_workspace` still errors for
  workspace-default tools when the resolved target is `None`; the new test
  `unresolved_run_target_never_falls_back_to_cwd_for_workspace_tools`
  (`crates/kuzushi-cli/src/tool_requirements.rs:143-150`) proves it, and
  `target_dot_builds_a_workspace_at_the_explicitly_chosen_cwd` proves the
  explicit `.` opt-in. All 5 resolver tests pass.
- **Workspace-construction seam unchanged**: `prepare_cli_tool_run` got only a
  doc comment (`run_tool_prepare.rs:43-45`); no logic moved.
- **Confirmed duplicate**: `crates/kuzushi-cli/src/dispatch/mod.rs:131`
  `target_or_default(Option<PathBuf>, &Option<PathBuf>)` is a semantic clone
  of `support::target_or_global` (only difference: borrows + clones the
  default). Single caller: `dispatch/reporting.rs:104`. Fold it (see N2).

### F6 (verified GOOD, one nuance): WorkbenchCache harness read

`crates/kuzushi-tui/src/app/view_state/workbench_cache.rs:229-247`:

- **Stamp soundness**: stamp = `(len, Option<mtime>)`, same
  `source_file_stamp` used by every other entry. Missing file → `stamp: None`
  cached with `contents: None`; file creation flips the stamp to `Some(_)` →
  refresh. Target switch invalidates via the `cache.target == target` filter.
  The known theoretical hole — a same-length edit within the same mtime tick
  (or with a preserved mtime) serves stale content — is *deliberately
  documented by the tests themselves*
  (`harness_file_serves_cached_contents_while_stamp_is_unchanged` forges the
  mtime with `set_modified` to pin the semantics). On APFS/ext4 (ns mtime)
  this needs a same-length write inside one timestamp tick — negligible for an
  operator-edited TOML, and consistent with the pre-existing
  `SourceFileCache` contract. Sound.
- **Renderer fs profile**: `panes/phase.rs` no longer does
  `fs::read_to_string` per frame; the remaining per-frame cost is **one
  `fs::metadata` stat** inside `source_file_stamp` (the read itself is
  cached). So: read-free, not stat-free — exactly the established
  WorkbenchCache pattern, and `grep std::fs crates/kuzushi-tui/src/renderer/`
  is now clean (no direct fs in renderer code outside tests). The
  `borrow_mut()` on the cache RefCell is a single-statement temporary; no
  overlapping-borrow hazard in `harness_material_lines`.
- All 3 new cache tests pass.
- **Nuance**: the new `harness_file_path(target: &Path)`
  (`workbench_cache.rs:320-322`) re-joins `ENGAGEMENT_DIR/HARNESS_FILE`, which
  core already exposes as
  `engagement_harness_path(&WorkspaceTarget)`
  (`crates/kuzushi-core/src/engagement/mod.rs:81-83`). Both use the shared
  constants so drift risk is low, but it's a small duplication (see N6).

### F7 (verified GOOD): AGENTS.md corrections are accurate (spot-checked 4)

1. **ShellView variants** — the new list matches the enum in
   `crates/kuzushi-tui/src/app/view_state/sast_task_row.rs:90+`
   variant-for-variant, in order (`Home` … `Scene`), and `Findings`/`Finding`/
   `Plan` are indeed gone from `ShellView` (the later `Findings` hit in that
   file is a pane enum).
2. **`SHELL_COMMAND_SPEC_GROUPS`** — correct; `SHELL_COMMAND_SPECS` no longer
   exists anywhere (`commands/shell_command_specs/mod.rs:17`), and the
   `sast_task_row.rs:178` doc-comment fix matches.
3. **Viz mapping** — `viz_page_for_tool`
   (`app/command_router/handle_scene_command.rs:13-19`) maps exactly
   `taint-iris:hunt`→AttackPath and `exploit-chain:scan`→ExploitChain;
   `threat-model:build` is absent and `auto_open_workbench_dfd` exists at
   `handle_scene_command.rs:58` and is called from
   `tool_runner/run_tool/events_and_results.rs:77`. AGENTS.md's rewrite is
   right (and the CLAUDE.md symlink means the correction propagates).
4. **Depth-stack entry** — `ui_view_models/workbench_depth.rs`,
   `renderer/views/workbench/depth_stack/`, and the
   `ui.workbench_depth_stack` option
   (`app/options/show_options/option_updates.rs`) all exist as described.

The two suppression doc-comment wording fixes
(`suppression_events.rs:9`, `suppression_rule.rs:102` — proof-sounding wording
→ "checks/enforced") and the two `useless_vec` fixes
(`sorted_finding_aliases.rs:154,166`, `suppressions/domain/tests.rs:150` —
`vec![…]` → array; note the latter still `.clone()`s element 0, which is fine
for a test) are accurate and behavior-neutral.

One accuracy footnote: `docs/assessments/mode-parity.md` was **not** updated
for the depth-stack asymmetry, which AGENTS.md's own "When you add a new
feature" rule #4 requires (see N5).

### F8 (verified GOOD, minor nits): DevEx tmux harness

Ran it live: `./scripts/devex/run-journey.sh J8` → completes, honest
verdicts (2 pass / 4 review), and `tmux ls` shows **no orphaned
`kzx-devex-*` sessions afterwards**. Design review:

- **Session lifecycle**: every session is tracked in `DEVEX_SESSIONS`,
  killed by a `trap … EXIT INT TERM` (`lib.sh:13-23`) *and* per-journey in
  `run_journey` (`run-journey.sh:316`); `devex_session_start` pre-kills name
  collisions and the name carries `$$`. No orphan path found.
- **Bounded waits**: `d_wait_for` defaults to 20s and polls at 0.5s
  (`run-journey.sh:213-228`); `d_wait` is a journey-specified fixed sleep.
  Longest journey waits: 120s (J2/J16 demo) and 600s (J4, real keyed scan,
  which `require-any-env`-skips honestly without a key). Nothing unbounded.
- **Isolation**: keyless journeys redirect `HOME=@TMP_HOME` and unset the
  provider keys; targets are per-journey seeded fixtures under the gitignored
  `scripts/devex/artifacts/` (`.gitignore:71`); no journey targets `@REPO`.
  The fixture AWS key is the AWS documentation example key, labeled as such.
- **Nit 1 (LOW)** — `d_wait_for` timeout parsing (`run-journey.sh:216-218`):
  the glob `[0-9]*' '*` treats *any* needle starting with a digit and
  containing a space as `<timeout> <needle>`. `wait-for: 7 findings` would
  wait 7s for "findings" instead of matching "7 findings", and a needle like
  `12x abc` yields `timeout=12x` → arithmetic error under `set -e`. Harden
  by requiring the first token to be all digits.
- **Nit 2 (LOW)** — J8's keyless variant doesn't actually reach "mid-run":
  the offline demo completes inside the 1s window (snapshot 01 already shows
  `✓ run completed`), so the two-stage Ctrl+C fires against a *finished* run
  and the canceled→✓done honesty check is only truly exercised via the keyed
  re-run. The journey file admits this in its header; still, the audit's
  single most important check deserves a reliably-slow keyless job (see N4).
- **Nit 3 (INFO)** — `d_keys` passes its value unquoted to
  `tmux send-keys` (`run-journey.sh:195`), so a `;` in a keys line would be a
  tmux command separator, and `d_env` word-splits on spaces (no
  space-containing values). Both fine for repo-controlled journey files;
  worth a one-line comment in the README's directive table.
- `.claude/skills/tui-devex-audit/SKILL.md` is complete (frontmatter +
  run/judge/report instructions), references only files that exist, and the
  `.gitignore` change correctly un-ignores `.claude/skills/` while keeping
  hooks locked down.

---

## TASK 2 — What's next (prioritized cleanup plan)

| # | Item | Files | Effort | Kind |
|---|------|-------|--------|------|
| N1 | **Fix the verify-pack contract** (blocks CI — must land in the same commit as the deps bump): undici `^7.28.0`/`7.28.0`, vitest + `@vitest/coverage-v8` `^3.2.7`/`3.2.7(...)`, six langchain lock strings without `(ws@8.20.1)`. Re-run `pnpm verify:pack` to green. | `scripts/verify-pack.mjs:152-210` | S | Mechanical |
| N2 | **Fold `target_or_default` onto the shared helper**: delete `dispatch/mod.rs:131`, point `reporting.rs:104` at `support::target_or_global` (pass `default_target.clone()` or take it by value — it's the tail use). Keeps one target-precedence policy, per the resolver-unification's own rationale. | `crates/kuzushi-cli/src/dispatch/mod.rs:131`, `crates/kuzushi-cli/src/dispatch/reporting.rs:104` | S | Mechanical |
| N3 | **Strip the leaked AGENTS.md tail + `—` churn**: delete the trailing `## Imported Claude Cowork project instructions` header; restore the literal em-dash in `package.json` description. | `AGENTS.md` (last line), `package.json:4` | S | Mechanical |
| N4 | **DevEx harness CI wiring — recommend: keep J1–J16 out of per-PR CI.** They need a debug `kuzushi` build, tmux, and real timing windows — a flake machine on shared runners, and the REVIEW items *require* human/agent judgment by design (the skill is the judge, not CI). Instead: (a) add a `workflow_dispatch`/nightly job running the keyless smoke pair `J1 J8` with artifacts uploaded, treating only `[FAIL]` as red; (b) fix J8's keyless interrupt window first (a `KUZUSHI_DEMO_SLOW`-style knob or longer-running demo job) so the canceled→done check is real. (a) is mechanical once (b) exists. | new `.github/workflows/devex-audit.yml`; demo-scan pacing in kuzushi-core/tui | M | Decision (a), Code (b) |
| N5 | **Update `docs/assessments/mode-parity.md`** for the depth-stack asymmetry (AGENTS.md rule #4 for shell-only features) — AGENTS.md got the entry, the matrix didn't. While there, confirm the viz-mapping row (threat-model:build → Workbench DFD) is reflected too. | `docs/assessments/mode-parity.md` | S | Mechanical |
| N6 | **De-duplicate the harness path join**: add a `&Path`-based `engagement_harness_path_at(root: &Path)` in `kuzushi-core::engagement` and have both `engagement_harness_path` and the TUI's `harness_file_path` (`workbench_cache.rs:320`) call it. Low urgency — shared constants already prevent drift. | `crates/kuzushi-core/src/engagement/mod.rs`, `crates/kuzushi-tui/src/app/view_state/workbench_cache.rs` | S | Mechanical |
| N7 | **Harden `d_wait_for` timeout parsing** (F8 nit 1): only treat the first token as a timeout when it is all digits (`expr "$tok" : '[0-9]*$'`-style check, bash-3.2-safe); add a `wait-for` note to the README directive table (leading-digit needles). | `scripts/devex/run-journey.sh:213-228`, `scripts/devex/README.md` | S | Mechanical |
| N8 | **`.claude/skills/` scaffold**: nothing to finish — SKILL.md is complete and its referenced docs exist. Just commit it together with `scripts/devex/`, the two `docs/devex/` companions, and the `.gitignore` change as one unit so the skill never points at missing files. | commit hygiene only | S | Mechanical |
| N9 | **Optional, decision**: give `Command::Run` a real command-level `--target` (making `resolve_run_target`'s hardcoded `None` slot live) *or* keep the current doc-anchored helper. Current state is correct and honest; only take this if operator ergonomics ask for `kuzushi run --target …` (today only the global flag position works). | `crates/kuzushi-cli/src/cli.rs` + `tool_requirements.rs` | M | Decision |

Suggested order: N1 (CI-blocking, same commit as deps) → N3 → N2 → N5 → N7 →
N8 → N6, with N4/N9 as scheduled decisions.
