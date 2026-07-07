# Kuzushi TUI Parity Target

Source bundle: current `design/mockups/*.jsx` in this repo.

The earlier planning note referenced 137 mockups. The checked-in bundle has
136 product mockups, excluding `design/mockups/_shared.jsx`.

This matrix is a Phase 0 scope gate, not an implementation spec. It maps every
mockup file to the closest current Rust/product surface and decides whether it
belongs in the design-fidelity backlog.

## Bucket Rules

- `Implement`: include in the parity harness now. State variants should usually
  collapse onto the same Rust view with a different fixture.
- `Defer`: keep the mockup as product/design input, but do not make it a
  fidelity blocker until the backend state, command route, or product
  graduation is explicit.
- `Cut`: exclude from the committed parity target unless the product direction
  changes.

## Summary

| Bucket | Mockups | Meaning |
| --- | ---: | --- |
| Implement | 114 | Current shell/CLI/module surface, current visible module, or fixtureable state variant. |
| Defer | 17 | Deferred/adapter/quarantined module, missing domain state, or CLI-only capability without shell ownership. |
| Cut | 5 | Reference-only or contrary to the current local-first / explicit-target product scope. |

The committed set is 114 mockup files, but many are state variants of the same
screen (`sast`/`sast-running`, `catalog`/`catalog-active`, etc.). The Phase 1
snapshot harness should collapse those into one fixture family per Rust view
rather than one bespoke renderer per file.

## Matrix

| Mockup | Bucket | Current target | Phase 0 note |
| --- | --- | --- | --- |
| `actor-bind.jsx` | Implement | `ShellCommand::Actor`, `ShellView::ActorDetail`, prompt/model actor state | Treat as actor configuration variant, not a new view family. |
| `actor.jsx` | Implement | `ShellView::ActorDetail` | Existing actor detail surface; needs parity fixture/copy pass. |
| `agent-chat-stream.jsx` | Implement | `ShellView::AgentChat` | Streaming state variant of agent chat. |
| `agent-chat.jsx` | Implement | `ShellView::AgentChat` | Existing chat view. |
| `agent-refused.jsx` | Implement | agent/chat refusal and permissions/error state | Product-relevant safety state; use existing refusal/error machinery. |
| `agent-router.jsx` | Implement | router/config/permissions surfaces plus tool dispatch state | Keep generic; do not add a separate router framework. |
| `agentic-sast-running.jsx` | Implement | `agentic-sast:scan`, `ShellView::Activity` / `ShellView::ModuleRun` | Running variant. |
| `agentic-sast.jsx` | Implement | `agentic-sast:scan`, generic module view | Visible built-in module. |
| `auth-oauth.jsx` | Implement | auth login flow, `ShellView::AuthMethodPicker`, `ShellView::Auth` | OAuth in-flight state. |
| `auth-success.jsx` | Implement | `ShellView::Auth` | Success state after auth login. |
| `auth.jsx` | Implement | `ShellView::Auth` | Existing auth/model/spend surface. |
| `boot-splash.jsx` | Implement | shell launch/onboarding frame | Pure UI shell entry state; no backend blocker. |
| `budget-hard-stop.jsx` | Implement | cost-cap halt / budget guard view-models | Hard-stop variant. |
| `budget-stop.jsx` | Implement | cost-cap halt / retry card / activity prefix | Budget stop variant. |
| `carlini-running.jsx` | Defer | deferred `carlini-threat-hunt` exact-name module | Product-quarantined module; do not block core fidelity. |
| `carlini.jsx` | Defer | deferred `carlini-threat-hunt` exact-name module | Needs graduation/fixture contract before parity gate. |
| `catalog-active.jsx` | Implement | `ShellView::Catalog` / home cockpit | Active-run state variant. |
| `catalog-recent.jsx` | Implement | `ShellView::Catalog` / home cockpit | Recent activity state variant. |
| `catalog.jsx` | Implement | `ShellView::Catalog` / `ShellView::Home` | Core entry surface. |
| `chrome-rce-no-target.jsx` | Defer | deferred `chrome-rce` module | Deferred recon-assessment surface; needs product commitment. |
| `chrome-rce-target.jsx` | Defer | deferred `chrome-rce` module | Target-picker state is module-specific and not yet a shell contract. |
| `chrome-rce.jsx` | Defer | deferred `chrome-rce` module | Keep as design input for the deferred module. |
| `codeql.jsx` | Implement | `codeql:scan`, generic module/options/activity views | Visible native scanner. |
| `command-palette.jsx` | Implement | `ShellView::CommandPalette` | Existing interactive-only surface. |
| `config.jsx` | Implement | `ShellView::Config` | Existing config surface. |
| `confirm-dialog.jsx` | Implement | `confirm_card_model`, approval/cost/sandbox confirmation chrome | Overlay parity target. |
| `context.jsx` | Implement | `ShellView::Context`, `context:build` | Existing workspace context surface. |
| `cost-breakdown.jsx` | Implement | `ShellView::Cost` | Cost detail variant. |
| `cost.jsx` | Implement | `ShellView::Cost` | Existing cost surface. |
| `deep-auditor.jsx` | Defer | deferred `deep-audit` module | Product-quarantined exact-name module. |
| `dep-hygiene-stale.jsx` | Implement | `dep-hygiene:check`, generic module view | Stale/outdated dependency variant. |
| `dep-hygiene.jsx` | Implement | `dep-hygiene:check` | Visible built-in module. |
| `dep-upgrade.jsx` | Implement | `dep-hygiene:check` plus patch/report state | Upgrade-plan variant over dependency findings. |
| `design-system.jsx` | Cut | design reference only | Not a runtime screen; keep as visual reference, not parity test. |
| `diff-workspace.jsx` | Implement | `ShellView::RunDiff`, runs diff CLI/application state | Existing diff-of-runs/findings concept. |
| `doctor-failing.jsx` | Implement | `ShellView::Health` | Failure variant of doctor/health view. |
| `doctor.jsx` | Implement | `ShellView::Health` | Existing doctor/health view. |
| `empty-states.jsx` | Implement | shared empty-state machinery across catalog/workbench/activity | Cross-view fixture family. |
| `err-no-binary.jsx` | Implement | scanner/tool error state | Common missing-binary error. |
| `err-no-model.jsx` | Implement | no-silent-fallback/model policy error state | Must stay explicit; no fallback copy. |
| `err-no-plugin.jsx` | Implement | optional adapter gate error state | Plugin gate state for adapter modules. |
| `export-bundle.jsx` | Implement | `workspace:export-findings`, report/export presentation | Scope to existing local export formats. |
| `findings-empty-match.jsx` | Implement | `ShellView::Workbench` findings pane / findings filter | Empty filtered result variant. |
| `findings-filter.jsx` | Implement | `ShellCommand::FindingsFilter`, workbench findings pane | Filtered findings variant. |
| `findings.jsx` | Implement | `ShellView::Workbench` / findings list route | Current findings route folds into Workbench. |
| `help.jsx` | Implement | `ShellView::Help` | Existing help surface. |
| `history-search.jsx` | Implement | `ShellView::History` plus line-editor history search | Search variant. |
| `history.jsx` | Implement | `ShellView::History` | Existing history surface. |
| `iac-crit.jsx` | Implement | `iac-scan:scan` | Critical-results variant. |
| `iac-scan-critical.jsx` | Implement | `iac-scan:scan` | Critical-results variant; likely collapses with `iac-crit`. |
| `iac-scan.jsx` | Implement | `iac-scan:scan` | Visible built-in scanner. |
| `kb-pull.jsx` | Defer | KB/intel ingestion | `/kb pull` is not a current shell command contract. |
| `kb-search.jsx` | Defer | KB/intel search | Cross-source KB search needs backend/command ownership first. |
| `kb-show.jsx` | Implement | `ShellView::KnowledgeBase` | Detail/show variant over existing KB attachments. |
| `kb.jsx` | Implement | `ShellView::KnowledgeBase` | Existing KB/attachments surface. |
| `keymap.jsx` | Implement | `ShellView::Help`, `SHELL_COMMAND_SPECS`, keybinding view-models | Overlay/help variant; derive from command specs. |
| `load-gh.jsx` | Implement | `ShellCommand::Load`, session load result state | Keep generic load-specifier state; no GitHub-specific backend assumption. |
| `mcp-tools.jsx` | Defer | CLI `kuzushi mcp ...` | No shell `/mcp list` route yet; CLI-only for now. |
| `module-options.jsx` | Implement | `ShellView::Options` | Existing descriptor-backed options surface. |
| `modules-detail.jsx` | Implement | `ShellView::Module` | Module detail variant. |
| `modules.jsx` | Implement | `ShellView::Catalog` / module catalog | Existing modules catalog. |
| `multi-target.jsx` | Cut | none | Conflicts with explicit target consent and no silent cwd/multi-target fallback. |
| `ndiff-running.jsx` | Implement | `ndiff:*` plus Activity/ModuleRun | Running variant. |
| `ndiff.jsx` | Implement | `ndiff:*` | Visible built-in module. |
| `network-allowlist.jsx` | Defer | scope/network governance | No current shell allowlist screen; needs policy contract. |
| `network-down.jsx` | Implement | retry/throttle/error card state | Common model/network failure state. |
| `onboarding.jsx` | Implement | onboarding, target/model/planning pickers | Existing first-run flow. |
| `options-set.jsx` | Implement | `ShellCommand::SetOption`, options store mutation state | Option mutation preview/result variant. |
| `options.jsx` | Implement | `ShellView::Options` | Existing options surface. |
| `patch-applied.jsx` | Implement | `ShellView::Patch`, patch result state | Applied variant. |
| `patch-conflict.jsx` | Implement | `ShellView::Patch`, patch conflict state | Conflict variant. |
| `patch-review.jsx` | Implement | `ShellView::Patch` | Existing patch review surface. |
| `patch.jsx` | Implement | `patch:finding`, `ShellView::Patch` | Existing patch module/view. |
| `pause-resume.jsx` | Implement | `ShellCommand::Pause`, `ShellCommand::Resume`, Activity state | Existing session control state. |
| `plain-mode.jsx` | Implement | `render_plain_app`, `plain_render_mode` | Plain renderer parity anchor. |
| `plan-preview.jsx` | Implement | planner state, `ShellCommand::Plan`, prerequisite/plan cards | Plan preview variant. |
| `plan.jsx` | Implement | planner state, `ShellView::PlanningPicker` / plan card | Existing planning flow. |
| `pre-commit.jsx` | Cut | none | Git hook UI is outside the current golden path and not a shell command. |
| `prompt-armor-red-flag.jsx` | Defer | optional `prompt-armor` adapter | Adapter visibility/backend state must be committed first. |
| `prompt-armor.jsx` | Defer | optional `prompt-armor` adapter | Do not build a bespoke UI ahead of adapter product ownership. |
| `prompt.jsx` | Implement | prompt editor/show/tune state | Existing prompt command surface. |
| `prompts.jsx` | Implement | `ShellView::PromptsEditor` | Existing prompt editor surface. |
| `quit-confirm.jsx` | Implement | exit request / confirmation state | Overlay parity target. |
| `randori.jsx` | Implement | `randori:pasta`, threat-model artifact view | Visible built-in module. |
| `rate-limited.jsx` | Implement | retry/throttle banner state | Common runtime error state. |
| `recon.jsx` | Implement | `recon:*`, bounty/recon import surfaces | Existing recon module path; keep generic. |
| `replay-scrub.jsx` | Implement | `ShellView::Replay` | Replay scrubber/state variant. |
| `replay.jsx` | Implement | `ShellView::Replay` | Existing replay surface. |
| `run-controls.jsx` | Implement | cost/config/options/prompts controls | Compose from existing surfaces; no new control plane. |
| `run-inspect.jsx` | Implement | `ShellView::Runs`, `ShellView::Trace`, run artifact detail | Detail variant. |
| `runs-list.jsx` | Implement | `ShellView::Runs` | Runs list variant. |
| `runs.jsx` | Implement | `ShellView::Runs` | Existing runs surface. |
| `sandbox-states.jsx` | Defer | permissions/sandbox policy | No current `/sandbox` shell route; needs command/domain decision. |
| `sast-running.jsx` | Implement | `sast:scan`, `ShellView::Activity` | Running variant. |
| `sast.jsx` | Implement | `sast:scan`, `ShellView::SastTasks` / Activity / ModuleRun | Umbrella scan result surface. |
| `schedule.jsx` | Cut | none | No scheduler command/backend; outside current local evidence workbench. |
| `secret-scan-hits.jsx` | Implement | `secret-scan:scan` | Hits variant. |
| `secret-scan.jsx` | Implement | `secret-scan:scan` | Visible native scanner. |
| `secrets-hits.jsx` | Implement | `secret-scan:scan` | Hits/detail variant; likely collapse with `secret-scan-hits`. |
| `semgrep.jsx` | Implement | `semgrep:scan` | Visible native scanner. |
| `share-gen.jsx` | Cut | none | Signed URL sharing is not part of the local-first product contract. |
| `shinsa.jsx` | Implement | optional adapter `shinsa:*` | Adapter-backed, but product-relevant when configured. |
| `show-runs.jsx` | Implement | `ShellCommand::ShowRuns`, `ShellView::Runs` | Same fixture family as `runs`. |
| `since.jsx` | Implement | `ShellCommand::Since`, diff-scoped findings | Existing command surface. |
| `snapshot-rollback.jsx` | Defer | run/workspace snapshots | Snapshot indexing exists, rollback UI/domain is not committed. |
| `story.jsx` | Implement | `ShellView::Story` | Existing story/memo surface. |
| `tail-stream.jsx` | Implement | `ShellView::Logs` / Activity live feed | Treat as live-log variant, not a new `/tail` command unless added later. |
| `taint-iris-next.jsx` | Implement | `taint-iris-next:*` | Visible current taint/dataflow path. |
| `taint-iris.jsx` | Defer | deferred legacy `taint-iris:hunt` compatibility route | Prefer `taint-iris-next`; do not block public parity on legacy screen. |
| `tasks.jsx` | Implement | `ShellView::SastTasks` | Existing SAST task selection surface. |
| `theme-picker.jsx` | Implement | theme config/view-models | Overlay can enumerate current themes without backend work. |
| `threat-model-diff.jsx` | Implement | `ShellView::Threat`, `ShellView::RunDiff`, threat patch state | Threat diff variant. |
| `threat-model.jsx` | Implement | `threat-model:build`, `ShellView::Threat` | Existing threat-model surface. |
| `threats-scope.jsx` | Implement | `ShellView::Threat(ThreatView::Scope)` | Existing threat scope tab. |
| `threats-stories.jsx` | Implement | `ShellView::Threat(ThreatView::Stories)` | Existing threat stories tab. |
| `threats-stride.jsx` | Implement | `ShellView::Threat(ThreatView::Stride)` | Existing STRIDE tab. |
| `threats-summary.jsx` | Implement | `ShellView::Threat(ThreatView::Summary)` | Existing summary tab. |
| `tob.jsx` | Implement | optional adapter `tob:*` | Adapter-backed, but product-relevant when configured. |
| `tools.jsx` | Implement | `ShellView::Tools` | Existing tools surface. |
| `trace.jsx` | Implement | `ShellView::Trace` | Existing trace surface. |
| `triage-queue.jsx` | Implement | triage activity/queue state | Fixture over existing triage + Activity concepts. |
| `triage.jsx` | Implement | `triage:run` | Existing finding lifecycle module. |
| `tune.jsx` | Implement | `ShellView::Tune` | Existing tune surface. |
| `update-available.jsx` | Implement | update notification state | Existing update app code; needs render parity. |
| `variant.jsx` | Implement | `variant:*` | Visible built-in module. |
| `vendor-assessment.jsx` | Defer | deferred `vendor-assessment` module | Product-quarantined and not repo evidence-loop core. |
| `vendor-sbom.jsx` | Defer | deferred `vendor-assessment` / SBOM vendor state | Needs vendor domain commitment first. |
| `verify-sandbox-spinning.jsx` | Implement | verify/proof ladder sandbox state | Verification state variant. |
| `verify-sandbox.jsx` | Implement | verify/proof ladder sandbox state | Verification state variant. |
| `verify.jsx` | Implement | `verify:finding` | Existing finding lifecycle module. |
| `vuln-scout-audit.jsx` | Implement | optional adapter `vuln-scout:*`, audit/run ledger state | Adapter-backed, but product-relevant when configured. |
| `vuln-scout.jsx` | Implement | optional adapter `vuln-scout:*` | Adapter-backed, but product-relevant when configured. |
| `workspace-manage.jsx` | Implement | `ShellView::Workspace` | Workspace management variant; stay within existing commands. |
| `workspace.jsx` | Implement | `ShellView::Workspace` | Existing workspace surface. |
| `x-ray-scanning.jsx` | Implement | `x-ray:run`, Activity/ModuleRun | Running variant. |
| `x-ray.jsx` | Implement | `x-ray:run`, `x-ray:read` | Visible built-in module. |

## Harness Order

1. Build the extractor and ignored parity test harness against the `Implement`
   rows.
2. Generate fixture families by target view, not by filename.
3. Add `Defer` rows only when their backend/command contract graduates.
4. Keep `Cut` rows out of `PARITY_STATUS.md` so they do not inflate the debt
   count.
