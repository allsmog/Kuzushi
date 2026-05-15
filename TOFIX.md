# Kuzushi Product Fixes

Generated: 2026-05-14

This file is a product-fix ledger for Kuzushi itself. Target-specific security
findings, including curl findings, do not belong here.

## Fixed In This Pass

- `systems-hunt` root-target discovery now skips non-production directories by
  default: `docs`, `doc`, `examples`, `example`, `tests`, `test`, `fixtures`,
  and `__tests__`. This prevents broad production hunts from spending their
  top surface budget on sample or test code before `lib/` and `src/` surfaces.
- Added `includeNonProduction` / `include_non_production` as an explicit
  systems-hunt input escape hatch for operators who intentionally want docs,
  examples, fixtures, or tests in scope.
- `uaf-hunt:hunt` and other tool-loop users can now run with
  `openai:*` / `openai-codex:*` models. `openai-codex:*` uses the same
  pi-ai completion path as other working Codex modules with a strict JSON
  step contract; direct OpenAI Responses function-calling remains available
  for plain `openai:*`.
- `uaf-hunt:hunt` now defaults repo-walking grep to production C/C++ files and
  excludes docs/examples/tests/fixtures unless `includeNonProduction` /
  `include_non_production` is explicitly set.
- CLI/TUI tool-run completion now loads the original `summary.json` before
  marking a run complete or failed, preserving the original `startedAtUnix`
  and input artifact. New live tool runs include `processId`; summary
  inventory/load repairs dead `running` entries to `interrupted` when the
  owning process no longer exists.
- `systems-hunt` now emits an explicit trace step listing every selected
  surface file, start line, and kind before the invariant/trigger/finding
  LLM phase.
- Tool-loop modules now have a runtime preflight hook. `uaf-hunt:hunt` calls
  it before spawning clang or entering the agent loop, and the traced runtime
  records preflight success/failure in `trace.jsonl`. For OpenAI/Codex models
  the bridge now checks Responses API access up front instead of failing at
  step 0 after analysis setup has started.
- `threat-intel:harvest` now declares its documented JSON-only `cves` input
  as a required structured option, so generic tool-input validation no longer
  rejects harvest requests before dispatch.
- `carlini-threat-hunt:run` now prioritizes exact threat-model
  `affectedFiles` in prompt inventory before the generic repository walk,
  expands high-impact business/security keywords used for actor routing, and
  reports prompt inventory coverage (`promptInventoryFiles` and
  `threatFocusedPromptFiles`) so a zero-finding run is easier to judge.
- `systems-hunt` now rejects under-evidenced LLM candidates before persistence
  when they have no evidence, no invariant link, no trigger link, no cheap
  verification flag, and no positive corroboration status. Rejected candidates
  are still written as artifacts for audit, but no longer count as findings.
- `carlini-threat-hunt:run` now explicitly tells actors that the run is
  prompt-only and cannot execute tools, shell commands, grep, or file reads.
  Actor response artifacts now label any tool-shaped JSON prelude as ignored
  and not executed, so operators do not mistake prompt text for evidence
  collection.

## Validation Runs

- `cargo test -p kuzushi-core systems_hunt --quiet` passed: 30 systems-hunt
  tests.
- Patched root-target `systems-hunt:systems-context-gatherer` over
  `/workspaces/curl` ranked production surfaces first: `lib/http1.c`,
  `lib/headers.c`, `lib/mqtt.c`, `lib/dynhds.c`, `lib/curlx/dynbuf.c`,
  `lib/bufq.c`, `lib/http_aws_sigv4.c`, `lib/ftplistparser.c`,
  `lib/http_proxy.c`, `src/var.c`, `lib/http.c`, and `lib/vquic/vquic.c`.
- Bounded root-target `systems-hunt:systems-hunt` completed after the fix:
  run `run-1778773312-81adafe285d8`, 0 findings, result artifact present.
- `cargo test -p kuzushi-core run_artifacts --quiet` passed: 17 run-artifact
  tests.
- `cargo test -p kuzushi-openai next_step_bridge --quiet` passed: 2 bridge
  round-trip tests.
- `cargo test -p kuzushi-cli
  cli_tool_completion_preserves_started_summary_and_input_artifact --quiet`
  passed.
- Local fake OpenAI Responses smoke test passed for
  `openai-codex:gpt-5.5` `next-step`: returned a `tool_call` with parsed
  arguments and no live token spend.
- Broader production-biased curl `systems-hunt:systems-hunt` run completed:
  run `run-1778775368-d0f56d5ff284`, 8 production surfaces, 1 candidate
  persisted. Artifact hygiene fix is visible: `summary.json` preserved
  `startedAtUnix` and lists both `input` and `result`.
- `uaf-hunt:hunt` against curl with generated
  `build-kuzushi/compile_commands.json` reached the fixed OpenAI next-step
  bridge, then failed cleanly with OpenAI `401` missing
  `api.responses.write`. This is no longer the old Anthropic-only bridge
  blocker; it is credential scope/readiness.
- After the preflight fix, `uaf-hunt:hunt` no longer depends on direct
  OpenAI Responses function-call scope for `openai-codex:*` tool loops. The
  bridge now uses the same pi-ai completion path as the OpenAI/Codex modules
  that already worked, with a strict JSON step contract. Smoke run
  `run-1778786903-f3a64676e2da` completed with `tool-loop preflight ok`,
  four bounded next-step turns, and no `api.responses.write` failure.
- `cargo test -p kuzushi-core uaf_hunt --quiet` passed: 23 uaf-hunt tests,
  including production-scope parser/glob coverage.
- Installed `clangd` in the test environment after the first full curl run
  reached `mcp-clang` and reported `clangd not on PATH`.
- Full production-biased curl `uaf-hunt:hunt` completed after installing
  clangd: run `run-1778790649-51db33c025ea`, 20 steps, 1 clang call, not
  truncated, 0 findings. The transcript investigated `src/tool_operate.c`
  `per->url` lifetime through `del_per_transfer` callers and ended with
  `{"findings":[]}`.
- `cargo test -p kuzushi-core capabilities::carlini_threat_hunt::tests
  -- --nocapture` passed: 9 Carlini tests, including business-impact actor
  routing and threat-focused prompt inventory coverage.
- `cargo test -p kuzushi-core
  exposes_option_specs_for_visible_tool_descriptors -- --nocapture` passed
  and verifies `threat-intel:harvest` exposes required `cves` metadata.
- Patched Matomo `carlini-threat-hunt:run` final rerun completed:
  run `run-1778800727-ac0c662f547d`, persisted run
  `885b6534-6078-469e-9440-8d84c0675aed`, 3 actors, 80 prompt source
  files, 22 threat-focused prompt files, 0 findings. Prompt artifacts now
  include threat-focused files such as `core/Auth.php`, `core/Cookie.php`,
  `core/API/Request.php`, `core/DataAccess/LogQueryBuilder.php`,
  `core/API/Proxy.php`, and `.github/workflows/release.yml` before generic
  inventory.
- `cargo test -p kuzushi-core systems_hunt --quiet` passed after adding the
  under-evidenced candidate rejection guard: 31 systems-hunt tests.
- `cargo test -p kuzushi-core carlini --quiet` passed after adding the
  prompt-only actor guard and ignored tool-prelude artifact labeling:
  16 Carlini tests.

## Still To Fix

- Run inventory should classify legacy scan artifacts that have raw
  `{ok, output, data}` summaries and `triage.jsonl` / `verify.jsonl` but no
  top-level `status` or `tool` fields.
- `x-ray` artifacts are written to `<target>/x-ray`, while operators often
  expect `<target>/.kuzushi/x-ray`. Decide whether to keep the public contract
  as `x-ray/` or mirror/symlink it from `.kuzushi/x-ray` inside Kuzushi instead
  of relying on manual compatibility links.
- `taint-iris-next:hunt` emits useful plan/evidence summaries but does not
  normalize those into `.data.findings[]` or persisted finding records. Decide
  whether those triage summaries are findings, candidate records, or evidence
  artifacts, then persist them consistently.
- Tool input validation should make unsupported knobs discoverable. Example:
  `reasoningEffort` was rejected by `taint-iris-next`; either expose the option
  where supported or return a clearer supported-options error.
## Suggested Next Scans After These Fixes

- Run a broader root-target `systems-hunt:systems-hunt` now that production
  surface selection is fixed, for example `maxSurfaces` 8-12 with one trigger
  hypothesis per surface.
- Add a broader run-artifact hygiene test for orphan run directories and legacy
  scan summaries; stale `running` summaries now have focused coverage.
