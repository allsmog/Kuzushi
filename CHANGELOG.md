# Changelog

Notable changes to Kuzushi. Release procedure lives in
[RELEASING.md](./RELEASING.md); GitHub Releases carry the per-tag commit log.

## Unreleased

**Additive:**

- Successful phase attempts now keep the durable phase workspace primary with
  a compact action receipt, and operators can browse every phase page
  without changing reality-derived workflow progress.
- Local KWP modules now accept the canonical `scan`, `review`, and `prove`
  descriptor phases while retaining the deprecated `hunt` and `confirm`
  aliases. Module and contributor guidance now describes the shipped Rust/KWP
  surface instead of the retired TypeScript SDK.

**Security:**

- Durable finding identity now rejects canonical fingerprint, deduplication,
  and source-signature overrides from KWP workers, keeps actor fingerprints as
  provenance only, and refuses exact-fingerprint reuse across different
  tool/rule structures or repository targets. New identities use a
  host-authenticated source-content locus when available, so line drift does
  not split one defect, distinct same-rule sinks remain separate, and
  cross-tool corroboration still converges.

**Fixed:**

- Shell command completion now anchors its fuzzy match: the first character
  you type must open the command or one of its words. Two stray keystrokes
  such as `xu` no longer draft `context build` (conte**x**t b**u**ild), which
  put a tool run one Enter away from a typo. Ordinary abbreviations (`cb`,
  `ctx`, `con`) are unchanged, and history and finding search keep the
  permissive match.
- `workspace:export-findings format=sarif` now emits spec-valid URIs. The
  `WORKSPACE_ROOT` base is built as a real `file:` URI instead of an
  interpolated path, so a workspace root containing a space, a non-ASCII
  character, or a Windows drive letter no longer produces a document SARIF
  consumers reject. Result locations percent-encode their workspace-relative
  path, so a repository file such as `docs/My Notes.md` resolves instead of
  breaking the location. A `\` in a path is escaped rather than treated as a
  separator, because on Unix it is an ordinary filename character.

## v0.24.0-alpha.13 · operator experience and descriptor boundaries

**Additive:**

- Module and tool descriptor contracts now live in the dedicated
  `kuzushi-descriptor` crate, while the Rust registry remains the shared
  execution boundary for scan, shell, and run modes.
- Review now exposes complete decision history, operator-specific calibration,
  stronger conflict categories, proof-band ordering, and consistent
  false-positive dismissal.

**Security and reliability:**

- Revision drift and abandoned-run recovery remain fail-closed while the shell
  now volunteers authenticated staleness, commit distance, and one-shot repair
  notices. Untracked source also participates in dirty-worktree identity.
- Proof bands, Markdown bundles, JSON evidence origin, and SARIF severity/help
  now share the same evidence-grounded classification and remediation context.
- File-scoped rescans and exact retries dispatch through the normal shared tool
  boundary instead of filtering stale findings or falling back to replay.

**Fixed:**

- Printable typing and paste are lossless across picker and planner views, bare
  `demo` follows the displayed guidance, and Review-to-Prove navigation retains
  finding identity.
- Cancellation stays nonterminal until cleanup finishes, missing cost never
  renders as zero, recovered and background runs volunteer attention, and
  quiet model/tool work uses honest distinct disclosures.
- Setup, Prove, scene, configuration, cost, quit confirmation, and narrow-width
  views now explain empty, deferred, volatile, source, and readiness state
  instead of requiring operators to infer it.
- `.kuzushi/scope.toml` host rules are now matched case-insensitively and
  ignore a trailing root dot, so `ADMIN.example.com` and `admin.example.com.`
  can no longer slip past an `[out_of_scope]` rule written as
  `admin.example.com`. CIDR rules also match bare IPv6 literals such as
  `2001:db8::1`, which previously reached recon dispatch and bounty imports
  unchecked.
- Setup no longer reports `Map plan EMPTY` and `BLOCKED` for a target whose
  recommended Map artifacts already exist. That state now reads
  `NOTHING TO RUN`, names how many cached artifacts will be reused, and the
  Start Map action states that it records the explicit Map skip instead of
  promising a run. Nothing checked while the planner still recommends work
  remains a real blocker. A task the planner still recommends because an
  earlier attempt failed or was interrupted no longer forces the blocker
  either when a later run already left its artifact on disk: Setup now reads
  the same cached-artifact reality the plan editor shows.
- Advancing the guided journey from a non-picker view now honors
  `phases.stop_after` the same way the phase picker already did, so a bounded
  journey stops where it is configured to instead of walking to the next phase.

## v0.24.0-alpha.12 — complete cross-platform release

**Fixed:**

- Native release jobs now allow enough time for Windows to compile and execute
  the platform-specific process and atomic-write contracts before packaging.
- Linux x64, Linux arm64, macOS x64, macOS arm64, and Windows x64 are all
  hard-blocking release targets; npm and GitHub publication cannot proceed
  with a missing supported archive, and release-contract checks preserve that
  five-platform assembly requirement.
- Platform-specific imports no longer produce an unused-import warning during
  the Windows native build.
- Terminal Run Focus now exposes and honors its real Back binding from both
  Prompt and Navigate state, including reopened background runs, while live
  runs keep their existing mode-toggle and cancellation behavior.
- Map no longer advertises Tab before its embedded gallery owns that key.
- Linux DevEx receipts now capture stable octal path modes without filesystem
  counters, and the real-target J25 journey accepts the truthful locked-Scan
  disclosure.

## v0.24.0-alpha.11 — Windows-native release repair

**Security and reliability:**

- Anthropic OAuth responses now fail closed when the provider omits the
  content array or returns malformed tool-call identities or arguments, so
  invalid provider output cannot enter tool execution as an empty call.
- Campaign job children retain whole-tree supervision on Windows, and detached
  shell dispatchers use explicit platform process groups with tested direct-kill
  fallback behavior.

**Fixed:**

- Windows-native builds now keep `OsStrExt` in scope where paths are encoded
  for atomic run-history publication.
- JSONL path/handle verification on Windows reuses Kuzushi's stable Win32 file
  identity adapter instead of unstable standard-library metadata methods,
  preserving replacement detection without weakening the security boundary.
- Required CI now compiles the complete Windows workspace and runs the focused
  JSONL contract before a release tag, so Windows-only source regressions fail
  the quality gauntlet during pull-request validation.
- Mutation CI now emits auditable receipts for Rust-free changes, excludes
  compiler-inactive platform adapters by explicit platform names, and protects
  the campaign log-tail, process-group, termination-fallback, and workspace
  identity contracts with focused tests.

## v0.24.0-alpha.10 — public CPG, durable cancellation, complete release gates

**Additive:**

- The default product now builds and runs against the public Oxidized Joern
  v0.1.1 graph engine, including persisted graph reopen and witnessed
  TypeScript taint-path compatibility coverage.
- Headless `kuzushi scan` now carries cooperative cancellation through normal,
  requested-input, demo, and APK execution, with two-stage SIGINT handling and
  deterministic canceled/interrupted batch exits backed by durable run truth.

**Security and reliability:**

- Ordinary CI and tag releases now require the complete default product—Rust
  lint/tests, dependency policy, coverage, mutation, package verification,
  Node 22 compatibility, and native E2E—without a private-source credential.
- CPG source paths and persisted artifacts are authenticated against canonical
  roots and the shared decoder; imported threat models are rebound to the
  current workspace tree before verification.
- Wasmtime 46.0.2 closes RustSec-2026-0222 and RustSec-2026-0223, while clean
  runner cache/debug settings keep complete-product builds within hosted disk
  limits.

**Fixed:**

- Review-yield schemas are part of the explicit package contract, so published
  tarballs include the documented model, dataset, and training-example
  surfaces without weakening fail-closed inventory checks.
- The mutation gate uses cargo-mutants' zero-based shard contract and preserves
  the tested Git build identity inside source copies, keeping lifecycle and
  checkpoint tests valid before mutants run.
- Current-attempt journey counts, deterministic coverage execution, stale
  fixtures and snapshots, surface linting, and public-engine API semantics now
  agree with the complete product gate.

## v0.24.0-alpha.9 — evidence-grounded cockpit and hardened analysis

**Additive:**

- The five-phase cockpit now keeps the full Map/Scan/Review/Prove/Fix rail
  visible, distinguishes locked pages from durable completion, and reopens
  historical phase material without treating page visits as progress.
- Map embeds the real-data visualization gallery: a source-grounded system
  summary, concrete DFD inspection, entry-point browser, and component stack
  share selection and navigation with Map-scoped full-frame zoom.
- Threat-model results carry registered source-tree identity, findings compare
  honestly across scans, and the scan worklist exposes contributor provenance
  and degraded-analysis state.
- Taint, fuzzing, chain analysis, finding review, replay, and run-lifecycle
  surfaces gained additional persisted evidence and focused operator controls.

**Security and reliability:**

- Review, default bulk triage, and chain construction consume the accumulated
  relevant finding corpus. Later observations retain identity-scoped human
  decisions, while deterministic and nondeterministic scan misses preserve
  their distinct lifecycle meaning.
- CodeQL, CPG, workspace traversal, subprocess, model-runtime, and artifact
  persistence boundaries now authenticate inputs and snapshots more tightly,
  keep cancellation bounded, and fail closed instead of changing execution
  policy silently.
- Typed run items remain the authoritative lifecycle stream, with durability,
  integrity, comparison, and same-second ordering covered by shared reducers
  and cross-surface tests.

**Fixed:**

- Map and DFD navigation now reaches concrete components, nodes, flows, and
  boundaries at narrow and wide terminal sizes while preserving cursor and
  scroll state across tabs and zoom transitions.
- Accepting a newer Map correctly reopens Scan without deleting prior findings;
  Review, Prove, and Fix no longer derive completion from a selected page,
  filter, or transient Run Focus state.
- Release, architecture, model-safety, CRAP-risk, packaging, and Rust lint/test
  gates cover the expanded native control plane and evidence contracts.

## v0.24.0-alpha.8 — bounded runtime, truthful benchmarks, responsive shell

**Additive:**

- The benchmark system now carries corpus manifests, immutable provenance,
  exact scoring and matching contracts, spend evidence, SARIF ingestion, and
  real-model/regression workflows suitable for reproducible release gates.
- The operator shell gains richer activity, permission, keymap, onboarding,
  completion, run-history, and phase-cockpit projections backed by explicit
  application/view-model boundaries and asynchronous hydration.
- Native MCP and testing surfaces expand with additional structural-analysis,
  process, run-artifact, mock-runtime, and cross-platform contract coverage.

**Security and reliability:**

- File, subprocess, prompt, model-usage, run-ledger, and patch-snapshot paths
  are bounded and validated at their owning adapters, with explicit failure,
  cancellation, provenance, and cost states instead of silent fallback.
- Workbench finding/review projections are revision-cached, background event
  work is time-sliced and wake-coalesced, and Jobs history no longer performs
  filesystem recovery on the terminal paint path.
- Process identity, atomic artifact commits, worker deadlines, and untrusted
  structured-output repair now have executable quality and platform tests.

**Fixed:**

- Keystroke-to-paint latency for the 391-finding Workbench case drops from
  63.5 ms to 35.1 ms p95 in the pinned 60-sample black-box profile.
- Completion, compact-terminal, activity, keybinding, review-queue, and
  provenance views preserve truthful selection, loading, malformed, and empty
  states without rebuilding unrelated presentation data.
- TypeScript project discovery, bootstrap/pack verification, documentation
  drift checks, and CI benchmark contracts now fail explicitly on incomplete
  or contradictory inputs.

## v0.24.0-alpha.7 — native control plane, hardened execution, phase cockpit

**Additive:**

- The Rust-native control plane now ships the CLI and every advertised MCP
  server through one versioned native-runtime contract, with platform smoke
  checks covering packaged executables and external-engine health boundaries.
- The shell gains the phase cockpit, explicit prompt/navigation modes,
  generation-safe target hydration, durable run status semantics, and richer
  evidence, proof, and remediation projections without changing headless JSON
  contracts.
- KWP modules now carry explicit tool effect, approval, workspace, path, and
  protocol-version policy through the shared registry dispatch boundary.

**Security and reliability:**

- Workspace reads, writes, subprocesses, artifact ledgers, and finding proof
  replay now use bounded, target-confined adapters with explicit cancellation
  and interruption states.
- Registry preparation rejects unknown or unsafe input before dispatch, keeps
  model/runtime selection explicit, and prevents target-local steering or
  silent execution-policy fallback.
- Release builds use the workspace Rust toolchain and exercise native runtime,
  atomic-write, cancellation, recon-process, and MCP contracts on each target
  platform before publishing.

**Fixed:**

- `cargo test --workspace` release blockers: the BDD onboarding skip-path
  scenario now asserts the Workbench cockpit handoff, and Workbench snapshots
  include the findings ledger row.
- Single-tool run mode and shell background tools now share the same
  finding-store provisioning predicate. Tools such as `cargo-audit:scan`,
  `offense:chain`, `variant:*`, SBOM, secret scan, and Android APK finding
  producers no longer drift between modes.
- The npm postinstall check now warns when the package has no native Kuzushi
  binary for the current platform, with consumer-facing remediation steps.
- Release native builds are pinned to the same Rust toolchain version as CI
  (`1.88.0`) via `rust-toolchain.toml` and the release workflow.
- `kuzushi doctor` now checks Joern and nmap availability, and auth ping
  missing-credential failures include exact `export ...` remediation.
- Unknown tool options now report valid option names and close-match hints
  instead of author-facing metadata wording.
- Dev scripts no longer depend on `/home/user`, fixed `/tmp` filenames, or a
  hardcoded `~/go/bin/ascii-image-converter` path.

**Docs:**

- Release instructions now describe the full gate set, cross-platform native
  binary staging, pack verification, and CI-driven npm publish flow.
- Mode-parity and agent docs now describe `kuzushi run` as always emitting
  JSON, without a separate `--json` flag.
- The actionlint workflow now installs actionlint from the pinned `v1.7.12`
  tag instead of downloading from upstream `main`.

## v0.24.0-alpha.4 — CI gating, offline demo, multi-platform packaging, reliability

First release where the npm package ships the documented Rust CLI on every
green-built platform.

**Additive:**

- `kuzushi scan --fail-on low|medium|high|critical` exits 3 when blocking
  findings exist (CI gating); `--sarif <path>` writes SARIF 2.1.0 straight
  from the CLI. The reference workflow gates on high and uploads to
  GitHub Code Scanning.
- `kuzushi demo`: offline first-wow — scans a vendored vulnerable fixture
  with the deterministic engines; no API key, model, or external scanners.
- The npm publish pipeline stages every green platform build
  (linux-x64/arm64, darwin-x64/arm64, win32-x64); darwin-arm64 is now a
  required release build. One binary per platform — `kz` is an argv0 alias.

**Fixed:**

- Finding identity is stable and message-independent (FNV-1a v2
  fingerprints + one-time migration): LLM rephrasing no longer duplicates
  findings, and Rust toolchain bumps can no longer resurrect history.
- Reliability triad: the Node bridge runs under a wall-clock deadline with
  kill+retry (no indefinite hangs; transient 429s no longer kill agent
  loops); the findings store uses WAL + busy-timeout + transactional
  inserts; state JSON writes are atomic (temp+rename).
- Supply chain: the required `github:` dependency on randori-plugin is gone
  (it was a Claude Code plugin, not runtime code); optional plugin deps are
  SHA-pinned.
- Trust kit: descending CHANGELOG, honest SECURITY.md versions, and a
  stated privacy promise (local-first, zero telemetry).

**Fixed (pre-release, via the consolidation/quality merges):**

- CI is hard-blocking again end to end: the DDD boundary regressions from the
  phase-workflow/security-viz work are resolved (model-ranked recommendation is
  an explicit adapter concern; chrome-layout and threat-DFD renderers consume
  view models), and the BDD onboarding features now encode the phase-driven
  launch contract (Esc skips a phase and advances; past 掛 KAKE the shell opens
  the Workbench cockpit).
- The CRAP-risk gate fails loudly when its diff base cannot be resolved
  instead of silently checking 0 files on shallow CI checkouts.

**Additive:**

- New CI gates: `cargo fmt --check`, `cargo clippy -D warnings`, and
  `cargo deny check advisories licenses sources` (see `deny.toml`); Dependabot
  watches cargo, npm, and GitHub Actions ecosystems.
- The e2e npm-wrapper smoke job is hard-blocking (all three documented flake
  sources were fixed previously).

**Internal:**

- Historical working notes moved from the repository root to `docs/notes/`.

## v0.24.0-alpha.0 — Rust/LangGraph cutover

**Breaking:**

- The npm `kuzushi` binary now invokes the native Rust CLI through
  `bin/kuzushi-rs.mjs`.
- The `kuzushi-ts` npm binary, `pnpm dev:ts`, and `scripts/kuzushi-dev` source
  CLI helper are removed. TypeScript remains only for published library exports,
  migration reference code, and tests.
- The source-only TypeScript `shell` command no longer has a TypeScript/Ink
  implementation; it exits with Rust replacement commands.
- The legacy TypeScript/Ink TUI, mock TUI harness, and React/Ink dev
  dependencies are removed now that the Rust Ratatui shell covers the operator
  surface.
- The old `dist/cli*` TypeScript CLI outputs are excluded from the npm tarball.
- Operator docs now describe only the Rust command surface:
  `shell`, `scan`, `findings`, `config`, `auth`, `modules`, `tools`,
  `doctor`, `run`, `mcp`, and `pr-comment`. Unsupported TypeScript-era scan
  flags such as `--preset`, `--sarif`, and CLI `--model` are not advertised
  for the Rust path.

**Additive:**

- Native module/tool registry, npm-wrapper smoke coverage, and shell help tests
  verify that docs and help point at executable Rust surfaces.
- Runtime-backed tools use LangGraph through the Rust bridge and still
  require an explicit configured model. Missing models, scanner binaries,
  bridge commands, or plugin roots fail explicitly.
- `kuzushi doctor` is now the Rust preflight surface for config, `.kuzushi/v2`
  state writability, findings DB openability, optional scanner binaries,
  LangGraph bridge readiness, and model/auth setup. It reports credential
  environment variable names only, never secret values.
- `kuzushi --plain shell` plus `KUZUSHI_PLAIN=1`,
  `KUZUSHI_SCREEN_READER=1`, or `KUZUSHI_LOW_BANDWIDTH=1` force strict
  line-oriented shell output with no ANSI escapes, animation, or box drawing.

## v0.21.0-dev — Clean Code major refactor (never published as v1.0.0; folded into v0.24.0-alpha.0)

**Breaking:**

- Flat runtime credential config is removed. Replace
  `agentRuntimeConfig.apiKey` / `agentRuntimeConfig.baseUrl` with an explicit
  backend slot such as `agentRuntimeConfig.claude.apiKey`,
  `agentRuntimeConfig.piAi.apiKey`, or `agentRuntimeConfig.codex.apiKey`.
- `agentRuntimeConfig` object values must use backend slots. The old
  `{"apiKey":"...","baseUrl":"..."}` shape is rejected by `config set`.
- Legacy built-in SAST tool aliases are removed. Replace names such as
  `sast:semgrep`, `sast:codeql`, and `sast:triage` with `semgrep:scan`,
  `codeql:scan`, and `triage:run`.

**Internal:**

- Shell command dispatch now routes through a table-driven command registry
  instead of hand-written slash and bare-command ladders.
- Database schema bootstrap moved behind `src/store/schema.ts`; `src/store.ts`
  remains the public compatibility facade for existing imports.
- Patch synthesis output parsing moved behind a focused parser module with
  unit tests.

## v0.20.0 — Module SDK hardening

**Breaking:**

- `ToolExecutionContext.uiStore | datastore | workspace | events` now use
  narrow handle interfaces (`HostUiHandle`, `ToolOptionStore`, `WorkspaceHandle`,
  `ModuleEventScope`) declared in `src/modules/host-handles.ts`. The concrete
  host classes are structural supersets, so existing in-tree callers continue
  to work; third parties that cast to internal host classes must migrate to
  the narrow API.
- Tool names are now required to begin with `<module.id>:` at load time.
  Loader throws `ModuleLoadError{ code: "SHAPE_INVALID" }` on violation.
  Duplicate tool names within a module are rejected.
- Built-in module IDs `n-day-diff-hunter` and `variant-hunter` renamed to
  `ndiff` and `variant` to satisfy the prefix rule. Backward-compat load
  specifiers (`--load n-day-diff-hunter`) still work.
- MCP-bridged tools default to `headless: false`. Only tools advertising
  `annotations.readOnlyHint: true && !destructiveHint` auto-dispatch in
  `kuzushi run` / pipeline mode. Opt in via `CreateMcpModuleOptions.trustHeadless: true`.

**Additive:**

- `module.manifest.json` gains `kuzushiSdkVersion` (semver string). Omitting
  it produces a warn; a future release may require it.
- `ModuleLoadError` replaces plain `Error` throws across loader / registry /
  core. Codes: `MANIFEST_MISSING`, `MANIFEST_INVALID`, `REQUIREMENTS_UNMET`,
  `ENTRY_NOT_FOUND`, `SHAPE_INVALID`, `ID_MISMATCH`, `SDK_INCOMPATIBLE`,
  `CONFIG_INVALID`. `ModuleLoadError extends Error`, so existing
  `err.message` consumers keep working.
- `ToolExecutionContext.host = { sdkVersion, capabilities }` populated by
  `CopilotCore.executeTool`. Modules probe with
  `ctx.host?.capabilities.has("workspace")` before using optional capabilities.
- `ToolExecutionContext.logger?: ToolLogger` for structured diagnostics,
  distinct from human-facing `ctx.print`.
- New `kuzushi/modules` exports: `defineModule`, `defineTool`, `ModuleLoadError`,
  `HostUiHandle`, `ToolOptionStore`, `WorkspaceHandle`, `ModuleEventScope`,
  `ToolLogger`, `HostInfo`, `parseModuleSpecifier`, `ModuleRegistry`.
- Manifest validation now Zod-backed (`src/modules/schema.ts`). JSON schema
  published at `schemas/module.manifest.schema.json` for editor autocomplete.
- `configSchema` in the manifest is validated against `moduleConfig` before
  `init()`; mismatches raise `ModuleLoadError{ code: "CONFIG_INVALID" }`.
- MCP bridge: configurable `timeoutMs` (default 60 000), auth token via
  `CreateMcpModuleOptions.authToken` or `KUZUSHI_MCP_TOKEN` env, collision-safe
  derived module IDs.

**Tooling:**

- Historical note: the legacy TypeScript CLI scaffolder emitted
  `kuzushiSdkVersion` + `$schema` in generated manifests and used
  `defineModule` + `defineTool` in `src/index.ts`. The current Rust operator
  CLI does not expose a `kuzushi create-module` command.
- `kuzushi/testing` exports expanded: `createMockToolContext` covers every
  `ToolExecutionContext` field; new helpers `createMockEventScope`,
  `createFakeRuntime`, `assertToolResult`, `expectModuleShape`.

**Docs:** new [`docs/modules.md`](./docs/modules.md) consolidates the
module-authoring guide; [`docs/mcp-server-requirements.md`](./docs/mcp-server-requirements.md)
documents the MCP server contract; [`docs/devex/06-module-sdk-assessment.md`](./docs/devex/06-module-sdk-assessment.md)
captures the audit.

**Migration checklist for existing modules:**

1. Add `kuzushiSdkVersion` (and optionally `$schema`) to `module.manifest.json`.
2. `grep` every tool `name:` and confirm it starts with your module `id`.
   Use `defineTool<"<id>">({...})` to get a compile-time check.
3. Replace `ctx.uiStore as UIStore` / `ctx.workspace as WorkspaceManager`
   casts with narrow-interface usage; add methods to the narrow interfaces
   upstream if you need a new host capability.
4. Update `kuzushi/testing` consumers — override fields via
   `createMockToolContext(overrides)` instead of reaching into undocumented
   internals.
