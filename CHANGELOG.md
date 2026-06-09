# Changelog

Notable changes to Kuzushi. Release procedure lives in
[RELEASING.md](./RELEASING.md); GitHub Releases carry the per-tag commit log.

## Unreleased

**Fixed:**

- CI is hard-blocking again end to end: the DDD boundary regressions from the
  phase-workflow/security-viz work are resolved (model-ranked recommendation is
  an explicit adapter concern; chrome-layout and threat-DFD renderers consume
  view models), and the BDD onboarding features now encode the phase-driven
  launch contract (Esc skips a phase and advances; past 掛 KAKE the shell hands
  off to recommendations).
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

## v1.0.0 — Clean Code major refactor

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
