# Releasing Kuzushi

## Changelog

### v0.24.0-alpha.0 — Rust/pi-agent-core cutover

**Breaking:**

- The npm `kuzushi` binary now invokes the native Rust CLI through
  `bin/kuzushi-rs.mjs`.
- The `kuzushi-ts` npm binary, `pnpm dev:ts`, and `scripts/kuzushi-dev` source
  CLI helper are removed. TypeScript remains only for published library exports,
  migration reference code, and tests.
- The old `dist/cli*` TypeScript CLI outputs are excluded from the npm tarball.
- Operator docs now describe only the Rust command surface:
  `shell`, `scan`, `findings`, `modules`, `tools`, `run`, and `config`.
  Unsupported TypeScript-era scan flags such as `--preset`, `--sarif`, `--ci`,
  and CLI `--model` are not advertised for the Rust path.

**Additive:**

- Native module/tool registry, npm-wrapper smoke coverage, and shell help tests
  verify that docs and help point at executable Rust surfaces.
- Runtime-backed tools use pi-agent-core through the Rust bridge and still
  require an explicit configured model. Missing models, scanner binaries,
  bridge commands, or plugin roots fail explicitly.

### v1.0.0 — Clean Code major refactor

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

### v0.20.0 — Module SDK hardening

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

- `kuzushi create-module` emits `kuzushiSdkVersion` + `$schema` in the
  generated manifest and uses `defineModule` + `defineTool` in `src/index.ts`.
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

## Prerequisites

- npm login: `npm whoami` should show your username
- Push access to `github.com/allsmog/Kuzushi`
- `NPM_TOKEN` secret set in GitHub repo settings (for automated CI releases)

## Manual Release (from your machine)

```sh
# 1. Make sure tests pass and build is clean
pnpm test && pnpm build

# 2. Bump version (pick one)
npm version patch --no-git-tag-version   # 0.2.0 -> 0.2.1
npm version minor --no-git-tag-version   # 0.2.0 -> 0.3.0
npm version major --no-git-tag-version   # 0.2.0 -> 1.0.0

# 3. Commit, tag, publish
git add package.json
git commit -m "chore: bump version to $(node -p 'require("./package.json").version')"
git tag "v$(node -p 'require("./package.json").version')"
npm publish --access public

# 4. Push commit + tag (triggers GitHub Release workflow)
git push origin main --tags
```

## Automated Release (via CI)

Pushing a `v*` tag triggers `.github/workflows/release.yml` which:

1. Runs the full CI suite (types, tests, coverage, e2e)
2. Publishes to npm (requires `NPM_TOKEN` secret)
3. Creates a GitHub Release with changelog and `.tgz` tarball

```sh
# If you've already published manually, just push the tag:
git push origin main --tags
```

## Setting up NPM_TOKEN for CI

1. Go to https://www.npmjs.com → Access Tokens → Generate New Token (Classic, Automation type)
2. Go to GitHub repo → Settings → Secrets and variables → Actions
3. Add `NPM_TOKEN` with the token value

## Verifying a release

```sh
npm view kuzushi version          # check published version
npm install -g kuzushi && kuzushi --version   # install and verify
```

## If a version is already published

npm doesn't allow republishing the same version. Bump and try again:

```sh
npm version patch --no-git-tag-version
npm publish --access public
```

## If you need to force-update a tag

```sh
git tag -d v0.2.0
git tag v0.2.0
git push origin v0.2.0 --force
```
