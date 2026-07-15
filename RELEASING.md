# Releasing Kuzushi

The canonical changelog lives in [CHANGELOG.md](./CHANGELOG.md). Update it as
part of every release commit.

## Prerequisites

- Node.js 22 or newer (`node --version`); this must match `engines.node` in the
  published package
- npm login: `npm whoami` should show your username
- Push access to `github.com/allsmog/Kuzushi`
- `NPM_TOKEN` secret set in GitHub repo settings (for automated CI releases)

## Manual Release (from your machine)

```sh
# 1. Make sure release gates pass locally
pnpm check:docs
pnpm quality:architecture
pnpm quality:model-safety
pnpm quality:crap-risk
pnpm test
pnpm check:types
cargo check --workspace
cargo test --workspace
pnpm build:clean
pnpm build:native
pnpm verify:pack

# 2. Bump the same version in package.json and workspace Cargo.toml.
#    Then let Cargo refresh local workspace entries in Cargo.lock.
npm version prerelease --preid alpha --no-git-tag-version
# Edit [workspace.package].version in Cargo.toml to that exact value.
cargo metadata --no-deps --format-version 1 >/dev/null
pnpm check:release

# 3. Commit and tag
git add package.json CHANGELOG.md
git commit -m "chore: bump version to $(node -p 'require("./package.json").version')"
git tag "v$(node -p 'require("./package.json").version')"

# 4. Push commit + tag (triggers GitHub Release workflow and npm publish)
git push origin main --tags
```

## Automated Release (via CI)

Pushing a `v*` tag triggers `.github/workflows/release.yml` which:

1. Runs the full reusable CI suite, including the hard-blocking e2e npm-wrapper smoke.
2. Builds native binaries for linux-x64, linux-arm64, darwin-x64,
   darwin-arm64, and win32-x64. Required legs block the release; best-effort
   legs are staged when they build.
3. Stages the CLI and every advertised MCP server from each green build into
   `native/<platform>-<arch>/`.
4. Executes each platform's staged CLI plus every advertised MCP health check
   with an empty inherited `PATH`, runs the platform-specific process/atomic
   tests, then runs `pnpm verify:pack` against the assembled npm tarball.
5. Publishes to npm with the multi-platform native payload (requires
   `NPM_TOKEN` secret).
6. Creates a GitHub Release with changelog, the full Node-capable npm tarball,
   and CLI-plus-MCP native archives. The native archives intentionally omit
   Node dependencies; model-backed and dynamic-Node tools use npm or source.

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

## Surface Compatibility Migrations

Before publishing a release that changes the registry surface, check
`docs/api-compatibility.md` and the deferred-surface contract. Current
compatibility folds intentionally keep old exact tool names runnable while
removing them from catalog/recommender discovery:

- `operator.keybindings` is an additive, home-scoped config surface. Empty
  binding lists mean explicit unbind; project-scoped keybinding policy is
  rejected, and invalid live edits preserve the last valid runtime map.

- shell `home`, `/home`, `/`, and `workbench` -> the selected
  Map/Scan/Review/Prove/Fix page in the Cockpit Spine, with workspace reality
  disclosed separately
- shell `findings` and `open <id>` -> Review; `report` -> the dedicated Report exit
- shell `modules` -> the contextual Capabilities overlay (`tools` is the raw inventory)
- `bounty:import-har` -> `recon:import {"tool":"har","path":"..."}`
- `bounty:import-burp` -> `recon:import {"tool":"burp-xml","path":"..."}`
- `randori:pasta` -> `threat-model:build {"methodology":"pasta"}`
- `carlini-threat-hunt:run` -> `offense-review:threat-hunt`

- `taint-iris:hunt` -> `taint-iris-next:hunt`
- `full-mode:hunt` -> `agentic-sast:scan {"strategy":"chunked"}`
- `deep-audit:run` -> `triage:run {"strategy":"deep"}`
- `classifier-gate:score` -> `triage:run {"strategy":"gate-deep"}`
- `verify:exploit` -> `verify:finding {"mode":"empirical"}`
- `shinsa:*quick-check` -> `shinsa:*scan {"depth":"quick"}`
- granular `android-apk:*` phase tools -> `android-apk:scan`

`smoke:next-step` was a hidden runtime smoke-test helper and has no migration
path.

## Five-phase Cockpit Spine and patch-lifecycle migration (unreleased)

The interactive shell has one canonical route:
`Target → Setup → Map ↔ Run Focus → Scan ↔ Run Focus → Review → Prove ↔ Run
Focus → Fix ↔ Run Focus → Report`. The old
Target → Model → Credentials → Planning wizard, generic whole-screen
Workbench, and duplicate Activity projections are superseded presentation
contracts; no production feature flag retains them. The canonical persisted
and descriptor phases are now `map`, `scan`, `review`, `prove`, and `fix`;
Report is an exit rather than a sixth phase. For one major release, descriptor,
query, CLI-autonomy, and config inputs accept deprecated `hunt` as `scan` and
`confirm` as `prove`, emit a warning, and serialize only the canonical names.
Config may not provide an old key together with its replacement. Existing run,
finding, proof, and patch artifacts are projected in place: scan records imply
Scan, triage records imply Review, verification records imply Prove, and patch
records imply Fix, with `legacy inferred` shown when no explicit phase attempt
exists.

The shell's `sast:scan` dispatch is discovery-only (`triage=false`,
`verify=false`, `autoPatch=false`). Explicit CLI full-pipeline calls remain
available, but the registry preflights their highest requested phase before
any scanner side effect. Phase attempts and dispositions are append-only
reference records under `.kuzushi/v3/workflow/`; canonical run bundles remain
the payload source of truth and discarding a result never deletes evidence.

Storage v3 additively introduces the `PatchLifecycleRecorded` event plus
`patch_lifecycle_events` and `patch_lifecycle_current` projections keyed by
`applicationId`. The event is append-only; projection rebuild/reset replays it
through the normal v3 projector. Existing event logs remain valid, absent
lifecycle rows mean “not applied,” and historical `SOUND` `PatchResult` records
must render as `draft available / not applied`. Do not synthesize application
receipts or infer apply state while migrating an old workspace.

`patch:reverify` is a new descriptor-backed, headless tool with required
`applicationId`. It replays only the originating detector and original prepared
input in the explicit workspace, refuses changed touched-file hashes, and
never chooses a substitute target, detector, runtime, provider, or model. Only
deterministic successful absence promotes the patch to `Verified`;
nondeterministic absence is `NotRediscovered` and unavailable comparison is
`Inconclusive`.

Finding exports add an optional `remediation` object in JSON/JSONL/Markdown,
SARIF properties prefixed `kuzushiRemediation`, and these flattened CSV
columns: `remediation_application_id`, `remediation_patch_run_id`,
`remediation_application_state`, `remediation_reverify_outcome`,
`remediation_reverify_run_id`, `remediation_diff_hash`, and
`remediation_touched_paths`. Consumers must tolerate the additive fields;
records with no applied lifecycle retain their prior shape/empty CSV values.
No existing finding or export record is rewritten.

Optional PromptArmor, Shinsa, Trail of Bits, and Vuln Scout packages are no
longer bundled or auto-discovered from `node_modules`. Configure an adapter
explicitly or load it as an approved KWP integration. This prevents development
dependencies from silently changing the operator and LLM discovery surfaces.
Keep those packages out of both `dependencies` and `optionalDependencies`;
`pnpm verify:pack` rejects their accidental reintroduction, including Git URL
dependencies that would make a fresh npm install depend on GitHub availability.

## Run status vocabulary migration (unreleased)

The public run-artifact vocabulary additively includes `"canceled"` in
`run.json`, `events.jsonl`, `failures.json`, CLI status filters, and terminal
projections. Consumers should treat it as a terminal status caused by an
operator or budget cancellation request. `"interrupted"` remains readable and
is reserved for watchdog escalation, process loss, and abnormal shutdown. No
existing artifact is rewritten, and readers that already tolerate unknown
additive status values require no data migration.

## Native dynamic-module policy migration (unreleased)

Local `file://` and path modules no longer become executable merely because
their specifier appears in `[operator].trusted_modules`. Before upgrading,
operators must run `kuzushi kwp approve <specifier> --grant <grant.toml>` for
each exact resolved bundle and retain the generated `kuzushi.lock`. Loading
rehashes the bundle, verifies its descriptor hash and optional Ed25519
signature chain, then runs it as a brokered KWP worker. Changed bundles require
fresh approval; revoked or mismatched entries fail before module code runs.
The old trusted-specifier list remains only for non-local compatibility forms.
The v0.1 KWP Node tier accepts one self-contained entry file. It requires the
permission-mode network boundary introduced in Node 25, adds a macOS network
sandbox, and requires Node 26.3.1 or newer on other platforms. Multi-file
directory bundles must remain on the legacy trusted path until a
content-addressed bundle format lands.

Trusted Node modules loaded with `--load` must now declare an explicit native
policy on every tool: `effect`, `approval`, `workspaceRequirement`, and a
concrete `phase` for effectful operations. `headless` remains mandatory.
Target-write, repository-execute, and external-action tools must use
`approval: "explicit"`. `repository-execute` is for repository-selected build
or test commands run in an isolated validation copy; it must disclose the
resolved commands before interactive dispatch.
Modules that omit this policy fail atomically during description, before any
tool is registered. This is an intentional fail-closed contract change; add
the fields described in `docs/modules.md` before upgrading an external module.

Dynamic descriptor options with `type: "path"` must now add a mandatory
`pathSemantics` value. This is a deliberate fail-closed migration: the host
does not infer whether an unlabelled path is a workspace read, Kuzushi state
write, target write, external read/write, or executable. Target-owned option
stores cannot supply model selectors or executable/external/write-capable
paths. Update modules and their tests before bumping the Kuzushi peer version.
The native/Node bridge also performs a protocol-version and exact package
semver handshake, so custom `KUZUSHI_DYNAMIC_MODULE_HOST` implementations must
emit the documented version envelope/handshake before payloads.

The old `dispatch_prepared_tool_with_runtime(name, Value, ...)` API remains
source-compatible, but it now re-runs canonical preparation. New Rust callers
should use `prepare_dispatch_input` and
`dispatch_prepared_input_with_runtime`, which carry an opaque preparation
proof and avoid duplicate validation.

`codeql:create-db outputPath` and `cpg:build outputPath` are now confined to
the active target's `.kuzushi/` state tree. Before upgrading, move any custom
destination into `<target>/.kuzushi/`; destinations elsewhere are rejected
instead of allowing scanner subprocesses to overwrite operator or project
files.

The empirical Rust API `verify_finding` now requires an explicit
`workspace_root` argument. Custom callers must pass the same trusted target
root that owns the finding store. Rust/C finding paths are resolved below that
root with bounded, no-follow reads; absolute paths outside it, `..` traversal,
symlinks, and oversized source files now fail as infrastructure input errors.

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

## Suppression primitive migration (unreleased)

A unified `SuppressionRule` primitive now backs all muting concepts. Notes:

- New durable store `<target>/.kuzushi/v3/suppressions.toml`. Absent file is a
  no-op, so existing workspaces are unaffected.
- The legacy `<target>/.kuzushi/v3/whitebox-suppressions.json` store is retained
  and compiled into the unified pipeline. `kuzushi suppress` now writes both.
  A later release may migrate whitebox records into `suppressions.toml` and drop
  the JSON store; no data loss in this release.
- No event-log or projection migration: the `SuppressionAdded` /
  `SuppressionExpired` / `SuppressionRemoved` event kinds and the
  `stable_findings.current_status` projection already existed. New payload fields
  are additive and ignored by old readers.
- `Finding.suppressed` is now hydrated from the projection (additive over any
  value stored in finding JSON). This lights up the pre-existing
  `status:suppressed` / `verdict:suppressed` filter tokens and the export
  `suppressed` column/SARIF `result.suppressions[]`.
