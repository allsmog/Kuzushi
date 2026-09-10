# Releasing Kuzushi

The canonical changelog lives in [CHANGELOG.md](./CHANGELOG.md). Update it as
part of every release commit.

## Export compatibility notes

- Spend databases add a durable ledger identity and investigation allowance
  revision/reservation tables. Existing dollar rows and operation caps retain
  their meaning. Deposits now read current operation caps and reserve within a
  SQLite write transaction across workers. Stage failures or incomplete cost
  receipts no longer refund context-generation deposits as zero. These are
  estimated commitments, not guaranteed maximum provider charges.
  The additive `kuzushi_core::allowance` API uses version-1 approval/snapshot
  documents with explicit model, call limits, protected review and revision
  checks. `AgentRuntime::with_allowance_binding` opts a runtime into host-bound
  accounting. The bundled LangGraph bridge reserves each provider attempt,
  including internal turns and transport retries, and disables hidden SDK
  retries in this mode. Tracing preserves the binding. Other adapters reject
  binding unless they implement this contract. Supported built-in descriptors
  expose the additive JSON `allowanceRef` option. Shared prepared dispatch
  validates it and binds the runtime before preflight; nested dispatch cannot
  replace inherited accounting. Ordinary unbound calls retain their existing
  behavior. This API does not itself approve an investigation or job list.

- `campaign:approve-allowance` records exact limits under explicit authorization;
  `campaign:allowance` reads them without creating a spend ledger. Approval is a
  Map preparation action with `phaseResult=false`, not an accepted Map or Scan.
  The shell confirmation shows the model, revision, total calls and protected
  review allocation. Its current card requires 80×24 before approval; smaller
  terminals preserve the pending request and support cancellation. A dedicated
  narrow-terminal allowance editor remains in progress. No jobs start when an
  allowance is approved.

- `campaign:study` compiles the existing scan-batch format without starting
  children, with three passes and one worker by default. Its additive
  `requiresWorkApproval` marker blocks launch until exact plan approval.
  `campaign:approve-allowance` optionally accepts `campaignId`,
  `campaignPlanSha256`, `campaignJobs` and `maxJobAttempts` to bind those jobs.
  Approval/snapshot version 1 gains an optional `workPlan`; Rust struct-literal
  callers should set it to `None` for legacy allowance-only behavior. The
  additive SQLite `investigation_work_attempts` table preserves failed,
  canceled and interrupted starts. Revised approvals cannot erase consumed
  attempts or reuse their identities for changed input/source/configuration.
  The campaign dispatcher attaches allowance references automatically and
  counts quota failures against approved attempt limits. Shared dispatch
  verifies the job and atomically claims it before executor entry. These plan
  approvals currently support discovery scan batches; immutable context
  isolation and review/learning job planning remain in progress. The shell
  requires 120×36 for the combined work/allowance receipt and preserves the
  pending request on smaller screens. Older campaign plans retain their
  existing launch contract.

- Source indexing now evaluates ignored directory names relative to the selected
  workspace. Repositories beneath an ancestor named `target`, `dist`,
  `node_modules` or `bazel-*` are no longer silently hashed as empty. Recompute
  older identities from affected paths before claiming unchanged dirty content;
  previously frozen study keys may correctly require a new plan.

- Runtime failure metadata adds `allowance_refused` to `run.items.schema.json`
  and `run.failures.schema.json`. Exhaustive consumers must accept this category.
  The optional `stdio-v1` provider-admission channel requires a startup
  acknowledgement within ten seconds; missing acknowledgement never falls
  back to an unaccounted call. Legacy bridge requests without an allowance keep
  their existing protocol. Unresolved reservations persist after cancellation,
  and absent dollar receipts remain unknown. Call limits do not promise a
  strict dollar ceiling. Failure handoffs offer reporting and explicit allowance
  review instead of recommending automatic stage resumption for this category.

- Tool descriptors add the `report` phase. `report:build` and `report:sarif`
  move from `fix` to `report`; tool names, outputs, saved workflow phases and
  historical receipts retain their meaning. Consumers with exhaustive phase
  enums must accept `report`. Re-approve local KWP descriptors when changing
  their phase. Reports are available at any autonomy posture and do not advance
  the persisted workflow; explicit export authorization still applies.
  Repository execution and external actions cannot use the Report phase.

- Repository size and model recommendations no longer preselect subdivision.
  The Map planner retains whole-repository work and an explicit scope action,
  including after a failed subdivision attempt.

- Repository inventory adds an optional `inspection` receipt with enumeration
  mode, entry/byte limits, omitted paths, and files inspected only as prefixes.
  Missing receipts in older artifacts mean the inspection extent is unknown.
  Prefix inspection now marks the inventory partial. Existing inventory fields
  retain their types, and existing artifacts are not rewritten.

- `pack:suggest-shards` derives at most eight candidates from one bounded
  inventory. Small repositories and parents with loose files can remain whole.
  New drafts rank extracted entry points (`signals.entrypoints`) rather than
  substring hits. New candidate IDs include a path digest to avoid slug
  collisions; saved shard manifests and scope trees are unchanged until the
  operator explicitly replaces them. Review scope references when accepting a
  new tree. `emitScopes` refuses incomplete inventory; the draft remains for
  inspection. Child scopes inherit parent context and threat-model sections.

- The interactive cost-halt action opens a cap editor instead of doubling the
  cap. Editing and cancellation preserve the halt; a specific amount above
  observed spend must be approved to continue. Unknown proposal estimates no
  longer pass a configured budget check as zero-cost work.

- Static `verify:finding` results now use `exploitable: null` for incomplete
  evidence, unsupported language, or an unresolved panel. These outcomes have
  `status: partial` and cannot replace selected proof. Consumers must handle
  null explicitly; false means the model cites evidence defeating the claim.
  `consensus.inconclusiveVotes` and `proofVerdict: inconclusive` are additive.
  Older model responses pairing false with an explicit incomplete verdict are
  normalized to null on new execution. Historical run files and selected
  evidence are not rewritten; rerun to obtain the corrected assessment.

- `verify:finding mode=empirical` now delegates through the shared `verify:exploit`
  dispatch boundary with explicit authorization and no model runtime. The public
  input contract is unchanged. Prove discloses backend availability and validates
  empirical receipt selection against the durable proof and current source.
  Historical incomplete or stale proof receipts remain inspectable; rerun before
  selecting them. No saved receipt is rewritten.

- Session transcripts add `agent_conversation` and `agent_conversation_cleared`
  events. The public Ask checkpoint retains its target/revision/Map/policy
  receipt and incomplete-turn state. It uses the existing redaction, retention
  and persistence opt-out. Historical unbound turns are not reconstructed into
  model context. No existing transcript or target run is rewritten. Oversize
  checkpoints explicitly disable recovery for that target instead of silently
  restoring an older answer; see the bounds in [operator guidance](docs/OPERATOR.md).

- Interactive Report destinations now default to `.kuzushi/reports/` instead
  of the target source root. Explicit destinations and the shared export
  format/path contracts retain their meaning; existing files are not moved.
  Destination edits save or cancel independently of export, and each format
  keeps its chosen path for the session. Report now discloses recent run-cost
  coverage without treating campaign totals as workspace spend. No campaign
  metric, run-cost record or serialized receipt is reinterpreted or migrated.

- Registered model-backed Scan outputs add `data.snapshotHash` and
  `data.treeHash` as adapter-owned source receipts. Existing result fields keep
  their meaning. Historical runs without a verifiable source receipt remain
  available for inspection; rerun them to obtain an execution-bound receipt
  before accepting work on dirty or unversioned targets. The offensive threat
  hunt now emits the same typed added/updated finding counts as Agentic SAST.
  No stored run is retroactively rewritten.

- Model-backed `threat-model:build` now includes `source-code` in its default
  `sources` list. This supplies bounded, file/line-addressed source excerpts to
  synthesis and refinement, with hashes and explicit coverage omissions.
  Explicit source lists retain their meaning; `contextMode=off` continues to
  exclude the default bundle. Code collection requires `maxSourceBytes >= 1024`.
  See [source evidence options](docs/modules.md#source-evidence-for-model-backed-map)
  for budgets, exclusions, and how to retain the previous input selection.

- Rust surface metadata now carries `sourcePolicy: rust-test-scopes-v1`.
  Production surface IDs ignore this extraction-policy marker, preserving
  their prior identities; payload digests still authenticate it. Before a new
  model run can reuse a context or explicit entry-point catalog with older
  Rust rows, rebuild with `context:build` and `entry-points:extract`. Historical
  models are not rewritten. The source projection excludes direct `#[cfg(test)]`
  scopes, `#[test]` functions and inner `#![cfg(test)]` scopes. Compound cfg
  expressions, unknown attribute macros and cross-file test-module ownership
  remain conservative candidates, not proven production reachability.

- Markdown-bundle and machine-export `derivedSourcePresent` now means that a
  finding has explicit source-grounded static proof. A constructor-generated
  source signature or automatic occurrence row remains provenance and no
  longer promotes a zero-evidence finding from `message_only` to
  `source_linked`.
- KWP `findings.create` no longer accepts worker-supplied `fingerprint`,
  `dedupKey`, or `sourceSignature` values. Those canonical identity fields are
  host-owned; module authors should use `actorFingerprint` for a producer-side
  observation id.

## Current release status

`0.24.0-alpha.14` is the next candidate. `0.24.0-alpha.13` was a failed
release attempt and was never published; do not create or reuse its tag.
Preparing a candidate does not publish npm packages, create a GitHub Release,
or change repository visibility.

## Prerequisites

- Node.js 22 or newer (`node --version`), matching `engines.node`
- GitHub CLI authentication and push access to `github.com/allsmog/Kuzushi`
- For the later tagged release only, an npm token available to the release
  workflow as `NPM_TOKEN`

## Prepare and verify a nonpublishing candidate

Run the local gates, bump every machine-owned version source, and commit the
candidate without tagging it:

```sh
pnpm check:docs
pnpm quality:architecture
pnpm quality:model-safety
pnpm quality:crap-risk
pnpm test
cargo check --workspace
cargo test --workspace
pnpm build:native
pnpm verify:pack

node scripts/bump-release-version.mjs 0.24.0-alpha.14
pnpm check:release

git add package.json pnpm-lock.yaml npm/platform-packages Cargo.toml Cargo.lock scripts/kuzushi-dynamic-module-host.mjs CHANGELOG.md RELEASING.md
git commit -m "chore: bump version to $(node -p 'require("./package.json").version')"
```

Push the reviewed commit to `main`, then dispatch `release-candidate.yml` at
that exact commit. Supply a previous reachable release tag, or a full ancestor
commit for the first release, as the quality baseline:

```sh
candidate_sha="$(git rev-parse HEAD)"
candidate_version="$(node -p 'require("./package.json").version')"
quality_base_ref="$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || git rev-list --max-parents=0 HEAD)"

gh workflow run release-candidate.yml --ref main \
  -f expected_sha="${candidate_sha}" \
  -f expected_version="${candidate_version}" \
  -f quality_base_ref="${quality_base_ref}"
```

The candidate workflow requires `expected_sha` to equal the workflow commit,
runs reusable full CI, builds all five native targets on four native runners,
installs the exact root and matching platform tarballs on all five target
runners, and uploads one
`release-candidate-artifacts` bundle. Its `release-manifest.json` receipt binds
the source commit and version to every npm package, native archive, and source
archive with byte size, SHA-256, and npm integrity where applicable. The
workflow has read-only repository permission and no npm credential.

A later tag run rebuilds these files and repeats every candidate check. It does
not promote bytes from an earlier manual candidate run.

## Repository visibility gate

This gate governs repository visibility only. Do not make the repository public
until every item below has an operator-owned receipt. It does not gate creating
a release tag or publishing to npm; see the recorded decision below.

1. Build the all-ref history rewrite in an offline mirror from the verified
   backup bundle. Record the old-to-new map for every advertised head and tag,
   and verify topology, author/committer identity and dates, metadata-only tree
   equality, the path-scoped content allowlist, and zero private identifiers or
   prohibited attribution across every rewritten ref.
2. With separate operator authorization and while the repository is private,
   force-update every advertised head and rewritten tag. Verify the remote ref
   map exactly matches the reviewed mirror before continuing.
3. Obtain GitHub Support confirmation that immutable pull-request refs and old
   sensitive object IDs have been purged from repository storage and caches.
   Verify the named old SHAs are no longer fetchable and that the contributor
   graph cannot recover the prohibited attribution. Rewriting branch and tag
   tips alone is not sufficient.
4. Confirm the Alpha14 candidate runs at the rewritten `main` commit and its
   downloaded bundle passes `node scripts/verify-release-artifacts.mjs
   <directory> <sha> 0.24.0-alpha.14`.
5. Obtain npm unpublish or registry-support cleanup for the exact
   `kuzushi@0.24.0-alpha.10` and `kuzushi@0.24.0-alpha.12` root packages. They
   contain private identifiers. Moving `latest` to Alpha14 does not make an
   exact historical version unavailable.
6. Remove or replace the corresponding root npm tarball assets on the
   `v0.24.0-alpha.10` and `v0.24.0-alpha.12` GitHub Releases. If an asset is
   replaced, record the approved clean file's SHA-256 and verify the downloaded
   bytes against it.
7. Verify the two exact npm versions are no longer downloadable, or retain the
   registry support confirmation that provides the equivalent restriction.
   Verify each GitHub Release asset list and download before recording the gate
   complete.
8. De-register and delete every self-hosted runner and restore hosted CI
   **before** the repository becomes public. `gh api
   /repos/allsmog/Kuzushi/actions/runners --jq '.total_count'` must return `0`,
   and `.github/workflows/ci.yml` and `.github/workflows/ci-full.yml` must be
   back on `runs-on: ubuntu-latest` (flip the `hosted` input default to `true`,
   or replace the expressions outright). A self-hosted runner on a public
   repository executes code from any fork pull request on the owner's machine.
   Teardown steps are in `scripts/runner/README.md`.

This work requires separate operator authorization. The release workflow does
not delete or rewrite historical registry content.

### Recorded decision, 2026-08-28: the visibility gate does not block Alpha14

Decided by the repository owner on 2026-08-28. Items 1 through 7 above were
previously written to block the Alpha14 tag as well as public visibility. They
now block public visibility only. Item 8 was added later, with the self-hosted
runner, and has always been visibility-only.

Rationale: `0.24.0-alpha.10` and `0.24.0-alpha.12` are already published and
already carry private identifiers. Publishing a scrubbed `0.24.0-alpha.14` at
the `latest` dist-tag strictly reduces exposure, because every new install
resolves to the scrubbed package instead of a contaminated one, and it is the
prerequisite for deprecating alpha.10 and alpha.12. Withholding the tag leaves
`latest` pointing at contaminated bytes and improves nothing. The repository
stays private until this gate is complete, so the history rewrite and support
confirmations remain required work rather than cancelled work.

## Publish the tagged release

The tag-triggered workflow is the sole publishing path. Create the tag only
after the candidate gate is complete and the release commit is the current
`origin/main`. The repository visibility gate above is not a tag prerequisite:

```sh
git fetch origin main --tags
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
version="$(node -p 'require("./package.json").version')"
git tag "v${version}" "$(git rev-parse HEAD)"
git push origin "v${version}"
```

`.github/workflows/release.yml` refuses a tag that does not match the package
version or current `origin/main`. It then calls the candidate workflow, rehashes
the complete receipt, publishes all five exact-version platform packages, and
publishes the thin `kuzushi` launcher last. Every npm publish uses the `latest`
dist-tag. A matching already-published file is reused; a byte mismatch fails.
Only after npm succeeds does the workflow create the GitHub Release and run the
five-platform public-package smoke.

Do not publish from a local package build. `pnpm publish:npm:go` fails closed
because `pnpm build:native` stages only the current host.

### Native platform builds

Four runners produce the five shipped platform payloads:

| Slug           | Built on              | Installed and executed on |
| -------------- | --------------------- | ------------------------- |
| `linux-x64`    | `ubuntu-24.04`        | `ubuntu-24.04`            |
| `linux-arm64`  | `ubuntu-24.04-arm`    | `ubuntu-24.04-arm`        |
| `darwin-arm64` | `kuzushi-mac`         | `kuzushi-mac`             |
| `darwin-x64`   | `kuzushi-mac` (cross) | `kuzushi-mac` (Rosetta)   |
| `win32-x64`    | `windows-2025`        | `windows-2025`            |

`kuzushi-mac` is the owner's self-hosted Apple silicon runner — see
[the darwin release legs](#darwin-release-legs-on-the-self-hosted-mac) below for
its prerequisites and the hosted escape hatch. Passing `hosted: true` (or setting
the `KUZUSHI_RELEASE_HOSTED` repository variable) restores `macos-14` for
`darwin-arm64` and `macos-15-intel` for `darwin-x64`.

`darwin-x64` is cross-compiled from the Apple silicon runner with
`rustup target add x86_64-apple-darwin` followed by a second
`node scripts/build-native-runtime.mjs` under
`KUZUSHI_NATIVE_TARGET=x86_64-apple-darwin`, and uploaded as its own
`release-candidate-native-darwin-x64` artifact. Kuzushi's native dependency set
crosses cleanly — no openssl, git2, or portable-pty; the tree-sitter grammars
and bundled `libsqlite3-sys` build through `cc`, wasmtime is cranelift-only, and
reqwest uses rustls. The x64 payload is still *installed and executed* as an
Intel payload — on a hosted Intel runner when `hosted: true`, and otherwise
through Rosetta 2 on the self-hosted Mac — so cross-compilation never replaces
execution evidence.

To cross-build one platform locally:

```sh
rustup target add x86_64-apple-darwin
KUZUSHI_NATIVE_TARGET=x86_64-apple-darwin node scripts/build-native-runtime.mjs
# equivalently: node scripts/build-native-runtime.mjs --target x86_64-apple-darwin
```

Cargo writes to `target/<triple>/release` (or `$CARGO_TARGET_DIR/<triple>/release`)
and staging publishes it as `native/<slug>`. Only the five supported triples in
`scripts/native-runtime-contract.mjs` are accepted; anything else is refused
rather than mapped to a guessed slug.

`node scripts/smoke-native-runtime.mjs [slug]` still refuses to execute a slug
the host cannot run. A `darwin-x64` payload may be smoked on a `darwin-arm64`
host only with an explicit `KUZUSHI_SMOKE_ALLOW_ROSETTA=1` opt-in *and* Rosetta 2
actually installed; the receipt then records the host slug, the smoked slug, and
`"translation": "rosetta"`. The same opt-in applies to
`scripts/smoke-release-tarballs.mjs`. No other host/payload pairing is ever
unlocked.

### Darwin release legs on the self-hosted Mac

Hosted macOS runners bill at 10x, and a release touches five macOS legs: the
native build, both local-tarball smokes, and both published-install smokes. All
five default to the owner's self-hosted Apple silicon runner (labels
`self-hosted, macOS, ARM64, kuzushi-mac`), so a release spends no hosted macOS
minutes. Linux and Windows legs are unchanged, and `identity`, `assemble`,
`publish-npm`, and `github-release` stay pinned to `ubuntu-24.04` — they hold
`NPM_TOKEN` or `contents: write`, which must never reach a persistent machine.

**Owner prerequisites**, one time on the Mac:

```sh
softwareupdate --install-rosetta --agree-to-license   # translate the x64 payload
arch -x86_64 /usr/local/bin/brew install node@22      # an x64 Node under /usr/local
rustup target add x86_64-apple-darwin                 # the candidate re-runs this anyway
```

The x64 Node is not optional for the `darwin-x64` legs: npm gates
`@kuzushi/darwin-x64` on `process.arch === "x64"`, so an arm64 Node installs no
platform package. The workflow puts `vars.KUZUSHI_X64_NODE_PREFIX` (default
`/usr/local`) first on `PATH` and fails the leg loudly if no x64 Node is there.

**Escape hatch.** To run one release entirely on hosted macOS — the Mac is
offline, mid-upgrade, or suspect:

```sh
gh variable set KUZUSHI_RELEASE_HOSTED --body true
git push origin vX.Y.Z          # this release runs on macos-14 / macos-15-intel
gh variable delete KUZUSHI_RELEASE_HOSTED
```

`release.yml` forwards `hosted: ${{ vars.KUZUSHI_RELEASE_HOSTED == 'true' }}` to
both the candidate and the published smoke, so the one variable moves every
darwin leg. `workflow_dispatch` on either workflow exposes `hosted` directly.

Full detail, including how a translated leg proves it smoked the Intel payload,
is in [docs/quality/release-legs-self-hosted.md](./docs/quality/release-legs-self-hosted.md).

## Verify a tagged release

```sh
npm view kuzushi version
npm view kuzushi@0.24.0-alpha.14 dist.integrity
npm install -g kuzushi@0.24.0-alpha.14
kuzushi --version

gh workflow run published-release-smoke.yml -f version=0.24.0-alpha.14
```

## Surface Compatibility Migrations

### Unresolved deep-auditor assessments (unreleased)

The raw deep-auditor analysis now accepts `triggerable: null` for unresolved
reachability or impact. Existing Boolean JSON remains readable, and persisted
`TriageVerdict` values keep their existing format. Rust callers constructing
`VulnAnalysis` must use `Some(true)`, `Some(false)`, or `None` for `triggerable`
and handle the unresolved case explicitly. A false `implausible_trigger`
assessment without an inspected `first_link` now remains `needs_review`, with
the original rationale and an explanation retained. Existing stored decisions
are preserved; an operator must explicitly retriage to produce new decisions.

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

## Map source receipt compatibility (unreleased)

`entry-points:extract` and `module-recommender:recommend` add
`data.snapshotHash` and `data.treeHash` to successful results. Both use registered
source snapshots and reject source changes detected during execution. Existing
result fields, module names, options, and the manifest contract are preserved.

Older completed Map attempts may lack a verifiable identity for one or more
referenced runs. The shell now keeps those unresolved results inspectable and
offers a fresh run instead of accepting a result that cannot advance the journey.
Already recorded dispositions remain historical records. Rerun Map against the
current source to create a usable receipt; do not backfill or rewrite old run
identities. See [the module contract](docs/modules.md#map-result-source-identity).

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

Nested project-scope trees now write schema version 2. Newly discovered
non-root scope ids keep their readable prefix and add a path-derived suffix so
two paths that normalize to the same slug cannot collide. Refresh preserves a
valid legacy id when kind and relative path still match exactly; removed or
changed scopes remain visibly stale instead of being reassigned. Consumers
must continue treating scope ids as opaque strings.

Threat models now use an additive immutable lineage/revision store under
`.kuzushi/threat-models/`. On the first writable open, a valid legacy
`.kuzushi/threat-model.json` is imported as one lineage and remains the derived
compatibility mirror of the active revision. Read-only opens never migrate.
After migration, `manifest.json` plus its content-addressed object is
authoritative; a missing/corrupt active object is an integrity error, and a
hand-edited divergent mirror requires explicit adopt or forced-discard action.
Every new run summary may add `threatModelId` and `threatModelRevisionId`
alongside the existing content SHA. Older readers may ignore those additive
fields but must not treat the mirror as an independently writable authority.

`kuzushi scan --trials N` creates a dedicated immutable `scan-batch` campaign
plan and invokes the same prepared `sast:scan` input for each logical trial.
The deprecated `--attempts` and `--samples` spellings remain input aliases for
`--trials`; dispatcher retries remain separately controlled. Batch artifacts
add equivalence, logical-trial, occurrence, and one-controller-gate metadata.
Consumers must count at most one completed observation per logical trial and
must keep failed/parked trials outside the completed denominator.

`--workers W` is additive for scan batches. Every immutable plan records the
requested/effective worker counts and the shared resource-claim decision.
Automatic or unresolved task selection stays single-worker; CodeQL database
and cpg-rs graph users name their workspace-exclusive resource and stay
single-worker. Explicit read-safe tasks may use up to eight detached campaign
children (and never more workers than trials). The controller publishes one
atomic `gate.json` after reporting/SARIF, before applying the final exit code.
Each child publishes `batch-equivalence.json` after recomputing the frozen
worktree/config/model/scope/engine key at scan consumption. The gate binds the
logical terminal state, safe-fold blocking set, and final SARIF digest, so a
later report refuses stale controller output.
Operationally incomplete dispatch remains code 1 even when completed trials
also contain a blocking finding; code 3 is reserved for an otherwise complete
batch gate failure.

Finding identity adds a conservative `basis` and descriptor-backed
`identityFold=legacy|safe|aggressive`, `identityReconcile=auto|off`, and
`modelDedupe=off|manual|auto` controls. The shipped default fold is `safe`;
file-fallback identities still require matching source signature or dedup key,
and attack-chain findings remain fingerprint-keyed. Existing findings remain
readable and derive a conservative basis when the persisted field is absent.
Run `kuzushi findings identity-audit --target <root>` before changing any
workspace policy to aggressive reconciliation or automatic model dedupe.

Review readers now include finding-local decisions on the exact observation
they address, even when that observation has a durable identity. These records
do not propagate to other generations. Policy-aware lists use the latest
observation, preserving source/evidence history, rather than choosing an older
observation for its severity or proof rank. Existing finding and decision
formats remain readable without rewriting them; the exhaustive generation
reader keeps its prior sort order. Human-over-automated review priority and
identity-fold policy are unchanged.

`triage:run` now adds source snapshot/tree hashes to its result and marks source
changes during work as partial without erasing classifications or spend.
Completed historical Review attempts lacking this receipt require an explicit
fresh run before reuse. No model, runtime, or reconciliation default changes.

Optional PromptArmor, Shinsa, Trail of Bits, and Vuln Scout packages are no
longer bundled or auto-discovered from `node_modules`. Configure an adapter
explicitly or load it as an approved KWP integration. This prevents development
dependencies from silently changing the operator and LLM discovery surfaces.
Keep those packages out of both `dependencies` and `optionalDependencies`;
`pnpm verify:pack` rejects their accidental reintroduction, including Git URL
dependencies that would make a fresh npm install depend on GitHub availability.

## Run status vocabulary migration (unreleased)

The public run-artifact vocabulary additively includes `"blocked"` and
`"canceled"` in `run.json`, typed `items.jsonl`, `failures.json`, CLI status
filters, and terminal projections. `"blocked"` means policy or validation
refused the operation before execution; it must never be projected as failed,
skipped, or completed. `"canceled"` means an operator or budget cancellation
request reached cleanup. `"interrupted"` remains readable and is reserved for
watchdog escalation, process loss, and abnormal shutdown. `events.jsonl` is a
non-authoritative compatibility diagnostic, not a terminal-status ledger. No
existing artifact is rewritten, and readers that already tolerate unknown
additive status values require no data migration.

## Typed run-lifecycle cutover (unreleased)

New runs write `runs/<runId>/items.jsonl` as the sole authoritative execution
lifecycle. The former diagnostic trace stream and its compatibility reader were
removed before release. `events.jsonl` remains only for non-authoritative
run-start and recovered-interruption diagnostics; replay never reduces it.
Verify live/replay/plain/JSON projection equivalence and document the minimum
reader version. Never add lifecycle fields to the current `run.json` or
workflow-v1 wire shapes because older readers deny unknown fields.

Phase-attempt records keep their workflow-v1 shape while additively admitting
the serialized outcome `"blocked"`; workflow-v2 persists the same truth as
`RunItemStatus::Blocked`. This is emitted only for policy refusal, remains
unselectable, and is dual-written without rewriting old attempts. Older Kuzushi
binaries whose closed workflow-v1 enum predates `"blocked"` cannot read those
new lines, so upgrade every reader before sharing a target written by this
release. The minimum compatible reader version must be called out in the
release notes.

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
paths. Update modules and their tests before bumping the required Kuzushi host
version.
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

Managed CodeQL databases now require a content-bound promotion receipt in the
operator-owned global state store. Existing target-only databases, including
legacy `.kuzushi/codeql-db` and `.codeql/db` layouts, are intentionally not
trusted after upgrade. Rebuild them with `codeql:create-db`; Kuzushi will then
bind the database contents, source commit, nested target scope, and language to
the operator receipt before any consumer can use the database.

The empirical Rust API `verify_finding` now requires an explicit
`workspace_root` argument. Custom callers must pass the same trusted target
root that owns the finding store. Rust/C finding paths are resolved below that
root with bounded, no-follow reads; absolute paths outside it, `..` traversal,
symlinks, and oversized source files now fail as infrastructure input errors.

## If a version is already published

npm does not allow republishing the same version. Choose a new version, update
the machine-owned version surfaces with the canonical bump script, and rerun the
candidate workflow. Publish only through a new immutable release tag.

## If a release tag is wrong

Do not move or force-update a release tag. Correct the problem in a new version,
pass the candidate gates again, and create a new tag for that version.

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

## JVM Joern retirement (unreleased)

The JVM Joern integration is deleted. CPG evidence now comes from the
in-process cpg-rs engine (git-pinned `oxidized-joern` crates) — no Java, no
2 GB Joern install, no `joern-parse` subprocess.

- `kuzushi-mcp-joern` is gone; `kuzushi-mcp-cpg` replaces it (`cpg.*` tools,
  joern-compatible input schemas). `kuzushi mcp serve|health joern` is now
  `kuzushi mcp serve|health cpg`.
- The `<target>/.kuzushi/cpg.bin` artifact is obsolete. Graphs live under
  `<target>/.kuzushi/cpg-rs/<lang>.v<shape>.cpg` and build implicitly in
  seconds; `cpg:build` prebuilds them and no longer accepts `heapMb`.
- `taint-iris-next` `backend=joern` is a retired alias: it redirects to
  `backend=cpg-rs` with a warning. Rename saved configs to `cpg-rs`.
- Retired env vars (now ignored): `KUZUSHI_JOERN_BIN`, `KUZUSHI_JOERN_CPG`,
  `KUZUSHI_JOERN_TIMEOUT_SECS`, `KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS`,
  `KUZUSHI_JOERN_FLOW_SCRIPT`, `KUZUSHI_JOERN_DEBUG_LOG`, `JOERN_SERVER_URL`.
- Language coverage change: Kotlin, C#, PHP, Swift, and bytecode targets have
  no cpg-rs frontend yet and fall back to codeql/structural evidence. cpg-rs
  covers c, cpp, go, java, javascript, python, ruby, rust, scala, typescript.

## Review-session recording (unreleased)

Prospective review sessions are recorded so a later evaluation can ask whether
a trained model would have helped. All three changes are additive; a workspace
that never sets `--review-yield-shadow-model` produces none of them.

- New event kind `review-session-started`. Old readers ignore unknown kinds, so
  a log containing it replays unchanged on an earlier build; a build that has
  the kind but no `review_sessions` table simply projects nothing.
- New projection table `review_sessions`, created by
  `create_projection_schema` on every open (`create table if not exists`), so
  legacy databases gain it without a `migrate_*` step. Projection is keyed by
  `event_hash` and is replay-idempotent.
- New additive column `review_decisions.review_session_id`, added by
  `migrate_review_decision_session_column`. Deliberately **not** backfilled:
  decisions taken before sessions existed genuinely have none, and inventing a
  link would fabricate the measurement the column exists to make.
- `DecisionWrite` gains `review_session_id: Option<String>`, emitted as
  `reviewSessionId` in the `triage-decided` payload. Existing projectors read
  named keys, so old and new events coexist.
- `--review-yield-model <path>` and `--review-yield-mode <shadow|visible>` are
  an interim operator mechanism and a stopgap. They replace the earlier
  `--review-yield-shadow-model`, which was never released; there is no
  compatibility alias, because a flag that implied a mode is exactly the
  guess this pair exists to refuse. Both are shell-only, both are required
  together, and both will be replaced by a `[review_yield]` config section
  with no compatibility shim.
- `--review-yield-mode visible` adds one advisory section to the finding
  detail. It changes no ordering, no filter, no stored artifact, and no other
  displayed value; `shadow` remains silent.


## Trace cost-result migration

Consumers of `trace:expand` results should replace the legacy
`data.costUsd` + `data.costUsdExact` pair with the shared cost contract.
`costUsd` is present only for exact metering; otherwise read
`observedCostUsd` and `providerSpendUnresolved: true`. Do not interpret an
absent exact total or an observed zero as a free call. Both the top-level
result and its `data` object carry the canonical fields. Existing run
artifacts are retained unchanged.

A zero-step Trace result is a valid completed outcome. Preserve its questions
and evidence notes independently of appended step counts. New results include
source snapshot/tree identities; older results without those identities are
shown with that limitation. The reader requires a call-correlated result
receipt for complete-result recovery and reports unverifiable history rather
than silently using it as current evidence.


## Phase-result descriptor migration

`ToolDescriptor` adds `phase_result`, defaulting to `true`. The default is
omitted from serialized descriptors, preserving the identity of unchanged
tools. Rust callers using struct literals must initialize the field; descriptor
builders can use `without_phase_result()` for supporting-evidence tools.
`trace:expand` opts out. Its Prove authorization phase, workspace-write effect,
model requirement and normal JSON output remain intact.

New workflow writers reject known supporting-evidence-only attempts and their
selection. Recovery removes those attempts from the selectable phase projection
while retaining raw v1/v2 events and canonical run history. Unknown historical
tools retain existing validation and visibility. This migration does not accept,
discard, delete or rewrite old attempts and does not select another proof.
The package/file module manifest schema is unchanged.

### Revision comparison disclosure

Run comparison adds `baseSource`, `compareSource`, and `absenceCoverage` to CLI
JSON. Existing classification fields remain compatible. Source metadata includes
the complete recorded Git SHA, branch, dirty state, and available indexed-content
and snapshot hashes. Legacy hashes remain unknown; a dirty flag alone does not
identify a working tree. Hash equality does not establish complete scan coverage.

The shell and CLI use the same coverage check to separate absent findings covered
by a completed engine receipt from findings that were not reassessed. Missing or
partial receipts, missing finding snapshots, and out-of-scope paths cannot prove
absence. Nondeterministic absence never changes a finding's verdict or establishes
a fix. Existing deterministic reconciliation remains a separate compatibility
classification; this change does not add a human-confirmed fix workflow.
