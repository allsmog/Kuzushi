# Changelog

Notable changes to Kuzushi. Release procedure lives in
[RELEASING.md](./RELEASING.md); GitHub Releases carry the per-tag commit log.

## Unreleased

**Additive:**

- Local verification now leaves a signed receipt. `pnpm verify:quick:summary`
  binds its result to the commit, tree, clean/dirty state, toolchain, host, and
  a digest of the plan that ran, and states what the run does not cover;
  `pnpm verify:receipt:sign` signs it and `pnpm verify:receipt:verify` refuses
  anything unsigned, stale, dirty, failing, from another commit, or produced by
  a weakened plan. A new `.husky/pre-push` hook asks for that receipt before a
  push reaches `main`. The gate stays trust-on-owner and advisory — `git push
  --no-verify` bypasses it — but it is now auditable. See
  [docs/quality/local-verify-receipt.md](./docs/quality/local-verify-receipt.md).

**Fixed:**

- `recon:import` now says what it imported and what `.kuzushi/scope.toml`
  refused. Every native adapter gates each parsed entry against the scope file,
  but only the HAR and Burp importers disclosed the refusals: amass and httpx
  buried the count in a store note, and nuclei and nmap-xml counted it and threw
  the count away. All four then completed with `"<tool> completed for <path>"`,
  the same line whether a dump imported whole or the scope file denied every
  entry in it, so an import filtered down to nothing read as a successful one.
  The report now carries `skippedOutOfScope` and the output line names the rows
  that landed beside the entries that did not — `recon:import nuclei imported
  nothing from dump.jsonl · 1 out-of-scope skipped`. Reports for `recon:nmap`,
  `recon:subdomain`, and `recon:http-fingerprint`, which take one target and
  refuse it at dispatch, are unchanged.

- `.kuzushi/scope.toml` CIDR rules now cover the shorthand IPv4 notations a
  real client resolves. The gate tested a candidate against a range only when
  `IpAddr::from_str` accepted it, which means only the dotted quad — so
  `http://2852039166/`, `http://0xa9.0xfe.0xa9.0xfe/`,
  `http://0251.0376.0251.0376/`, and `http://169.254.43518/` matched no rule,
  while browsers, `curl`, Go, and libc `inet_aton` reach 169.254.169.254
  through every one of them. A `169.254.0.0/16` deny list therefore returned
  `Unknown` and let recon dispatch and the amass/httpx/nuclei/nmap-xml/HAR/Burp
  import gates through. Each host reading the gate already weighs now also
  yields the dotted quad the URL Standard's IPv4 parser reads it as, and a
  host rule an operator spelled the same way is compiled in both forms, so
  neither side of the comparison depends on which notation was written. A host
  whose last label is not a number stays a domain, a host the parser fails on
  contributes no candidate rather than a guessed address, and a target already
  written as a dotted quad keeps exactly the verdict it had.

- `.kuzushi/scope.toml` can no longer be walked past with a percent-escaped
  host. The gate compared rules against the authority exactly as written, so
  `https://admin.example%2ecom/panel` matched no rule naming
  `admin.example.com` — while every browser, and any client following RFC 3986
  §3.2.2, percent-decodes the domain and reaches the denied host. A deny-list
  file therefore returned `Unknown` and let recon dispatch and the
  amass/httpx/nuclei/nmap-xml/HAR/Burp import gates through. Each of the two
  parser readings the gate already weighs is now weighed in its decoded form
  too: one deny match on either refuses the target, and an allow list has to
  cover both. An escape that decodes to a code point the URL Standard forbids
  in a domain (`/`, `:`, a literal `%`, a control) names no host a client can
  reach, so it contributes no candidate rather than a guessed one, and a
  target whose host carries no `%` keeps exactly the verdict it had. IDNA is
  still not applied — a decoded non-ASCII domain is judged in the Unicode form
  it was written in, as a raw non-ASCII target already was.

- Capture imports no longer present an encoded payload as the raw HTTP
  message, and no longer drop entries without saying so. Burp marks a
  request/response `base64="true"` and HAR marks a body
  `encoding = "base64"` precisely when the payload is binary or compressed —
  a gzip'd response, an image, anything not UTF-8 text. `bounty:import-burp`
  answered a failed decode by storing the base64 text itself under
  `request_blob`/`response_blob`, and `bounty:import-har` never decoded a
  declared-base64 body at all, so evidence labeled `http-request` held
  base64 that an operator reading the finding had no way to recognize as
  undecoded. Both importers now decode the payload, keep the readable part
  of a non-UTF-8 body with its undecodable bytes shown as `U+FFFD`, and
  state in the evidence rationale exactly how the stored blob differs from
  what the capture carried; a field that does not decode keeps its literal
  text and says so. Decoding is now strict standard base64 (the `base64`
  crate, padded or unpadded), because the hand-rolled decoder accepted a
  truncated field — `"A"` decoded to an empty body and `"AAAAA"` dropped its
  last symbol, both as valid UTF-8, so the disclosure never fired on exactly
  the fields that needed it. Separately, an item with no URL was dropped from both
  importers with no counter, so `imported` plus `skippedOutOfScope` silently
  failed to add up to the capture's entry count. Those entries are now
  counted as `skippedUnusable` and named in the tool output line
  (`recon:import` and the two `bounty:import-*` verbs alike).

- A multi-language `codeql:scan` no longer hides the languages it failed to
  analyze. Per-language failures — a database that would not build, an
  analysis that died — were collected and then dropped whenever any other
  language produced a finding, so a run that never analyzed Java or C++
  reported `codeql: 4 findings under <target>` with nothing to say that two
  thirds of the repository went unscanned. This is the recommended
  invocation: the module recommender asks for `multiLanguage: true` whenever
  a target has more than one CodeQL language. Those failures now travel with
  the scan as `scanErrors`, and the report marks the run
  `(coverage incomplete: N scan errors)` and lists what was missed, matching
  what `semgrep:scan` already discloses. The hard failure when *no* language
  could be analyzed is unchanged; a run where one language succeeded with
  zero findings and another failed is now reported as an honest empty result
  with its gaps disclosed, rather than as `all language analyses failed` —
  a claim that was untrue whenever an analysis had in fact succeeded.

- The classifier gate no longer turns a response it could not read into a
  score. An unparseable answer became a neutral `0.5`, and `0.5` sits below the
  default `0.6` cold-start floor — so the fallback meant to keep a real bug from
  being rejected rejected it: the deep auditor never ran, and the finding was
  left carrying a persisted `NeedsReview` row whose confidence was `0.50` and
  whose rationale read `below adaptive triage threshold (score=0.50, …)`, a
  parse failure presented as a model judgement. An unreadable response is now
  `ParseDegraded`: it escalates to the deep auditor, trains no quantile,
  persists no triage verdict, and `classifier-gate:score` reports a null
  `score` with `parseDegraded: true` instead of a number nobody produced.
  Responses the gate can read are scored, thresholded, and recorded exactly as
  before. The score-only Rust API stays source-compatible: `should_deep_audit`
  still takes a bare score, and `LikelyVulnClassifier::score` remains as a
  deprecated wrapper that errors on an unreadable response instead of inventing
  one.

- `.kuzushi/scope.toml` can no longer be walked past with a URL that two
  parsers read as two different hosts. The gate extracted one host under RFC
  3986 rules, so `https://evil.test\@in-scope.host` presented as the in-scope
  host while a browser-derived client resolves `evil.test` — and an embedded
  tab, CR, or LF split the readings the same way. Recon dispatch and the
  amass/httpx/nuclei/nmap-xml/HAR/Burp import gates now weigh every host such a
  target could name: one deny match refuses it, and an allow list has to cover
  all of them. Ordinary targets carry none of those characters, so both
  readings agree and their verdicts are unchanged.

- Map's inventory no longer claims a web framework because a manifest happens
  to spell its name. Framework needles were matched as raw substrings of whole
  manifest text, so a Python package named `falcon-benchmarks` was reported as
  the Falcon web framework — a routing/deserialization surface claim carried by
  a coincidence. A needle now has to stand as a whole package token on a line
  that can declare a dependency, which also rules out comments and the
  manifest's own name/description/keywords fields. Declared dependencies,
  dotted Java and ASP.NET prefixes, Go module paths, and Cargo
  `[dependencies.<crate>]` headers all keep matching.

- The JOURNEY phase chip no longer flips to `Scan 2/5` partway through the
  first Map run on a target. Pre-ledger inference reads `.kuzushi/` artifacts,
  which Map tools write while the run is still going; it is now suppressed
  while a first-class Map or Scan attempt is in flight, so the chip stays on
  `Map 1/5` until an attempt actually completes and is accepted.

**Release process:**

- Routine CI now bills far fewer runner minutes without weakening a gate.
  Quick CI dropped its redundant post-merge `push: branches: [main]` run and
  skips prose-only pull requests, both CI workflows cache the Rust target
  directory, Full CI installs cargo-llvm-cov and cargo-mutants from
  checksum-verified release binaries instead of building them, its cron
  dropped from weekly to monthly, and the 90-minute mutation sweep now runs
  only behind an explicit `deep` input that release-candidate.yml always
  passes. Dependabot batches into one grouped monthly pull request per
  ecosystem. Release candidates run the same complete gauntlet as before.

- Every darwin release leg now runs on the owner's self-hosted Apple silicon
  runner, so a release spends no 10x-billed hosted macOS minutes. The native
  build, both local-tarball smokes, and both published-install smokes default to
  the `self-hosted, macOS, ARM64, kuzushi-mac` labels; the `darwin-x64` smokes
  execute the Intel payload there through Rosetta 2 under an x64 Node, and refuse
  loudly rather than skip when Rosetta or that Node is missing. Linux and Windows
  legs are unchanged, and `identity`, `assemble`, `publish-npm`, and
  `github-release` stay pinned to hosted `ubuntu-24.04` because they hold
  `NPM_TOKEN` or `contents: write`. A `hosted` workflow input — reachable on a
  tag push through the `KUZUSHI_RELEASE_HOSTED` repository variable — sends every
  darwin leg back to `macos-14` and `macos-15-intel` for one release. See
  [docs/quality/release-legs-self-hosted.md](./docs/quality/release-legs-self-hosted.md).
- `darwin-x64` is now cross-compiled on the Apple silicon release runner instead
  of on a separately billed Intel macOS build host. The release candidate builds
  five platform payloads on four runners: `macos-14` builds `darwin-arm64`
  natively and then `darwin-x64` through `--target x86_64-apple-darwin`,
  uploading each slug as its own `release-candidate-native-<slug>` artifact, so
  `assemble` still receives all five required slugs. The `darwin-x64` tarball and
  the published package are still installed and executed on a real
  `macos-15-intel` runner, so no execution evidence is traded away for the
  cheaper build.
- `scripts/build-native-runtime.mjs` accepts `--target <triple>` or
  `KUZUSHI_NATIVE_TARGET=<triple>` for the five supported Rust targets and
  forwards the selection to staging, which reads
  `target/<triple>/release` and publishes `native/<slug-for-triple>`. An
  unsupported triple is refused instead of mapped to a guessed slug, staging now
  honors `CARGO_TARGET_DIR`, and the executable suffix follows the target
  platform rather than the building host.
- Native and local-tarball smokes still refuse to execute a foreign platform
  payload. `KUZUSHI_SMOKE_ALLOW_ROSETTA=1` unlocks exactly one pairing —
  `darwin-x64` on a `darwin-arm64` host — and only when Rosetta 2 is actually
  installed; the run then executes through `/usr/bin/arch -x86_64` and records
  the host slug, the smoked slug, and `"translation": "rosetta"` in its receipt.
  No other pairing is ever unlocked, and nothing is smoked silently under the
  wrong architecture.
- The seven-item historical artifact cleanup gate is renamed the repository
- Routine CI now runs on one ephemeral self-hosted Apple-Silicon runner
  (`self-hosted, macOS, ARM64, kuzushi-mac`) on the owner's Mac, so a pull
  request costs no hosted minutes. `windows-compile` stays on
  `windows-latest`, and a new `hosted` workflow input puts every other job
  back on `ubuntu-latest` when the Mac is offline. The actionlint step no
  longer needs a Docker daemon: it runs the pinned 1.7.12 binary and refuses
  any other version. The patch-validation sandbox action is an explicit no-op
  off Linux, and `rust-cli` records in its job summary that bubblewrap and
  AppArmor were not exercised, because a green run there proves less than the
  same run on Linux. Setup, threat model, and teardown are in
  `scripts/runner/README.md`; de-registering the runner is now item 8 of the
  repository visibility gate.

- The historical artifact cleanup gate is renamed the repository
  visibility gate and now blocks making the repository public only. Creating
  the Alpha14 tag requires the candidate gate and a release commit equal to
  current `origin/main`. Recorded by the repository owner on 2026-08-28, on the
  reasoning that moving the `latest` dist-tag to a scrubbed Alpha14 reduces
  exposure for new installs and is the prerequisite for deprecating
  `0.24.0-alpha.10` and `0.24.0-alpha.12`. No gate item is cancelled and the
  repository stays private until every item has its receipt.

## v0.24.0-alpha.14 · candidate integrity and release preparation

_Release status: candidate only. This preparation change does not publish npm
packages, create a tag, or create a GitHub Release._

**Additive:**

- A recorded proof deferral is now visible wherever the finding is. The new
  headless `kuzushi proof defer <finding> --target <repo> --reason <text>`
  records the same operator decision as the shell's `proof defer` through one
  shared core service, the Prove page discloses it on the STATUS/NEXT strip of
  a selected finding (and in plain output), and `kuzushi finding` reports it
  beside the proof state. The deferral stays a decision, not evidence: it never
  moves proof confidence, the proof ladder, or a verification verdict, and it
  remains bound to the exact discovery generation it was recorded against.
- Successful phase attempts now keep the durable phase workspace primary with
  a compact action receipt, and operators can browse every phase page
  without changing reality-derived workflow progress.
- Local KWP modules now accept the canonical `scan`, `review`, and `prove`
  descriptor phases while retaining the deprecated `hunt` and `confirm`
  aliases. Module and contributor guidance now describes the shipped Rust/KWP
  surface instead of the retired TypeScript SDK.

**Security:**

- `kuzushi auth ping` no longer builds its own request envelope. The
  credential is now bound to the provider of the model being pinged, so a
  provider argument that disagrees with the model — including the default
  `anthropic` argument on a config whose model is `openai:*` — fails before any
  environment variable is read or any bridge process starts, instead of
  forwarding one provider's API key to another provider. The ping also runs
  through the shared runtime credential preflight used by scan and run, and a
  bridge that exits nonzero is now reported as a failure even when it printed a
  success document.
- Durable finding identity now rejects canonical fingerprint, deduplication,
  and source-signature overrides from KWP workers, keeps actor fingerprints as
  provenance only, and refuses exact-fingerprint reuse across different
  tool/rule structures or repository targets. New identities use a
  host-authenticated source-content locus when available, so line drift does
  not split one defect, distinct same-rule sinks remain separate, and
  cross-tool corroboration still converges.

**Fixed:**

- `kuzushi scan --since <ref>` and the shell's `scan since <ref>` now resolve
  the same changed-file scope through one shared helper. The CLI no longer
  writes paths the reference deleted into `.kuzushi/v3/since.txt`, and the
  resolved scope compiles into the canonical `sast:scan` `paths` and
  `diffBase` options, so `--since` narrows every engine instead of only the
  ones that read the scope file. Combined with `--paths`/`--shard` the
  effective scope is the intersection, disclosed as
  `scope: N files since <ref> ∩ M requested → K`. A reference that changed
  nothing — or an empty intersection — now refuses the scan instead of leaving
  an empty scope file that silently widened the run to the whole target. A
  `diffBase` already present in raw scan input must match `--since`; a
  mismatch is an explicit error.
- Enter no longer types a stray `j` into the shell composer. A carriage return
  that reaches the terminal while the line discipline is still translating CR
  to LF — the startup window before raw mode engages, and every
  external-process suspension — arrives from crossterm as Ctrl+J, and the
  composer inserted the bare letter instead of submitting, so `demo` became
  `demoj` and the command was never run. Line feeds are now folded into Enter
  at the key-dispatch boundary, and unbound Ctrl/Alt chords are refused by the
  line editor rather than typed as text.
- Shell command completion now anchors its fuzzy match: the first character
  you type must open the command or one of its words. Two stray keystrokes
  such as `xu` no longer draft `context build` (conte**x**t b**u**ild), which
  put a tool run one Enter away from a typo. Ordinary abbreviations (`cb`,
  `ctx`, `con`) are unchanged, and history and finding search keep the
  permissive match.
- Runtime-validation labels no longer read as a rejection of the scanner's
  claim when nothing ran. A harness that failed to build, blocked
  infrastructure, an unsupported language, and a finding with too little
  detail now read `not executed - …` instead of `execution_rejected - …` in
  the finding detail report and in JSON/JSONL exports. The durable
  `execution_rejected` proof-state token in `.kuzushi` artifacts is
  unchanged, so stored findings and their vocabulary still load as before.
- Ctrl+C now names the job it stops. The shell logged
  `abort requested for active worker` with no subject, which left an
  operator guessing when the running job had been backgrounded from a view
  they had since left. The stop request now reads
  `stop requested for <job> · <run-ref>` whenever the job hub knows the
  label, and the per-domain cleanup lines are unchanged.
- An unbuilt Map no longer wastes the terminal it was given. The readiness
  card is now a width-capped centered form rather than a status pane stretched
  across the whole body, and each project-context receipt row carries the
  state and next action the project model already knew — the Ratatui card and
  plain output project the same columns, collapsing to the compact
  section/summary row when the terminal cannot afford them.
- A refused phase rerun no longer discards the draft the operator just
  reviewed. Enter on the rerun review card consumes the pending review only
  once a launch exists, so a missing target, a stale phase prerequisite, or a
  saved input that no longer prepares leaves the reviewed draft — including
  every edited option — open where it was. The reason is disclosed on the card
  as a `REFUSED · DISPATCH` row and painted as a Workbench notice instead of
  only reaching the transcript.
- `workspace:export-findings format=sarif` now emits spec-valid URIs. The
  `WORKSPACE_ROOT` base is built as a real `file:` URI instead of an
  interpolated path, so a workspace root containing a space, a non-ASCII
  character, or a Windows drive letter no longer produces a document SARIF
  consumers reject. Result locations percent-encode their workspace-relative
  path, so a repository file such as `docs/My Notes.md` resolves instead of
  breaking the location. A `\` in a path is escaped rather than treated as a
  separator, because on Unix it is an ordinary filename character.

**Security and reliability:**

- A nonpublishing candidate workflow now binds the requested version and full
  commit SHA to reusable full CI, five required native builds, and five local
  installs of the exact root and platform tarballs.
- One release receipt records the commit, version, filename, byte size,
  SHA-256, and npm integrity for the root package, all five platform packages,
  all five native archives, and the exact-commit source archive. Publishing
  rehashes the same files and stops on any difference.
- Package checks now inspect the files actually reported by `npm pack`, reject
  unsafe paths and links, exclude bridge tests from the root package, and keep
  the existing 10 MiB root and 60 MiB platform package limits.
- Source export now refuses tracked `.kuzushi` runtime state and verifies that
  the archive is complete for its embedded commit before writing the final
  output.

**Release operations:**

- The tag workflow accepts only the package-version tag at current
  `origin/main`, reruns the complete candidate, publishes exact matching
  platform packages before the thin launcher, and applies npm's `latest`
  dist-tag explicitly.
- Public-release instructions now separate private candidate verification from
  publishing and require verified cleanup of quarantined historical root
  artifacts before repository visibility changes.

## v0.24.0-alpha.13 · operator experience and descriptor boundaries

_Release status: failed and unpublished. This version was superseded by
`0.24.0-alpha.14`; do not create or reuse an Alpha13 release tag._

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
