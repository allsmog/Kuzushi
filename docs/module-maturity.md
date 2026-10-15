# Module maturity tiers

CodeQL database preparation and scanning are Labs and auxiliary. Preparation
retains explicit repository-execution consent and produces a source-bound
database, without completing Map. Query scans require an authenticated managed
database even when dbPath is supplied; observations remain partial and require
review. Real engine coverage, exact discovery scopes, authentication cancellation
and complete UX acceptance remain unqualified; see the
[CodeQL module audit](assessments/codeql-module-audit-2026-10-14.md).

The Android APK module is Labs. Its visible `android-apk:scan` action is auxiliary
Scan, with explicit target-write consent and partial observations. Selected
timeouts and executables reach preparation/code scanning; archive digests and
per-stage outcomes remain in successful receipts. These identify supplied
bytes, not accurate decompilation or original-source locations. Useful real
decompilers, complete coverage, generation isolation and full recovery remain
unqualified; see the
[APK pipeline audit](assessments/android-pipeline-audit-2026-10-14.md).

`recon:nmap`, `recon:subdomain` and `recon:http-fingerprint` are Labs and
auxiliary Map. Explicit external-action consent remains required. Each process
has a wall-clock deadline from one to 300 seconds; multi-source and redirect
actions can run several processes. Passive names carry unknown liveness.
Partial observations establish no source accuracy, repository coverage or phase
completion. Live probing, broad network scope and whole-operation recovery
remain unqualified; see the
[external-recon audit](assessments/external-recon-audit-2026-10-14.md).

`threat-intel:research` and `threat-intel:harvest` are Labs and auxiliary Map.
Their finite catalog drafts use Learning allowance, retain nested extraction
receipts and defer further advisory work when unprotected capacity is exhausted.
Patterns stay unaccepted and create no hunts or Map checkpoint. Live retrieval,
useful detectors and final human UX review remain unqualified; see the
[advisory-catalog audit](assessments/advisory-catalog-audit-2026-10-14.md).

The `ndiff` module is now Labs throughout. **Draft advisory pattern from supplied
diff** requires Learning allowance and explicit external-action authorization.
Its bounded source receipt discloses omissions; the draft has no source tools
and remains unaccepted. Neither extraction nor an explicitly requested search
can complete Map or Scan. See the
[advisory-pattern audit](assessments/advisory-pattern-audit-2026-10-14.md).

`ndiff:hunt-variants` is Labs and auxiliary Scan. It searches source using an
explicitly supplied advisory pattern, inherits selected reasoning and requires
separate Discovery allowance. Results disclose partial coverage, unverified
locations and independent review. Exact discovery scope, advisory applicability
and useful detection remain unqualified; see the
[advisory-search audit](assessments/advisory-search-audit-2026-10-14.md).

`offense-review:threat-hunt` is Labs and auxiliary Scan. Its compatibility alias
retains the same executor and options. Reasoning inherits the selected runtime;
retry requests keep their output and turn limits. Results disclose partial
snippet/actor coverage and unverified observations. Existing prioritized
threat-model context is required. Useful detection, scope and total resource
bounds remain unqualified; see the
[actor-discovery audit](assessments/actor-discovery-audit-2026-10-14.md).

`trace:expand` is Labs and auxiliary source analysis with retained Prove
authorization. Optional work uses Discovery allowance, preserving Review.
Generated claims remain partial and unverified. The reader isolates the last
authenticated result and its source receipt; earlier history remains accessible.
Model usefulness, citation validation and immutable scope/context binding remain
unqualified; see the
[trace source-history audit](assessments/trace-source-history-audit-2026-10-13.md).

`triage:chain-hunt` is Labs and auxiliary Review. Optional metadata synthesis
uses Discovery allowance, without a Review checkpoint or member verdict changes.
The bounded request has no source tools, and its new observations explicitly
require independent review. Exact dispatch remains available. Source-version
isolation, full ledger preparation bounds and useful relationships remain
unqualified; see the
[finding-relationship audit](assessments/finding-relationship-hypotheses-2026-10-13.md).

Kuzushi separates product maturity from implementation visibility. Hidden
modules are internal or exact-only implementation details. A non-hidden module
has one of three maturity tiers:

| Tier | Default discovery | Exact dispatch | Product meaning |
| --- | --- | --- | --- |
| `core` | Included | Included | Supported default capability with release-quality contracts. |
| `labs` | Omitted | Included | Opt-in research capability awaiting product-quality evidence. |
| `compatibility` | Omitted | Included | Retained migration or integration surface, not the recommended path. |

Plain and JSON catalogs use the same scope. `kuzushi modules` and `kuzushi
tools` show Core. Add `--all` to inspect every non-hidden tier, with a maturity
label in both formats:

```bash
kuzushi modules --all
kuzushi modules --all --json | jq '.[] | select(.maturity == "labs")'
kuzushi tools --all --json | jq '.[] | select(.maturity != "core")'
```

Hidden modules remain absent even with `--all`; their descriptors are available
only to internal registry consumers and exact dispatch. Labs and Compatibility
tools remain callable when the operator supplies their complete registered id:

```bash
kuzushi --target . run fuzz:status --input '{}'
```

Guided phase planners and capability actions use the same Core/visibility
predicate as the default catalog. A task table or exact tool name cannot make a
Labs or hidden tool a default action. This curates discovery only; presence in
Core still does not prove that the current target, prerequisites or allowance
are ready. Individual-tool readiness evidence is tracked in the
[bounded investigation audit](assessments/bounded-investigation-tools.json).

Citation inspection and imported finding history are auxiliary Review actions.
Neither grants local Map/Scan completion or establishes finding validity.
The [citation/import audit](assessments/citation-module-audit-2026-10-09.md)
records real dispatch, preserved history, bounds, partial states and native
reading evidence. Large cases and full investigation acceptance remain open.

`fuzz:status` and `fuzz:import` remain Labs. They read external engine history
and cannot complete a fresh Scan. Verification flags belong to that external
engine; neither reader establishes local reproduction or current-revision
coverage. Malformed rows produce partial receipts. Status bounds inspection;
import still needs aggregate disk-work and in-progress cancellation evidence.

`engagement:aim` is a Compatibility action for legacy harness metadata. Its
recorded budget does not enforce a spending limit or approve investigation work;
use `campaign:study` and explicit allowance approval for that workflow. Exact
dispatch remains available. Configuration, routing, workspace status and the
methodology catalog are operational inspections, not Map producers. A complete
small history containing only operational receipts still enters Setup.

The shell capability picker shows preparation hints for its selected action:
target, model or input required, missing dependency, plan review, or input review. Stored tool options
use the shared registry input preparation and runtime policy, so a deterministic
threat-map configuration does not acquire a model requirement. These hints do
not certify credentials, dependency versions, scope support, allowance or
useful executor output. Validation runs only for the selected action.

Declared executable options are inspected by the shared background reader.
The picker shows **CHECKING DEPENDENCIES**, then **DEPENDENCY MISSING** when the
requested executable is unavailable. The check uses prepared defaults and stored
options, including compatibility aliases. Semgrep publishes its existing
executable default in its descriptor. Implicit adapter defaults and undeclared
dependencies remain unassessed. Unix files without any
execute permission are unavailable. Presence alone returns **REVIEW INPUTS**,
not a functional verdict. With an empty composer, `r` rechecks dependencies;
with a draft, `r` remains text input. Checks bind to the exact option values and
refresh generation, so late results cannot appear current after either changes.
The cache retains at most 32 results. Checks start no commands or model requests.

The selected runtime-backed action also checks the shared model/auth binding
policy without reading credentials. An unsupported provider or incompatible
credential-environment setting shows **RUNTIME CONFIG** with a `doctor` route.
Explicit deterministic inputs skip that check. Modal and plain readers show the
same recovery guidance; short modals wrap it and reserve space before action rows.
Selecting or reading an action changes no configuration and starts no work.

Setup, Model and Health distinguish stored credentials from provider acceptance.
OAuth refresh required is an attention state: runtime must attempt refresh
before a model request, and success remains unverified. Invalid or unrefreshable
OAuth has a repair state; deterministic selections do not require credentials.
Session and API-key presence stay separate from OAuth. These local readiness
checks never sign in, refresh or authorize model requests.
The catalog uses its available body before reserving decorative margins. Its
footer names **Enter load** while an empty composer belongs to the picker;
an unsent command retains its editing contract. The modal then names command
editing instead of advertising Enter as another draft-loading action.
Without a target, Enter opens the target picker and the footer names that
action. Preparation guidance alone never selects the current directory.

With an empty composer, arrows select and Enter loads an editable command.
Loading starts no work. A draft keeps its editing keys; Esc clears it before
returning from a contextual picker. Selection survives draft clearing and resize.
The contextual footer advertises back rather than navigation-mode entry.

Catalog omission does not bypass policy. Exact dispatch still passes through
descriptor input validation, workspace containment, effect approval, runtime
selection, lifecycle recording, and artifact contracts.

## Classification ownership

`variant:hunt` is Labs and displayed as **Search related observations**.
Its separate source search requires current confirmation and approved Discovery
allowance. Results stay partial with unverified scope/source coverage and do
not complete Scan. New observations need independent Review; absence does not
resolve the original subject. Optional effort inherits the selected runtime.
Useful detection and scope enforcement remain unqualified. See the
[related-observations audit](assessments/related-observations-audit-2026-10-13.md).

`variant:lift-pattern` is Labs and displayed as **Draft source pattern**.
It requires current confirmation and returns an unaccepted signature, without
writing a lesson, activating context or completing Scan. Learning accounting
protects Review capacity. Optional reasoning inherits the selected runtime.
Use `findings:lesson-generate` for reviewed context reuse. Pattern usefulness
and source-version isolation remain unqualified. See the
[source-pattern audit](assessments/source-pattern-draft-audit-2026-10-13.md).

`taint-iris-next:finding-review` is Labs and displayed as **Discover taint
candidates**. It runs fresh discovery and imports observations; it does not
review selected ledger findings. Invalid output can require another agent
session. Scope isolation, useful results and interruption remain unqualified.
Exact dispatch is retained without Scan checkpoint ownership. Existing human
decision history remains durable, with no automatic current verdict for an
unverified new observation. See the
[candidate discovery audit](assessments/taint-candidate-audit-2026-10-13.md).

`ndiff:fetch-cve` is Labs and auxiliary Map metadata. Supplied records keep
their contents but are labeled unverified and must match the requested advisory
id. The declared `maxMetadataBytes` bounds the combined encoded supplied record
and fixtures, with an 8 MiB ceiling. Exact dispatch remains available. Metadata
does not establish applicability to the target or complete Map. Live retrieval,
cancellation and useful downstream analysis remain unqualified.

`taint-iris-next:dataflow-plan` is Labs and auxiliary Scan preparation.
`taint-iris-next:source-sink-trace` is Compatibility: both use the same planner,
options and output, so the alias has no distinct executor contribution.
Exact dispatch remains available. Their source inventory now uses iterative
traversal and includes declared `.cxx` files; partition advice reuses that
inventory. Scoped evidence, prefix-coverage disclosure, cancellation during
work and useful engine output remain unqualified. A focused module with an
experimental primary requires an exact action rather than substituting another
tool or model-backed operation.

`threat-intel:apply` is Labs and auxiliary Map. The default dry run remains a
runtime-free metadata preview; explicit live dispatch is a legacy path outside
accepted scope studies. Reading a preview does not approve hunts or complete Map.
Failed and partial child receipts remain visible in the parent result. Complete
small histories of auxiliary receipts keep fresh targets in Setup unless actual
source artifacts or findings establish investigation material. Unknown, cold
and larger histories retain conservative resume behavior. No tool or receipt
format is removed by this curation.

`findings:chains` is Labs and auxiliary Review work. Its output limit is applied
after pair enumeration and does not bound total work; large histories and
cancellation during the fold remain unqualified. Exact dispatch and saved scene
artifacts remain available. The default shortcut explains experimental readiness
without running the fold. Its receipt cannot complete Review. The
[advisory relationship audit](assessments/advisory-chains-module-audit-2026-10-13.md)
records small owned-metadata execution and unchanged human decisions. It does
not establish source feasibility or qualify optional candidate publication.

`threat-intel:discover` is Labs. The legacy extractor can omit nested manifests
and inspect enclosing Bazel metadata when its selected subtree yields no
packages. Exact dispatch is retained with a partial result, coverage limits
and a `sbom-scan:scan` inventory route. Candidate extraction and
`threat-intel:list` are auxiliary Map actions and cannot complete Map.
The [candidate inventory audit](assessments/dependency-candidate-audit-2026-10-13.md)
records local execution and the limits that still prevent Core qualification.

`govulncheck:scan` is Labs in discovery while exact dispatch and scan-task aliases
remain available. Its parser now handles the upstream JSON stream and separates
module, package and symbol signals without promoting proof. Installed execution,
network behavior, scope containment, partial work and calibrated product value
remain unqualified. See the
[Go scanner assessment](assessments/govulncheck-module-audit-2026-10-12.md).

`cargo-audit:scan` remains Core with scoped installed offline evidence. It
inspects a bounded snapshot of the selected directory's Cargo.lock with the
standalone scanner. Directory scopes work independently of the workspace-root
lockfile, and independent lockfiles retain distinct finding identities. Exact
membership is refused. Readiness depends on a lockfile, executable and advisory
database; published-advisory matches remain signals requiring owner review.
The [Cargo audit assessment](assessments/cargo-audit-module-audit-2026-10-11.md)
records shared execution, failure states, finite approval and native consumers.
Database freshness/identity, full configuration and interface coverage, large
cases and complete investigation acceptance remain open. Its context DAG edge
does not execute context preparation.

`semgrep:scan` remains Core with scoped installed local-rule evidence. Shared
dispatch declares a per-job subprocess time allowance, retains earlier completed
file batches on failure, and preserves raw observations through Review, Report
and restart. Standalone directory inspection and exact-file SAST membership have
distinct evidence. The [Semgrep audit](assessments/semgrep-bounded-execution-2026-10-11.md)
keeps default-rule usefulness, large scopes, source-authentication bounds,
all configurations/interfaces and full investigation acceptance open.

`dep-hygiene:check` remains Core for bounded dependency version-policy signals.
It inspects nested manifests, excludes symlinks, repository state, installed
dependencies and build output, and retains valid observations when another
document cannot be inspected. The result discloses counts, limits and gaps.
These heuristics require owner review and perform no advisory lookup, model
request, package installation or target execution. Whole targets and explicit
directory subtrees are supported; accepted exact-file membership is refused.

`cpg:build` is Labs and auxiliary Map work. Exact dispatch retains source
parsing, directory scoping, cache reuse and graph import. Saved graphs do not
replace accepted context. A later language failure retains earlier graphs in a
partial receipt. The file cap limits frontend construction, while enumeration,
source reads, import size and in-flight cancellation still lack dependable
operation-wide limits. Prefer a small explicit `subdir` when opting in.
Import rejects `languages`, `subdir` and `maxSourceFiles`, which apply to builds;
imported graph source applicability remains unassessed.

`sbom-scan:scan` keeps its declared Core tier and now belongs to auxiliary Map
work. Its manifest/lockfile inventory can inform Components, but cannot complete
Map or Scan or generate vulnerability verdicts. Qualification is limited to
the named dispatcher, parser, containment, failure and native TUI evidence;
registration alone does not establish every ecosystem or interface.

`context:build`, hidden `context-lite:index` and `entry-points:extract` are
auxiliary Map preparation. Context snapshots and extracted surfaces remain
inputs to scanners and context producers, with their existing runtime and
authorization rules. They do not supply an accepted threat-model revision or
complete Map. Their new results and preparation-only historical receipts cannot
be selected as phase checkpoints. Primary context production and import retain
their explicit Map review and acceptance controls.

Individual tools can further restrict a Core module with the optional
`discoveryMaturity` descriptor field. This permits supported study planning and
compatibility shard planning to coexist in Campaign. Default tool catalogs and
guided actions use the effective tier. `--all` names the effective tier and
exact dispatch remains available. A tool override cannot promote a Labs or
Compatibility owner. Local KWP descriptors support the same field.

`x-ray:run` and its hidden `x-ray:x-ray` alias are Labs generation actions.
They write mutable architecture reports without authenticated source coverage
or an immutable accepted context. They have no supported finite Map study and
cannot complete Map. Exact dispatch remains available with explicit target-write
authorization and Context allowance accounting. The bounded `x-ray:read`
reader stays Core and presents historical report claims as unassessed.
Exact options and plain reading disclose Experimental or Compatibility support
from the same descriptor metadata used by default discovery.

`campaign:plan` and `campaign:coverage` are retained Compatibility actions.
Their shard/threat progress format does not consume accepted scope studies.
Use `campaign:study` to approve finite work and Report to read its results.
`campaign:status` remains Core as an operational tracker; its trend-history
write is disclosed and does not make the run an analysis source.

`pack:suggest-shards` is retained as Compatibility. It writes a legacy draft
and optionally materializes the legacy nested-scope tree only when explicitly
requested. Use `pack:scopes` for reviewed inventory-bound proposals and
`pack:suggest-scopes` for one explicitly budgeted model proposal. `pack:lint`
remains a Core read-only pack validator. Both lint and legacy suggestion are
auxiliary Map operations; their receipts cannot complete the Map phase.

Maturity is declared beside each Rust module descriptor. There is no central
module-id allowlist and no environment override. Promotion or demotion is a
reviewable change to the module that owns the capability.

The initial classification is:

- `fuzz`: Labs and visible through `--all`;
- `pwn`: Labs and hidden because it remains an exact-only specialist surface;
- `carlini-threat-hunt` and `taint-iris`: Compatibility and hidden because
  they are retained aliases for newer product paths.

## Graduation rule

Moving a module into Core requires a reviewed code change backed by at least
one measurable product result:

- improved precision or recall on a versioned corpus;
- improved empirical proof or patch-closure rate;
- reduced cost or latency without losing coverage;
- improved coverage or accountability for work that would otherwise be silent.

The module also needs explicit descriptor policy, cancellation and failure
semantics, durable evidence and provenance, focused tests, current
documentation, and parity across every interface that exposes it. New research
modules should enter Labs instead of expanding default discovery automatically.

The [finite allowance audit](assessments/allowance-controls-module-audit-2026-10-10.md)
refines planning, approval and inspection evidence for four existing Core
Campaign tools. It establishes finite drafts, exact-plan approval, explicit
protected capacity and restart-safe native inspection on owned inert metadata.
It promotes no tool, retires no implementation and certifies no live-model
generation quality. The remaining unassigned tools stay pending in the matrix.
