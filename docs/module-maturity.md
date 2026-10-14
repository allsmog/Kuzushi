# Module maturity tiers

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

`engagement:aim` is a Compatibility action for legacy harness metadata. Its
recorded budget does not enforce a spending limit or approve investigation work;
use `campaign:study` and explicit allowance approval for that workflow. Exact
dispatch remains available. Configuration, routing, workspace status and the
methodology catalog are operational inspections, not Map producers. A complete
small history containing only operational receipts still enters Setup.

The shell capability picker shows preparation hints for its selected action:
target, model or input required, plan review, or input review. Stored tool options
use the shared registry input preparation and runtime policy, so a deterministic
threat-map configuration does not acquire a model requirement. These hints do
not certify credentials, external dependencies, scope support, allowance or
useful executor output. Validation runs only for the selected action.

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

`sbom-scan:scan` keeps its declared Core tier and now belongs to auxiliary Map
work. Its manifest/lockfile inventory can inform Components, but cannot complete
Map or Scan or generate vulnerability verdicts. Qualification is limited to
the named dispatcher, parser, containment, failure and native TUI evidence;
registration alone does not establish every ecosystem or interface.

Individual tools can further restrict a Core module with the optional
`discoveryMaturity` descriptor field. This permits supported study planning and
compatibility shard planning to coexist in Campaign. Default tool catalogs and
guided actions use the effective tier. `--all` names the effective tier and
exact dispatch remains available. A tool override cannot promote a Labs or
Compatibility owner. Local KWP descriptors support the same field.

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
