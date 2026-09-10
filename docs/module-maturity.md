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

Catalog omission does not bypass policy. Exact dispatch still passes through
descriptor input validation, workspace containment, effect approval, runtime
selection, lifecycle recording, and artifact contracts.

## Classification ownership

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
