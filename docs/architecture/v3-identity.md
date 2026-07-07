# V3 Finding Identity

Finding identity must survive line drift. A line number is display metadata, not
the durable identity of a finding.

V3 uses three concepts:

| Concept | Purpose |
| --- | --- |
| `stable_fp` | Stable finding key across line shifts and cosmetic edits. |
| `observation_hash` | Exact scanner/plugin/tool observation in one run. |
| display alias | Human-facing label such as `F-0001`; never canonical. |

## Stable Finding Key

`compute_stable_fp_v3` hashes domain-separated identity parts and returns an
`fp3_...` key:

```text
kuzushi:v3:finding
identity-version:3
tool family
rule id
language
parser version
normalizer version
symbol path or rename group
AST locus hash
normalized local snippet
local context hash
optional disambiguator
```

The disambiguator is a fallback. It should only be used after the structural
fields still collide.

The current generic adapter path uses tool, rule id, normalized path, and rule
identity hints when AST/symbol data is not available yet. That keeps the v3
shape in place while richer scanner adapters add parser and structural context.

## Observation Hash

`compute_observation_hash_v3` returns an `obs3_...` key for one exact tool
result:

```text
kuzushi:v3:observation
identity-version:3
run id
tool name
tool version
rule set hash
target snapshot hash
raw result hash
```

Changing the run id or raw result changes the observation hash without
changing the stable finding key.

## Occurrences

Occurrences point at immutable content:

```text
snapshot_hash
blob_hash
byte_start
byte_end
display_path
display_line
```

`display_line` is derived from the blob/span for presentation. It must not be an
identity input.

## Rekeying

Rekeying is an event, not silent mutation:

```text
FindingRekeyed {
  old_fp,
  new_fp,
  method,
  confidence,
  evidence
}
```

Safe rekeys forward stale decisions when the writer can prove continuity.
Ambiguous or low-confidence changes produce a conflict. Rekey chains resolve
transitively through projected `rekey_edges`.

## Plugin Boundary

Plugins never supply canonical ids. They return untrusted candidates with
`ruleId`, title, severity, blob hash, byte span, and message. The host validates
the candidate, confirms the blob/span is inside the granted snapshot, computes
`stable_fp` and `observation_hash`, then commits through the storage writer.

Unknown fields such as spoofed `stableFp`, `eventHash`, proof, or triage state
are rejected by the strict plugin-output schema.

## Implementation Map

- `crates/kuzushi-core/src/identity/hash.rs` - BLAKE3 domain-separated hashes.
- `crates/kuzushi-core/src/identity/finding_identity.rs` - `fp3_` and `obs3_`
  computation.
- `crates/kuzushi-core/src/storage_v3/projection_observations.rs` - projected
  observations and stable finding rows.
- `crates/kuzushi-core/src/storage_v3/projection_rekey.rs` - rekey continuity
  and stale-decision forwarding.
- `crates/kuzushi-core/src/plugin_sandbox/observation.rs` - plugin candidate
  conversion into host-owned observation writes.

## Forbidden Regression

Do not restore `(rule_id, file_path, start_line)` as the canonical finding id.
Do not let message text, mutable line numbers, or plugin-provided ids decide
durable identity.
