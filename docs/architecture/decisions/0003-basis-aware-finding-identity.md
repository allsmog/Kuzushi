# 0003 — Basis-aware finding identity

- Status: Accepted
- Date: 2026-08-27
- Owner: `@allsmog`

## Decision

Every durable finding identity records one basis:
`ExactProducerFingerprint`, `CrossRunDedupKey`, `SourceLocator`, or
`FileFallback`. Legacy rows are derived conservatively; an unprovable source
locator becomes `FileFallback`.

`identityFold` has `legacy`, `safe`, and `aggressive` policies. Attack-chain
findings always remain fingerprint-keyed. Safe mode uses `identityId` for the
first three bases. File fallback additionally requires equal non-empty source
signature or dedup key. Missing identity falls back to dedup key and then
fingerprint.

The repository ships a read-only identity audit that reports groups with
multiple source signatures, non-overlapping spans, multiple rule
families/symbols, chain/component mixing, or conflicting human decisions.
There is no numeric corpus minimum. `safe` becomes the default only after the
owner records corpus composition and signs off every unresolved suspicious
group.

The audit emits a canonical evidence envelope with its target key, corpus
watermark, and report digest. Approval is an explicit
`kuzushi findings identity-audit approve --from <request.json>` action. The
request must name an operator and give every suspicious identity an
`accepted` or `fixed` disposition plus a nonempty rationale. Kuzushi writes
the resulting receipt atomically under
`$HOME/.kuzushi/v3/identity-audit-approvals/`; a target-local receipt has no
authority. The shared dispatch resolver checks the canonical target, current
watermark, current report digest, schema, actor, and complete dispositions.

When that receipt is absent, stale, malformed, bound to another target, or
incomplete, omitted policies resolve to `identityFold=legacy` and
`identityReconcile=off`. A current receipt changes those omitted defaults to
`safe` and `auto`. An explicit descriptor input remains an operator override;
it is never inferred from the receipt. `modelDedupe` stays `off` unless the
operator explicitly selects another declared value.

Automatic triage propagation follows the same basis rules, never crosses the
attack-chain boundary, and never overwrites a human decision. Review events
record propagation basis and source finding ids.

`identityReconcile=auto|off` is the deterministic reconciliation control and
defaults to auto only after the audit gate. `modelDedupe=off|manual|auto`
defaults off. Cross-tool clusters are report-only until a labeled evaluation
records zero false merges and receives owner approval.

## Consequences

Repeated presence may corroborate a finding. Absence from a nondeterministic
trial never refutes it, lowers confidence, or breaks a tied verdict. Existing
explicit `dedupe=true` remains a deprecated alias for explicit auto mode.
