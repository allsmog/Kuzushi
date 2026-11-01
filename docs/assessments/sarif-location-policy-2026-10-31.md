# SARIF location policy — one emitter forged a line, the other did not (2026-10-31)

## The defect

Kuzushi has exactly two SARIF 2.1.0 emitters, and both are consumed by CI
gates and GitHub code scanning:

- `workspace:export-findings --format sarif`
  (`workspace/application/export_sarif.rs`)
- `report:sarif` (`report/confirmed_sarif.rs`) — the "hand a CI gate only what
  a review stood behind" surface.

Each carried its own copy of the `physicalLocation` projection, and the copies
had drifted. `report:sarif` built its location as:

```rust
"artifactLocation": { "uri": finding.file_path },
"region": sarif_region(finding),   // startLine: finding.start_line.max(1)
```

Two consequences, both operator-facing:

1. **A forged line number.** `start_line == 0` means the detector reported no
   line. `.max(1)` reported it as line 1. `bounty:import-har` and
   `bounty:import-burp` build *every* `http-request` finding with
   `start_line: 0` and a URL for `file_path`
   (`findings/import/har.rs:103`, `findings/import/burp_xml.rs:223`), so a
   reviewed capture finding reached the CI gate as
   `{"uri":"https://api.lab.test/orders?id=1","region":{"startLine":1}}` —
   line 1 of a URL. The sibling emitter already omits the region in this case
   and says why.
2. **An unencoded `uri`.** SARIF §3.4.2 wants a URI reference, not a literal
   path. A repository file named `docs/My Notes.md` was emitted with a raw
   space, which consumers reject; a raw `#` or `?` silently truncates the path
   for any consumer that parses the location, mis-attributing the finding to a
   different file. An absolute path was never distinguished from a relative
   one, and no `originalUriBaseIds` was declared at all.

`export_sarif.rs` had already fixed every one of these, with the reasoning
written down in its doc comments. Only `report:sarif` was left behind — which
is the failure mode `CLAUDE.md` names directly: "Do not duplicate policy or
parsing logic across scan, shell, and run modes."

## Why this ranked first

Ten problems were ranked this run. This one won on three counts: it is a
dishonest label in a machine-consumed artifact (a fabricated line number, not
a crash or a cosmetic gap); it affects the bug-bounty intake path the
repository ships as a headline workflow; and it is deterministic, needs no
model or network, and fits one reviewable change. The next-ranked items
(`app/effect_runtime.rs`'s twelve `unreachable!` routing arms, and widening
`kuzushi-core`'s hostile-input panic ratchet past its four directories) are
both larger and continue a lane the previous three changes already worked.

## The change

`findings/presentation/sarif_location.rs` now owns the policy once:
`sarif_artifact_location`, `sarif_region`, `sarif_original_uri_base_ids`, and
the URI encoders beneath them, carrying over the existing doc comments
verbatim. Both emitters call it. `report:sarif` additionally declares
`originalUriBaseIds` on its run, so the `uriBaseId` its relative locations
reference resolves.

## What is not claimed

- No new SARIF field, rule, property, or severity mapping. `report:sarif`
  results change only in `locations[].physicalLocation` and the run's
  `originalUriBaseIds`.
- `workspace:export-findings` output is byte-identical; its change is the
  move, and its existing location tests cover the extracted helpers unchanged.
- `has_uri_scheme` still reads a relative path whose first segment contains a
  colon (`foo:bar/baz.rs`) as an opaque URI rather than a workspace-relative
  name, bypassing the `:` escaping `relative_uri_reference` documents. That
  predates this change, affects both emitters equally, and is left for its own
  change.
- Nothing here validates an emitted document against the SARIF schema; the
  tests assert the two fields, not whole-document conformance.
