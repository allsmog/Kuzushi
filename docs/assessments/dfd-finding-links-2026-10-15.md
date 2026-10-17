# DFD evidence paths and saved finding navigation

The working implementation adds an `f` action to the Map and full-frame DFD.
It opens Review for repository file paths attached to the selected node, flow
or trust boundary. Inside the context inspector it selects the focused row's
paths. The action uses the existing findings application service and shared
filter parser. It starts no discovery, model request or follow-up job.

The queue matches paths across saved source revisions. Each observation keeps
its own source identity, authority and human decisions. A matching path does
not establish that the same finding exists at another SHA or has been fixed.
The notice states that path matches span saved revisions. Back restores the
diagram, its workflow origin and the prior Review filter, selection and page
request. The ledger is refreshed rather than restored from an old data copy,
so newer decisions survive navigation.

`findings:list` declares `filePaths` and its `file_paths` alias. Array entries
are literal, case-sensitive paths; separators and leading `./` are normalized.
The `files:["src/a b.rs","src/a,b.rs"]` expression uses the same exact
selection. Paths match with OR and combine with other filters using AND.
Legacy `file:` and `filePath` substring behavior is unchanged. Pagination binds
the entire filter and rejects a cursor from a different path selection.
The public Rust struct addition and cursor reload requirement are documented
in `RELEASING.md`. No stored finding or decision schema changes.

## Tests and native evidence

Seventy-six distinct focused and snapshot checks pass: 31 core filter and
pagination checks, eight DFD navigation checks, two Map hint checks, ten footer
checks and 25 plain snapshots. The workspace build passes. The navigation
tests include actual paginated ledger reads, return to a prior page, draft
preservation, target changes and input ownership.

Native journey J289 exercises an owned four-file fixture using deterministic
source inspection. The files contain inert Terraform text and are never
deployed or executed. The fixture produces four unverified policy observations;
two have the exact DFD-linked paths, including a space and a comma. A similarly
named file and an unrelated file remain independent observations. Shared
prepared dispatch selects the same two records before TUI navigation.

The final native run has 35 machine passes, zero failures, 29 authenticated
text/ANSI capture pairs and three pending human judgments. It covers node,
flow, boundary and focused-context queries, missing evidence, Back, the prior
Review filter, six terminal sizes and a no-color restart. Final fixture checks
retain the same four observations, zero decisions, source hashes and accepted
context manifest. These interactions add no investigation jobs.

The first two native attempts exposed navigation assumptions and a misleading
Map hint. Map now shows `Esc then z` while the composer owns input, and `z`
while Navigate mode owns it. Inspecting the third run exposed hidden DFD actions
at compact widths. The final run retains selection, findings, context and exit
controls at 60x20 and 40x12, including the focused context inspector. Earlier
attempts remain in the evidence directory.

Final evidence is under `/tmp/kuzushi-dfd-finding-links-20261015`, with the
native run in `native-v4/20261015-165633/J289`. The native executable SHA-256 is
`51e8aa020f967784639a23765a8b9b6754470c23dc2637e7346858e0b2ebf2a1`.
All 4,240 source inputs, 688 runtime inputs and 13 copied binaries retain their
frozen hashes. `native-qualification-v4.json` and `capture-invariants-v4.json`
record those checks. The harness result remains `REVIEW_REQUIRED`.

## Remaining work

Three concrete gaps remained at this checkpoint:

- Manually typed shell filters collapse repeated whitespace inside literal
  filenames. Direct tool arrays and the DFD's typed command preserve it.
- DFD evidence currently combines structured literal paths with citation text.
  A literal filename ending in a numeric colon suffix or fragment can therefore
  be mistaken for a source citation. The path origin needs to remain explicit.
- The separate immutable context-preview modal still has no finding shortcut.
  It must use its selected frozen context and preserve its own modal origin.

The [context navigation follow-up](dfd-context-navigation-2026-10-15.md) addresses
these gaps and records the subsequent terminal checks. This checkpoint's changes
were uncommitted. No module maturity or readiness is promoted by this test.
Machine checks do not establish human UX acceptance, reference-product parity,
model accuracy or completion of the full bounded-investigation plan.

This increment uses zero provider requests. The completed live experiments used
OpenAI OAuth with GPT-6 Luna and low reasoning. Fourteen requests
remain spent, with no additional approved live capacity.
