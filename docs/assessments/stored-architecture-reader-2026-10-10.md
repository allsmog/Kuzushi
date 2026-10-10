# Bounded stored architecture reports

The `x-ray:read` audit found three supported-path defects. A read could publish
a Map phase result, its data labeled old generation cost as exactly zero, and
the architecture SVG had no read-size bound. Three red regressions reproduce
these defects. A direct adapter also inferred its target from cwd when neither
target nor workspace was provided.

## Operator behavior and compatibility

The reader is now auxiliary Map evidence with `phase_result: false`. The shared
descriptor declares its target option, and direct calls require an explicit
target or active workspace. All four contained regular artifacts have an 8 MiB
per-file bound. Missing, unsafe, oversized or invalid UTF-8 text refuses without
repair or truncated parsing. Cancellation is checked before and after bundle
IO; individual filesystem reads are not guaranteed to be interruptible.

Original tier/count fields and four full artifact references remain compatible.
Readable copy identifies the tier as a recorded claim, the counts as parsed
report values, freshness as unassessed and old generation spend/model/runtime/
context as unknown. Structured `readProvenance` records the same limits;
`data.costUsdExact` is false. The separate current reader operation has known
zero provider cost. SVG size/containment does not establish graph semantics.
No finding severity, confidence or decision is changed.

The initial terminal review found repeated absolute paths occupying too much
of the compact transcript. The final receipt shows one target path and grouped
relative filenames after the report claims and uncertainty. Structured absolute
references remain intact.

## Native execution and terminal evidence

Owned manually supplied files are consumed through real prepared CLI and shell
dispatch. Native checks exercise explicit target binding, unknown-key refusal,
oversized SVG and missing-artifact failure, deliberate restoration and restart.
No transport or product result is simulated. The stored fixture itself is
explicitly labeled and provides no model-generation or vulnerability evidence.

Final J168:
`/tmp/kuzushi-xray-reader-audit-20261010/final-tui/20261010-094149/J168`.
Native SHA-256:
`b256c9f91c9e6481d960a7ac73c8a617d4ed80de2b7964588da529b66a196b26`.
There are 20 machine passes, zero failures and 27 authenticated live text/ANSI
captures across six sizes, complete compact paging, failure recovery and
no-color restart. Three assistant judgments qualify the owned reader separately
from raw REVIEW_REQUIRED and operator approval false.

Report/source hashes survive unchanged. Observations, human decisions, provider
reservations and investigation work attempts remain zero. No accepted Map
baseline or model/scanner work is created by reading.

## Verification and remaining acceptance

Twenty-four focused Core checks pass with zero ignored tests, including the
reader regressions, target preparation, cancellation, parser/adapter behavior
and related artifact indexing. Fake runtime generation checks are separate
from live quality. The workspace build and risk proxy for 679 changed code files
pass, as do all ten repository summary gates. Final repository and
documentation receipts are retained under
`/tmp/kuzushi-xray-reader-audit-20261010`.

Evidence is assigned to 65 of 109 catalog entries, with 44 unassigned. Seven
unassigned reproduction/patch actions are now explicitly excluded from required
investigation work; a source-review tool's execution mode is distinguished from
its static mode. These annotations do not qualify, modify or execute excluded
implementations. Maturity is unchanged and no module is retired.

Live `x-ray:run` generation, graph semantics, source currency, full configurations,
large-input latency and in-flight IO interruption remain unqualified. Versioned
investigation briefs are still a missing interface; the legacy `aim` command is
already correctly isolated as compatibility metadata that approves no work.
All nine broad delivery milestones, the full live investigation and complete
reference-product TUI acceptance remain open. The specific live allowance stays
pending. Work remains uncommitted on main, with no credential renewal, target
execution, exploit development, reproducer work, vulnerability patch, commit or
push.
