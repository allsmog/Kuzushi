# Complete stored-context comparison

The existing comparison could miss a changed DFD type, trust zone or flow endpoint
when the model reused an element ID. It also exposed only selected text and
structural subsets. This draft adds complete stored field differences through
`threat-model:diff` and the study context reader. It changes no finding verdict,
source file, accepted context, scan job, model selection or maturity tier.

## Shared result and operator behavior

The additive `data.contextStructure` object has schema version 1. It preserves
full before/after values, exact JSON pointers, literal IDs and matching method.
DFD nodes, flows, boundaries, security context and questions compare by unique
literal ID. Duplicate IDs remain explicitly ambiguous positional matches; missing
IDs remain positional. Added and removed rows retain complete objects. Missing
fields differ from explicit JSON `null`. Unique-ID collection order changes are
separate; other arrays retain stored order. Existing result fields stay available.

This compares saved values. It does not infer architectural equivalence, source
freshness, vulnerability validity or a fix on another SHA. Recognized source
claims from both saved documents remain separate. Disagreeing recorded revision
fields are flagged without silently choosing one. Unrecorded source claims stay
unrecorded. Manifest-only or unrecognized source metadata is not invented.

After inspecting a candidate with a recorded parent, `d` opens Text, Graph,
Source and Other views. Graph includes security context and questions. Arrows
select a record; PgUp/PgDn and Home/End read its complete values. Tab/BackTab
preserve each view's selection and scroll. Wide terminals show list and detail;
compact terminals stack them and keep complete controls visible. Plain output
includes every view and record independently of the interactive selection.

Comparison reads the exact authenticated parent through shared prepared dispatch
and compares it with the already inspected exact candidate. A failed or loading
read cannot select a candidate. Retry stays local and preserves navigation.
`a` associates a successfully read candidate with this study only. Escape returns
to the inspected candidate and original draft without activation or approval.

The terminal summary previews at most eight field records, four lines per value
and 240 characters per line. Full stored values, source claims and order changes
remain in structured data. Field-change counts are not component counts.

## Verification

The evidence root is
`scripts/devex/artifacts/context-structure-diff-20261023/`.

- The core context suite passed 710 checks, including the prepared-dispatch
  regression, complete row additions/removals, literal IDs, ambiguous matching,
  missing versus null, full Unicode values and more than 100 changed records.
- Three registry audit checks passed. The final frozen catalog has 118 visible
  tools and 81 Core defaults. Compared with the previous reader catalog, only
  `threat-model:diff` changed, through its description. Its full descriptor digest
  agrees with the audit matrix. Policy and maturity remain unchanged.
- The broader TUI context suite passed 435 checks before the final presentation
  refinements. All 28 focused comparison checks then passed on the final code,
  including two added source/label checks and complete Back controls at all sizes.
- The workspace build, Core/TUI Clippy, CRAP-risk gate and all ten repository
  gates passed. Final presentation evidence is in `final-results.json` and
  `final-draft-receipt.json`; earlier runs remain separate.
- Final native journey `J342`, attempt 3, has 39 machine passes, zero failures,
  two pending operator judgments and 30 capture sets. It covers 40x12, 60x20,
  80x24, 96x89, 120x36 and 160x48, independent view positions, source claims,
  missing/null, five-pass draft preservation, explicit draft recovery and a
  no-color restart. Its 6,411 repository inputs and 13 frozen programs remained
  unchanged during execution. The final native SHA-256 is
  `613d48f83384d57bb2fb862a34f9fb445a543b6b9d922d2bee383f3b5ece4f1c`.

The earlier attempts remain evidence. Attempt 1 had a runner archive-copy typo,
an early capture, an assertion against a provenance string import replaces, and
an assumption that the allowance table already existed. Its compact screen also
exposed a clipped Back label and unclear missing-ID labels, which were repaired.
Attempt 2 had 31 machine passes and one observer failure because it expected a
fresh form instead of the correct saved-draft recovery picker. Attempt 3 restores
the draft explicitly and checks its five passes and preserved cursor.

## Previously generated context

The same frozen binary compared the owned invoice draft
`tmr_125e5c7aa5d04f1a8562f7654f2f10ca` with its exact inherited parent
`tmr_a53f6f6541d24d0e8e869a107ff82ad5`. The saved result contains 121 stored field
changes and no unique-ID order changes. Its source and context references remain
distinct. Twenty tmux capture sets inspect Text, Graph, Source and Other, including
compact paging and return to the candidate.

Before/after checks preserve all 14 source hashes, the active-context manifest,
plan, queue, saved result, call reservations, allowance revisions, work attempts,
finding observations and human review decisions. No context was accepted and no
new model request was made. Cumulative experiment consumption remains 16, with
no approved requests left and dollar consumption unknown. This reads the earlier
GPT-6 Luna low result; it performs no new inference or accuracy experiment.

Thirteen selected ANSI cell replays were visually inspected, including native
and saved-live views, compact controls, literal values and no-color rendering.
They use Menlo 15 and a chosen dark background and are not OS screenshots.
The two operator judgments remain pending. Stored comparison and these captures
do not certify model semantics, broad-history performance, accessibility in all
terminal configurations, revision-specific fix adjudication, or the complete
investigation workflow. The generated data-type process nodes still require
human architecture review.
