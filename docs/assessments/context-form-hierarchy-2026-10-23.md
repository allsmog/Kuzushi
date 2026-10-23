# Context planning hierarchy, 2026-10-23

This draft on main follows `b891f86c842e575850f915a11ed3eaf89d07611b` and the
[source-index and context acceptance](source-index-context-acceptance-2026-10-23.md).
It improves the context planning decision without changing provider execution,
approved workloads or source membership.

At 40 by 12, the first screen now shows current consumption or missing approval,
the selected file count, one job and attempt, proposed total calls, protected
Review calls, unknown dollar cost, model and next action. Model selection and
output-retention controls remain visible. Longer source details and receipts
follow those decisions. The inherited revision has a readable catalog label
when available; its exact identity remains in the details and options.

Prepared evidence and model labels use the frozen receipt, rather than a later
mutable draft. A separate regression reproduced a draft header showing the
session model despite an explicit different model in the tool input. The header
now follows canonical dispatch precedence without changing session selection.
Missing or malformed inheritance is shown as unavailable. Frozen reasoning is
shown as `runtime` when its value is absent from the recorded tool input; the
current session is not presented as historical evidence.

Inventory limits use exact KiB/MiB units without rounding irregular byte counts
or substituting zero for unknown values. Linked DFD evidence quotes literal
paths while preserving narrative evidence as prose. Leading-space and ordinary
paths remain visually distinct, with their dispatch identities unchanged.

| Check | Evidence |
| --- | --- |
| Focused Rust tests | 63 distinct passes across context presentation, inventory formatting, DFD inspection and context application; final evidence suite rerun after the explicit-model correction |
| Build and lint | Workspace build and TUI Clippy with warnings denied passed |
| Repository summary | All ten checks passed, including model policy, workspace check and CRAP-risk, with a separate dirty draft receipt |
| Final J339 | 54 machine passes, zero failures, 43 capture sets and three pending operator judgments |
| Final J341 | 35 machine passes, zero failures, 29 capture sets and three pending operator judgments |
| Frozen runtime | SHA-256 `f3032cd7a8556b3efe750251bfdd82dda63495fbf9a0eb2758fe63e74436bf68`; 6,392 repository inputs and 13 programs unchanged during the final journeys |
| Model work | One intercepted request per journey; no new real request, target execution or follow-up work |

The new first-screen test failed before the change and passes at all six
viewport sizes. The explicit-model mismatch also failed before correction.
The actual-cap J341 retains the 100,000-entry, 512 MiB and 256 KiB per-file
inventory limits, one job, one worker and one attempt. Three calls reserve two
for Review. It keeps the selected source unchanged, the result inactive, and one
settled intercepted request through no-color restart. Partial enumeration and
complete selected excerpts remain separate. J339 retains the different active
context, original selected diagram and original five-pass parent draft.

The first native attempt passed its machine checks but produced incomplete
wide/tall captures during resize. The shared harness captures immediately after
resize. The two public journeys now wait 0.5 seconds after resizing; the shared
`run-journey.sh` is unchanged. Both final journeys were rerun. Their five resized
planning frames have the expected centered border and full viewport height.
The original approval and completion observation limits are unchanged.

Seventeen final terminal-cell images were inspected across all six sizes,
approval, literal evidence, Back restoration and restart. These are ANSI cell
replays using Menlo 15 and a chosen dark background, not operating-system
screenshots. Evidence is retained locally under the ignored directory
`scripts/devex/artifacts/context-form-hierarchy-20261023/`, with final journeys
in `attempt-2/` and the final code receipt in `settled-draft-receipt.json`.

Six formal operator judgments remain pending. Broader context-reader hierarchy,
clearer frozen reasoning, focused-row versus component action labels, module
usefulness and complete investigation/reference-UI qualification remain open.
No broad delivery checkbox closes. Real experiment usage remains 15 requests,
with no further live allowance approved. This assessment and its documentation
links were written after the frozen journeys and are outside their manifests.
