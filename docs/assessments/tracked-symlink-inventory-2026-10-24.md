# Known tracked symlinks remain visible exclusions

Preparing a source-only scope proposal on published commit `55e4fa7b52` exposed
an inventory defect. The Git-index path list contained the tracked `CLAUDE.md`
symlink. Regular-file opening correctly refused it, but classified that known
exclusion as incomplete enumeration. `context:build` returned partial, and
`threat-model:import` then correctly refused complete entry-point grounding.
The failed preparation used no model requests and remains recorded.

The Unix inventory adapter now classifies the leaf relative to its pinned
parent directory without following symlinks. Known symlinks and non-regular
leaves are recorded as exclusions, matching the filesystem walk. Missing
files, unsafe ancestors and classification errors still reach the existing
regular-file refusal and partial-result path. Root replacement still prevents
snapshot publication. No context-import or completeness guard was relaxed.

Other platforms retain the strict partial-result path until their adapter can
provide equivalent pinned-ancestor classification. This change claims no
Windows execution evidence. Complete enumeration under inventory policy does
not mean every repository file was inspected; ignored paths, per-file inspection
limits and other omissions remain separate recorded facts.

Evidence is under the ignored directory
`scripts/devex/artifacts/tracked-symlink-inventory-20261024/`. The strengthened
existing regression first fails on the false truncation. A separate adapter
test covers a broken link, an external directory link, missing files, escaping
paths and unsafe ancestors. The full inventory suite passes 118 checks, with
one existing ignored test. Seven adapter checks and 49 affected scope checks
also pass, together with workspace build, Core all-target Clippy and the risk
proxy for 15 changed code files.

Repeated preparation keeps `CLAUDE.md` as a named exclusion and reports complete
enumeration under inventory policy. Fifteen oversized files still make content
inspection partial. Architecture import is not retried against that partial
snapshot, and its complete-grounding guard remains intact. An explicitly
inventory-only scope study is prepared with `threatModelRef: null`, one fixed
job, one worker and no allowance or queue. All 6,474 tracked normal files retain
their published bytes. No live model request or target-source execution occurs.

The repeated J88 run is under
`scope-context-overview-20261024/native-attempt-6/`. Its frozen binary is
`4ea9d8213a23b80b030af461da93c8eb87d06a3ba25d0faa06dff89376e5b8a3`.
It records 49 machine passes, zero failures, 39 capture pairs and eight pending
operator judgments with 6,483 unchanged source inputs. Three current terminal-cell
replays were inspected. A copied immutable ledger and independent request check
reconcile one intercepted scope request, exact selected overview, unchanged
active context and source, and a separately prepared unstarted three-job scan.
This synthetic response does not establish useful monorepo grouping.
