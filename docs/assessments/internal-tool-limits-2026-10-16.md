# Structured scanner settings and honest finding limits

Two actual shared-dispatch probes found contract defects in hidden tools.
`uaf-hunt:hunt` advertised custom allocation/free pairs while canonical
preparation rejected those input keys. `chrome-rce:scan` returned three
observations from three comment lines despite `maxFindings=1`.
Neither probe used a model, executed target source or established a vulnerability.

## Repairs and retained boundaries

Both allocation/free settings are now declared advanced JSON options. A
nonempty `allocFreePairs` array replaces the defaults; `extraAllocFreePairs`
extends defaults when the replacement is omitted. Explicit non-array values
fail rather than silently using default pairs. Unknown input keys still fail
at shared preparation. These changes qualify input plumbing, not the agent,
clangd integration or discovery usefulness.

The first native attempt exposed an additional UI defect: every JSON setting
was labeled workflow supplied, so the new arrays could not open their editor.
`OptionSpec` now has additive `editableJson` presentation metadata, omitted by
default. Only explicitly opted-in JSON settings use canonical JSON coercion,
visible values and lossless editor drafts. Legacy plan, context and allowance
references remain read-only. This metadata grants no execution authority.
The focused malformed-draft check also caught legacy JSON coercion accepting
unfinished JSON as a string. Opted-in settings now require complete JSON text
at shared operator-text coercion and preserve typed values exactly. Legacy
workflow JSON coercion is unchanged.

The Chromium heuristic accepts only positive finding limits and stops collecting
when it reaches the selected limit. That result is partial in both the tool
envelope and findings ledger. Its warning puts the omitted-work reason before
the target path. It retains the registered tool names and finding rule identity.
Existing callers of generic finding persistence keep their completed behavior;
this scanner passes its actual status through the same persistence boundary.

The scanner is Labs and its visible label is **Inspect Chromium handle checks**.
Finding text describes a text match requiring source review. The engine can match
comments and recognize rejection-marker text elsewhere in a file. It therefore
establishes neither executable calls nor correct handle validation. Traversal
still lacks a shared entry/read budget and complete cancellation qualification.
This finding-cap repair does not qualify exact accepted scopes, complete coverage
or source settlement. The separate changed-hot-path action is retained; no
trigger, reproducer or exploit is generated or executed.

## Verification

Evidence is retained at `/tmp/kuzushi-hidden-contracts-20261016`, including
before-change preparation and dispatch results. Focused tests cover canonical
arrays, invalid values, replacement/extension semantics, unknown keys, positive
limits, declared aliases, exact raw-observation counts, ledger status and
stopping before a later oversized file. Existing generic persistence behavior
has separate regression coverage. Tool labels name actual work.

Fifty-nine distinct focused checks pass: 26 Core, 31 TUI and two descriptor
compatibility checks. The workspace build and risk gate pass. Final repository
summary verification passes all ten checks, including workspace checking,
format, architecture, model safety, documentation and the risk gate. The receipt
at `final/receipt.json` records a dirty draft and is unsigned; it is not a clean
publication receipt. The verifier marks dirty runs `driftedDuringRun`; the
separate frozen source/runtime manifests establish unchanged native inputs.

The final J305 run is
`final/paged/native/J305/20261016-084153/J305`: 27 machine passes, zero failures,
33 text/ANSI capture pairs and four pending human judgments. It inspects and
persists the advanced structured option without running the UAF scanner,
dispatches one capped local heuristic, saves a scripted human deferral, exports
and restarts without color. Editor, partial receipt and Report each cover
120x36, 160x48, 96x89, 80x24, 60x20 and 40x12. At 40x12, paging reaches the
remaining limit explanation. The restarted setting retains its exact JSON array;
the observation and recorded deferral remain unverified.

Thirteen native programs, 4,298 source inputs and 740 runtime inputs are frozen
and unchanged during that run. Native SHA-256 is
`f387f83fc6a8adba451b0781ced627c2e92c8dcd606b31350b31f99083b8b0ea`.
The retained initial UI failure and malformed-draft regression are distinct
from this successful machine run. Selected ANSI cell replays were visually
inspected using Menlo on a chosen dark background. They are not OS screenshots
or human acceptance; the harness retains `REVIEW_REQUIRED`.

No live provider work is authorized by this increment. Earlier real experiment
usage remains fourteen requests. The prior 366-file publication proposal remains
an immutable separate tree; this increment is outside that pending approval.
