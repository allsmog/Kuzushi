# Dependency readiness and exact operator paths

The capability picker now distinguishes a missing declared executable from
ordinary input review. The registry derives requirements from executable option
metadata and canonical prepared values. The existing background reader checks
presence without invoking commands, keeping filesystem work outside rendering.
Results bind to the target, exact requirements and refresh generation. The
bounded cache retains 32 results. With an empty composer, `r` rechecks while
preserving selection; with a draft, `r` remains text.

Semgrep publishes its existing executable default in the descriptor. CodeQL's
optional binary retains adapter resolution; unprovided or undeclared dependencies
remain unassessed. Unix presence checks reject files without execute permissions.
Semgrep preflight shares the lookup and keeps its structured failure behavior.
Presence remains an input hint, not a version or functional-output verdict.

## Defects and repairs

Semgrep trimmed executable filenames, so a selected file with a trailing space
could pass a literal presence check while execution referred to a different path.
The adapter and presence lookup now preserve the exact filename. A focused test
covers canonical alias preparation, the recorded requirement and preflight
without invoking the inert file.

The real TUI experiment then showed that `setg` stored quote delimiters literally.
Text/path operator values now use a shared decoder for complete double-quoted
JSON strings, retaining spaces and escapes inside. Unquoted text keeps its prior
trimming behavior. Malformed quotes fail before storage. Typed JSON inputs and
existing stored strings retain their literal contract. The JSON option editor
restriction remains, keeping structured workflow-owned artifacts in their forms.

The complete options suite also exposed an older name classifier that mistook
Secret Scan workload limits for credential fields. Its test now recognizes the
limit namespace while still rejecting credential-shaped suffixes, including
`secretScanMaxApiKey` and `secretScanPassword`. Production secret handling is
unchanged. The initial risk gate caught two oversized dispatch functions; catalog
key routing and bounded cache writes were extracted into cohesive helpers.

## Native evidence

Final J190 is
`/tmp/kuzushi-dependency-readiness-20261011/quoted-path-native/20261011-010502/J190`.
It records 14 machine passes, zero failures and 14 authenticated native text/ANSI
captures at six terminal sizes plus no-color restart. Native SHA-256 is
`7f797ce25c0d245e20be29e0e12c1f1823730958c9749bfd01f0d2dff74e3d47`.
Every requested dimension matches the actual dimension. No-color ANSI contains
no color escape codes. Both scoped assistant judgments are separate from raw
REVIEW_REQUIRED and operator approval false.

The fixture locally clones the existing owned repository at main SHA
`f29dc288e0660ad20d074fc219c025f98ef7d155`, completes and explicitly accepts a
real runtime-free default Map, then sets a quoted external inert filename.
Changing its execute permissions and pressing `r` demonstrates missing, present
and missing states. The saved option retains its trailing space without quote
delimiters. Loading the command starts no work; typing `r` edits the draft.
Escape clears it and restores the same selected engine. Restart recovers the
saved binding and missing-dependency explanation. At 40x12, the engine identity,
missing state and full recovery remain readable, with dense surrounding chrome.

Tracked source is unchanged. Provider reservations, work attempts, observations
and review decisions remain zero; no scanner or target source executes. The
original live fixture and owner configuration are not modified. Earlier evidence
is retained: one presence assertion matched generic copy before settlement;
the exact-path run then failed on literal quote storage. Both defects have
specific final assertions instead of being counted as successful presence tests.

One capture shows a stale-inventory workspace notice despite unchanged tracked
source. Its cause is not established by this increment and remains a follow-up
for the complete journey, rather than a claim that Map freshness is qualified.

## Remaining acceptance

There are 231 distinct passing focused tests covering dependency lookup,
prepared dispatch, Semgrep adapters, options, catalog keys and background
hydration. Workspace build, the 176-file production risk proxy and all ten
repository summary gates pass. The unsigned receipt at
`/tmp/kuzushi-dependency-readiness-20261011/precommit-verify-receipt.json` records
dirty/drifted state and cannot attest to a clean commit. Final documentation
checks cover the evidence-only additions after that gate.

Actual installed scanner execution, versions, configuration, useful nonempty
outputs, scope enforcement and complete interface parity remain separate module
evidence. No module is promoted or retired from a presence test. The registry
still has 111 visible tools, with 71 assigned scoped assessments and 40 unassigned,
including eight excluded tools. Live Review approval, complete per-tool readiness,
operator screen acceptance and full reference parity remain open. All nine broad
delivery milestones remain unchecked.
