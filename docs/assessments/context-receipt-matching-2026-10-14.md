# Match context inspection to its exact saved receipt

The context picker previously accepted completed reads by target and immutable
context revision alone. An ordinary read or a different saved projection of
that same revision could replace the current study's scanner preview and reset
its reading position.

Frozen read previews now include `frozenReference` as additive version-1
inspection metadata. The reader adds it to the returned copy after authenticating
the object. Saved text, content objects, fingerprints and approvals are unchanged;
the object does not contain a reference to itself.

The picker derives its expected reference through the same input builder used
to dispatch inspection. A completion must match target, context revision and
saved projection reference. Unbound revision reads remain distinct from saved
projections. A stale completion leaves the current preview, scroll, text view,
composer and cursor intact. Comparison and other context consumers retain their
existing behavior.

## Verification

The controlled late-completion regression failed before the fix. Its final
version checks missing and different references while reading at a nonzero
scroll offset in a 40x12 viewport. A second test rejects a saved projection
when the current inspection is unbound. These are controlled completion tests,
not a claim of observed OS scheduling or hardware latency.

The locked workspace build and 33 focused Rust tests pass. The native J273
fixture independently checks that the returned reference equals the fixed
plan's reference. Its missing-object refusal and no-color restart remain intact.

Evidence root: `/tmp/kuzushi-tui-integration-20261012`.
Native SHA-256:
`fd253fb4fe3198022507987f0d85dfa1ff09190d23a57cdd283446d8c674e6f7`.
Thirteen executables are frozen read-only. Sequential J273 at
`context-receipt-tui/20261014-224812/J273` records 27 machine passes and 22
live text/ANSI pairs. J121 at
`context-receipt-complete-tui/20261014-224928/J121` records 109 passes and 87
pairs. All captures use this native runtime and the six-size viewport matrix.
The 18 human judgments for these journeys remain pending. Assistant review
does not approve them.

J121's actual workers complete three Map jobs and three discovery jobs. Its
four requests use fully intercepted transport; all three discovery requests
decode to the same saved context. Budget stopping, protected Review capacity,
specific allowance revision, human FP/deferral fixtures, Report and restart
remain intact. Source and active context remain unchanged, with no source
execution or live provider request. The shared spending boundary also already
requires approved or inherited allowance before supported model work; this
change adds no alternate budget path.

This closes the demonstrated preview identity gap. Full Rust/CI/platform
acceptance, physical contrast, hardware latency, operator delight and useful
live discovery remain unqualified. No module is promoted or retired, and the
broader investigation plan remains open.
