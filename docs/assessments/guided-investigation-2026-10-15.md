# Visible Setup recovery and a complete local investigation

An owned fixture exposed a misleading Setup state. Its parent `.gitignore`
hid `.kuzushi/scope.toml`, so workspace policy correctly refused Map artifact
initialization. No worker started, but Start Map still said `READY`; the cause
was available only through notices and logs.

Setup now retains the launch cause on Start Map, shows `RETRY`, and offers the
complete explanation through its existing paged details reader. The failed
step remains queued and the plan pauses. An explicit Start Map retry rebuilds
the selected plan, preserving its choices. Opening an editor retains the cause;
switching targets clears it. An unrelated background or prior-target refusal
does not change Setup or focus. The shared workspace policy guard is unchanged.
This is session state, with no new public artifact or dispatch contract.

## Native evidence

Final J280 is retained at
`/tmp/kuzushi-setup-retry-20261015/tui-v2/20261015-073307/J280`.
It runs the installed `/opt/homebrew/bin/kz` wrapper with the frozen native
bundle at `/tmp/kuzushi-setup-retry-20261015/native-v1`.
The native executable SHA256 is
`4359ed886769d9cfcc90c01d86042d23fb7db91a40054604bc7f02e79ccc27ae`.

The journey uses visible controls to select manual context, edit its path,
observe the launch refusal, read its full cause and retry the same Map plan.
The helper explicitly repairs only the owned fixture's `.gitignore` after the
refusal and records before/after hashes in `policy-repair.json`. It does not
weaken product policy or dispatch product tools. The two inert public-example
source files are unchanged. Subsequent source comparisons use the repaired
three-file source baseline, not the original ignore policy.

The accepted Map supplies an immutable inactive context revision. Guided
`next` opens Scan planning. The operator chooses `secret-scan`, three fixed
passes, one worker, zero provider calls and zero protected Review calls, then
explicitly approves and launches. The three real local jobs complete once
each, producing six observations for two finding identities. Human FP decisions
for the two labeled public examples remain in the ledger and JSON report.
The report and exact three-job study survive no-color restart. Helpers seed
source and inspect state; they create no product plan or job and perform no
product dispatch. No model request, exploitation or vulnerability patching
occurs. This does not validate live-model discovery quality.

| Verification | Recorded result |
| --- | --- |
| Focused Setup suite | 101 checks passed, including four new launch-failure checks |
| First narrow launch-failure run | Four of those checks also passed separately |
| Existing ad-hoc artifact-failure regression | One additional check passed |
| Full cause reading | Six sizes from 40x12 through 160x48, paging and plain output |
| Workspace build | Passed; existing vendored terminal and dead-code warnings remain |
| CRAP-risk proxy against the parent remote | Nine changed code files passed |
| Frozen inputs | 4,212 crate/build inputs and 671 runtime/test inputs unchanged across final verification |
| Final native J280 | 46 machine passes, zero failures, 39 text/ANSI capture pairs, five human judgments pending |

The initial native run reached export with 40 machine passes, then correctly
stopped at the session-exit confirmation instead of relaunching into a live
shell. The final script confirms exit explicitly. Its failure-screen assertion
also uses the complete failure caption: the earlier short `RETRY` check could
match the fixture path. The initial capture is not credited as the failure
overview. Final captures 09 and 10 show the actual refusal and complete cause.
The driver is unchanged. Exit 4 means `REVIEW_REQUIRED`, not human approval.

## Copy and remaining acceptance

Register lint of changed product strings:

- Positioning vocabulary: no hits.
- Brand-voice banned words: no hits.
- Internal jargon leaks: no hits.
- Typography and inflated language: no hits.
- Unsupported success labels: no hits.
- Required Liminal product vocabulary: inapplicable to Kuzushi. Existing
  Map/Scan/Review and plan terminology is retained.

Applicable product-copy verdict: **CLEAN**.

This qualifies one local visible-control flow and its initial launch failure.
The five visual judgments, broader failure combinations, full module readiness,
large-repository behavior and reference-level operator experience remain open.
No full Rust-suite, platform, release or broad delivery milestone is certified.
The completed live Scan remains at eleven cumulative experiment requests;
this local validation consumes none of its unused capacity or protected Review.
