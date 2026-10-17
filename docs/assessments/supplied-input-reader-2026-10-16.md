# Separate results and supplied input

Replay now offers Result, Inputs and Receipt when an authenticated result
contains an explicit supplied-input document. Tab advances and Shift+Tab
reverses the order. Each page keeps its own scroll position. Held multiline
drafts, cursor and navigation origin remain intact. Prompt mode retains input
ownership; background hydration does not select a different reading page.

Deep discovery moves its readable frozen input from primary output into
`data.inputDocument = {"schemaVersion": 1, "text": "..."}`. The primary result
puts candidate titles and locations before source details. The historical
reader retains the module-supplied model, reasoning setting, requested limits,
selected classes, scope, source prefixes, context references and system text.
An unset reasoning option is labeled explicitly. Requested adapter limits do
not certify provider enforcement. Reading starts no model request, changes no
active context and creates no job.

Existing structured `frozenInput`, `systemPrompt`, raw observations and source
references retain their formats. Older saved results keep their existing
output and two-page reader. The shell's plain Replay includes both complete
safe-display documents independently of the selected interactive page. The
Rust DTO field addition and literal migration are documented in `RELEASING.md`
and `docs/modules.md`; tool descriptors and manifests are unchanged.

The existing result artifact is authenticated before either document is read.
The input document shares the 4 MiB safe-display allowance and the existing
512 KiB and 10000-row per-text limits. Unsupported versions, malformed text or
excessive input produce an explicit Inputs error without hiding a valid primary
result. After invalidation and reread, changed artifact bytes cannot substitute
new text or silently reuse the earlier input. No display limit was raised.

All 121 distinct focused Rust checks, the workspace build and ten final quick
gates pass. The risk proxy passes for 396 changed code files. Result formatting,
input formatting and reading-page state have small named helpers. The quick
receipt is dirty local draft evidence, not signed publication verification.

Final sequential J318/J304 record 118 machine passes, zero failures,
118 capture pairs and fourteen pending human judgments. J318 contributes
63 passes and 64 capture pairs. Its complete primary result fits at 120x36
for the owned one-observation fixture. The candidate is visible at 60 columns;
one page-down reaches its title at 40 columns, followed by its location on the
next page. Result and Inputs cover all six sizes and no-color restart.
Reading preserves three settled intercepted requests, one observation, one
human FP decision record and protected Review capacity. J304 retains its six
fixed intercepted calls, learning experiment, export and lesson retirement.

An earlier J318 assertion incorrectly required the title after exactly two
page-downs. The captured title was on the first page and its location on the
second. The corrected assertions verify both. That failed run, its 61 passes,
one failure, captures and manifests remain archived. All application source
and thirteen binaries are identical across both J318 attempts; only the
pagination assertions changed. The final ten gates were rerun before freezing.

The final source manifest covers 4500 inputs, including vendor sources, assets,
fixture inputs and build configuration, plus 772 runtime inputs and thirteen
programs. All remain unchanged through the final pair. Native SHA256:
`90462658fa8c191444ff90cb988d20e55da8f399491d60cc4b56ea56bc7c79cc`.
Thirty-one ANSI cell replays were generated; sixteen were visually inspected.
These are terminal-cell renderings, not OS screenshots or human acceptance.
Scope/reference JSON remains dense inside Inputs, and long Review rationale
still needs work. Reference parity remains unqualified.

The registry and visible catalog are byte-identical to the preceding checkpoint:
189 registered actions and 118 visible, comprising 81 Core, 32 Labs and five
Compatibility actions. Eight hidden Core actions, including three with only
descriptor evidence, remain unqualified. Other scanners' source binding, the
actual SHA-change TUI journey, larger-tree support and all nine broad delivery
milestones remain open. This is a scoped reader increment, not complete product
acceptance.

A formatting command initially touched four fixture/vendor files outside this
increment. Their exact prior bytes were restored and independently checked;
the recovery evidence is retained. Publication remains **Keep as draft** on
`main`, with the original seven-file index and saved 366-file proposal intact.
No project commit, push or new live request is added. Fourteen live requests
have been spent and no live allowance remains. Evidence:
`/tmp/kuzushi-supplied-input-reader-20261016`.
