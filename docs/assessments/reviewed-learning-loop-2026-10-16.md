# Reviewed lessons in a bounded context experiment

The local learning workflow now checks actual downstream request contents,
alongside its accepted lesson and immutable context references. An owned literal
policy marker supplies source observations from installed Semgrep. A scripted
human decision confirms only that marker, with no vulnerability claim. The
operator drafts and accepts a lesson, then explicitly creates an inactive
context copy. The existing active context remains unchanged.

A separate three-job context experiment selects that copy against the recorded
three-pass baseline. Both studies use one worker and the same six-request
allowance. Their actual model adapter transport is intercepted with isolated
credentials and no network fallback. Every response contains zero model
findings. The local scanner supplies the observations; the test establishes
context delivery and workflow behavior, not model inference or accuracy.

The request assertion decodes the production percent-v1 untrusted-data frame
and compares its exact UTF-8 contents with the frozen scanner preview. It
rejects missing or duplicated frames, malformed UTF-8 and incorrect byte counts.
The test decoder does not change production framing or instruction authority.
Recorded request evidence contains hashes and counts rather than prompt text.

## Source exclusion correction

The first actual unversioned whole-repository scan found the marker twice:
once in source and once in Kuzushi's cached source object. Semgrep does not
consistently apply Git ignore policy outside a repository. Its shared command
now explicitly excludes `**/.kuzushi/**`, covering direct, whole-repository and
exact-file execution. Inspection receipts disclose that exclusion. Public tool
names and options remain unchanged; historical findings are retained.

An installed Semgrep 1.165.0 probe excludes root and nested workspace objects
while preserving ordinary source and the distinct `.kuzushi-other` directory.
The corrected unversioned three-pass regression produces exactly three source
observations. The native learning journey uses the harness's separate Git
fixture and does not substitute for that unversioned regression.

## Verification checkpoint

Evidence root: `/tmp/kuzushi-learning-loop-20261016`.
Thirty-four Core checks and seven TUI checks pass. Five focused Node checks
cover request framing and canceled request numbering. The workspace build and
final ten-command summary pass. The risk proxy passes for 187 changed
production files and its 15 support checks. The final development receipt is
dirty, unsigned and `driftedDuringRun: true`.

Final J304 is `native/J304/20261016-064634/J304`: 51 machine passes,
zero failures, 47 capture pairs and six pending human judgments. Its native
SHA-256 is `b6f230fd366fb5a2a36df93b95d7833595a8ce1b937470a5c45cc01b117aac82`.
All 13 programs, 4,294 source inputs and 738 runtime inputs retain their frozen
hashes throughout that run. The lesson editor is captured at all six sizes.
`native-evidence.json` authenticates dimensions, text/ANSI hashes, the six
completed jobs and exact candidate context consumption. It also checks the
no-color restart captures.

The final state retains six observations, one original human policy decision
and six settled intercepted requests. Retirement blocks new use of the context
copy while preserving historical reading and the earlier export. The source
and globally active context remain unchanged. Report does not credit the old
decision as present review completion on unversioned re-observation. Export
retains that decision's original basis and `later_source_unverified` status;
it does not attach the older generation's lesson to a new generation. The
accepted lesson remains in its own durable history and frozen context.

Selected ANSI cell replays were visually inspected, including the compact
editor, supplied lesson and limits, retired-context refusal and restarted study.
They are terminal-cell replays with a chosen font and background, not OS
screenshots or operator UX approval. Earlier failed fixtures and their
reservations remain intact, including the overly broad ignore rule, incorrect
form navigation, raw-Unicode assertion and incorrect Report expectations.

A later summary run passed nine checks and found formatting errors in three
test files. Formatting occurred after native execution, followed by the five
framing checks. The original native input manifest remains intact. The final
runtime manifest and `post-native-formatting.json` distinguish those formatting
changes from the exact native candidate. All ten final summary checks pass;
no production Rust changed after the verified build.

No target program is executed. No new live provider request, Git commit or push
is included. Fourteen earlier live requests remain spent. Human UX acceptance,
model-generated lesson usefulness and the remaining original delivery
requirements stay separate from these checks.
