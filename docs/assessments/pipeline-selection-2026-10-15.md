# Internal source-class selection

The internal class selector had a runtime declaration that disagreed with its
executor. Supplied classes run locally. Omitted classes request a model, but the
descriptor declared `Never`, so normal callers omitted the runtime and manually
supplied runtimes could reach an unbudgeted query. The retained baseline test
fails with `Unbudgeted selector query reached`; it makes no provider request.

## Shared dispatch and useful results

`pipeline:taint-cwe-select` now declares `InputAware`, requires an explicit
workspace and accounts model proposals as Scope work. Canonical `cwes` and the
retained `cwe` alias use no model or allowance. Invalid supplied values fail
without querying. A missing selected model produces an error without fallback.

Model selection uses the selected model and supplied inventory snippets, with
no agent tools or MCPs. Inventory preparation requests at most 60 files and
1,024 source bytes per file. The proposal is guidance, not evidence that those
classes contain vulnerabilities or that the repository has complete coverage.
Structured-output repair attempts use the same durable call allowance and
cannot consume protected Review capacity under the tested Scope binding.

The result text now includes the actual identifiers, names and reasons, alongside
the existing structured `data.cwes`. Class selection and `pipeline:task-selector`
are auxiliary. Neither can publish primary Scan completion, create campaign jobs
or establish findings. Tool names, existing aliases and result data remain
compatible. The [migration notes](../../RELEASING.md#internal-source-class-selection)
describe the corrected runtime and allowance requirement.

The existing direct-dispatch test now supplies an accounted Scope runtime.
It proves execution through prepared dispatch. No current scanner call site
automatically consumes this selector's output; its DAG node remains metadata.
This checkpoint does not credit that metadata as execution ordering or claim an
automatic phase-to-phase consumer.

The native restart check also exposed a quit warning for untouched planning
defaults. The warning previously treated any selected task as an unsaved edit.
Planning state now compares the current selection with its recorded defaults
and checks rebuild requests and changed drafts from other phases. Deselecting
every default still counts as an edit. A restored current phase uses its live
selection, so reverting an edit is not overridden by its older saved draft.
Untouched defaults no longer require exit confirmation. Actual drafts retain
the existing confirmation and content-hiding behavior.

## Verification record

Evidence is retained at `/tmp/kuzushi-pipeline-selection-20261015`.
Seven new contracts pass: unbound refusal, descriptor/input agreement, local
supplied classes, one admitted proposal with protected Review, malformed output
and repair admission, missing-model refusal, and invalid supplied values.
The existing direct selector dispatch and TUI auxiliary phase-result test pass.
The policy diff contains exactly one changed tuple: this selector's runtime
changes from Never to InputAware and its workspace becomes required.

There are 34 distinct focused Rust passes: nine core dispatch/policy checks,
one TUI auxiliary-result check, four planning-selection checks and 20 quit
presentation checks. The workspace build passes. Earlier evidence retains the
41-line risk failure and the helper extraction that resolves it.

J292 in `native-v2/20261015-204522/J292` has 19 machine passes, zero failures,
17 capture pairs and three pending human judgments. It exercises supplied
classes without a request, unbound refusal, six-size allowance review, one
intercepted Scope request, visible identifiers and reasons, a second-request
refusal, no Scan jobs or findings, clean idle exit and no-color restart. The
reservation is settled as Scope work with protected Review untouched. Fixture
source and the selected model remain unchanged.

Fresh headless CLI probes also consume supplied classes through canonical JSON
and the descriptor option alias, without a configured model or credentials.
Both successful run receipts record `model: null`, retain the selected class and
leave source unchanged. Their commands and outputs are in `cli-model-free`.

The final frozen binary SHA-256 is
`d6dd3e6f2154fa14354e4e652cfb7c9e06fd0937d776212a3c124eb208a043ab`.
Source, runtime and native manifests are retained beside the logs. The earlier
J292 failure records the unnecessary quit warning after otherwise successful
selection and restart accounting. Native fixtures intercept transport completely
and execute no target source. They do not qualify live model usefulness. Real
experiment usage remains at 14 previously approved provider requests; no further
real requests are approved.

The complete J121 rerun on that same binary is
`full-investigation-v1/20261015-204600/J121`: 135 machine passes, zero failures,
100 capture pairs and 17 pending human judgments. It retains admitted-request
cancellation, partial Report, explicit retry, allowance exhaustion, the specific
six-to-seven-call revision, three fixed discovery jobs, human FP and deferral
decisions, final export and no-color restart. The legitimate edited Map selection
still requires quit confirmation. Missing context shows an honest failure reader.
Combined native evidence is 154 machine passes, zero failures, 117 authenticated
capture pairs and 20 pending human judgments. Both runs retain `REVIEW_REQUIRED`.

All ten final quick repository checks pass, including workspace checking, model
safety and the risk proxy over 71 changed code files with 15 support checks.
`quick-final-receipt.json` is a dirty draft receipt with drift recorded; it is
not signed or eligible for publication. Focused ANSI replays use a chosen dark
background and are not OS screenshots or operator acceptance.

## Remaining qualification

The tool remains internal and excluded from normal catalog discovery. Its class
proposals have no demonstrated downstream scanner consumer or general accuracy
qualification. The full investigation plan and operator UX acceptance remain
open. No model-backed discovery, exploit work, reproducer work or vulnerability
patching is introduced by this change.
