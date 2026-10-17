# Draft artifact generation and reading

The retained before-probe found four user-visible failures in the PASTA artifact
reader: malformed and oversized optional files disappeared without a warning,
an empty scope object reported a completed model, and a literal trailing space
in the directory name was removed. The producer also ignored edit preservation
for its draft files and could emit unsolicited bridge findings despite the
default `emitFindings=false` option.

Evidence is retained at `/tmp/kuzushi-randori-contracts-20261016`. These tools
remain outside the default operator catalog. No implementation is deleted.

## Per-tool contracts

| Dimension | `randori:pasta` | `randori:threat-model` |
| --- | --- | --- |
| Purpose | Optional experimental PASTA-framed context draft. Use the canonical context workflow for accepted context. | Read historical draft artifacts. Prefer `threat-model:read` with the same `outputDir` and `methodology=pasta`. |
| Phase | Auxiliary Labs Map action. It cannot complete Map or accept context. | Auxiliary Compatibility reader. The DAG dependency is metadata, not execution ordering. |
| Inputs | Explicit selected model, Context allowance, source snapshot and declared limits. Stage names frame one synthesis request. | Literal contained artifact directory and methodology. A legacy model value is accepted but explicitly ignored. |
| Execution | Shared prepared dispatch, selected-model routing, no tools/MCP and one turn per query. | Shared prepared dispatch with no model runtime. Exactly seven known paths; no directory traversal. |
| Outputs | Normalized JSON and Markdown draft files. No active context replacement. Findings require explicit opt-in. | Read receipt, document and retained stage objects. An inactive import creates an immutable context for the exact context reader. |
| Failure | Existing files refuse before querying by default. A second preflight and no-clobber publication preserve files created during generation. Explicit replacement requires `preserveUserEdits=false`. | Malformed, oversized, linked, unreadable and cancelled reads are disclosed. An unusable primary cannot silently fall back to stage fragments. Missing optional files are normal. Empty DFD content stays partial. |
| Resources | Shared durable Context reservations cover requests and repairs. The isolated draft policy does not qualify for semantic-cache reuse. Protected Review capacity stays separate. | Normalized file limit 8 MiB, stage limit 16 MiB, aggregate read reservations 32 MiB. Failed reads retain conservative reservations; oversized files consume no content read. Cancellation is checked between files. |
| Interfaces | Shell and run share options and dispatch. This is not a Scan engine. | Legacy and canonical readers consume identical draft documents; exact immutable reads keep their separate authenticated path. |
| Product value | Repairs edit loss and unsolicited findings. Live draft quality, late cancellation and useful incremental generation remain unqualified, so the action stays Labs. | Repairs hidden omissions and literal path corruption without promoting historical artifacts to accepted context or complete repository coverage. |

## Identity and failure limits

The historical reader labels source identity `unverified`. File hashes identify
the bytes actually decoded; they do not authenticate those bytes against the
current repository SHA or establish that a finding has been fixed. No context
is accepted by reading a directory. Importing a document against the current
tree also does not retroactively prove the quality of its original generation.

Read reservations include one extra byte per attempted read to detect growth.
Successful UTF-8 decoding releases unused capacity; failed reads retain the
upper bound. Metadata, filesystem overhead and total database IO are outside
that content-read limit. Requested `maxElements` and `maxThreats` constrain
prompt framing and input ranges, not a guaranteed output cardinality. The two
output files are published separately, so a
late failure can leave one completed draft file. There is no automatic retry,
scope expansion, Scan or follow-up job.

## Verification status

The first focused pass found a private test import and a late-writer fixture
using a path outside the declared state-write surface. Both are corrected.
There are 635 distinct focused Core passes: 616 context checks, twelve atomic
write checks, four phase-result checks and three display-name checks. The
workspace build, architecture, risk gate and all ten final summary checks pass.
The risk gate covers 287 changed code files and fifteen gate-support checks.
Draft receipts remain dirty and unsigned; they are not publication receipts.

The four retained before-probes now return partial for malformed, oversized and
empty stages, and completed for the literal trailing-space directory. The
complete 187-row registry comparison changes only the two audited actions.
Default and optional-visible catalogs remain unchanged. Eleven hidden Core
actions still need qualification, including seven descriptor-only cases. All
nine original broad delivery milestones remain open.

The initial J312 generated the draft correctly but stopped on a fixture that
compared a relative output path with the TUI's canonical absolute path. That
failed run and its frozen manifests are retained. The corrected final run is
`literal-paths/native/J312/20261016-141907/J312`: eighteen machine passes, zero
failures, 26 capture pairs and three pending human judgments. It admits two
intercepted Context requests, refuses implicit overwrite before another query,
reads the produced document through both paths and imports it as an inactive
immutable revision for the exact context reader. No observation, finding
decision or follow-up queue is created. The only primary Map attempt belongs
to the explicitly requested canonical import, with matching legacy and v2
records. The draft tools create no phase attempt or active-context change.

Sequential J304 is `literal-paths/native/J304/20261016-142001/J304`: 55 machine
passes, zero failures, 54 capture pairs and seven pending human judgments. Its
six fixed local jobs and intercepted requests retain six observations, the
recorded policy decision, reviewed guidance, retirement and refusal of future
use through export and no-color restart.

Both final journeys use the same thirteen programs, 4324 repository source
inputs and 756 runtime inputs, unchanged during execution. The native SHA-256 is
`c4956a853bfce93a2303dd2d202caed44aa3a3bfc821b63040eaf122eb87f42c`.
`literal-paths/native-evidence.json` authenticates eighty capture pairs across
six viewport sizes and no-color restart. There are 73 machine passes and ten
pending human judgments; both journeys retain `REVIEW_REQUIRED`.

A subsequent J312 reading check authenticates the running native process and
40x12 pane. Four page actions reach `source revision unverified. No context
accepted.` and the malformed-stage warning. Its six supplemental text/ANSI
pairs and process proof are retained under `literal-paths/J312-source-reading`.
The intercepted request bytes and operator configuration stay unchanged.
Selected native frames were visually inspected as ANSI cell replays. They are
not OS screenshots, human acceptance or reference-product parity evidence.

The native transport is fully intercepted and cannot use the network. It checks
GPT-5.5 with medium reasoning and fresh tool-free sessions; this demonstrates
contracts, not inference quality. Human screen judgments remain separate from
machine checks. No new live model request is authorized or made. The fourteen
earlier live requests remain the cumulative experiment usage. No repository
commit or push is made, and the earlier publication proposal remains unchanged.
