# Bounded source-only deep discovery

`systems-hunt:deep-semantic-hunt` is now hidden Labs Scan work under Discovery
allowance. It requires explicit selected CWE classes. Its old executor could
select classes implicitly, ignored declared source limits, requested structured
output repair and silently discarded malformed finding rows. Those paths are
replaced. The existing tool name, report fields, class handoff and artifact
references remain available.

One fresh session requests one tool-free model turn with 4096 output tokens.
Adapter token/turn enforcement varies; transport retries share approved call
capacity. There is no output repair, implicit class selection, delegation,
source execution or follow-up job creation. Reasoning inherits the selected
runtime unless explicitly overridden. Missing model, active ledger or matching
target fails before the request. Unknown dollar cost stays unavailable.

Source prefixes reuse shared bounded inventory. Defaults are 80 files, 2048
bytes/file and 160 KiB overall, with a separate 192-KiB prompt-source budget.
The declared ceilings are 100,000 files, 256 KiB/file and 16 MiB source bytes.
Inventory retains its 100,000-entry/512-MiB limits and containment rules. Scope
membership uses indexed sets; it does not repeatedly search a linear file list.
Ignored, uninspected, truncated and prompt-clipped material remains disclosed.
Frozen input is limited to 512 KiB and system text to 16 KiB.

An exact accepted `scanScopeRef` restricts discovery membership. Shared files
have the context-only role and cannot become finding targets. Without a scope
reference the action explicitly uses repository-wide systems-source prefixes.
Supporting context is captured or read through authenticated `scanContextRef`;
stale supporting context fails before model work. Threat context pins an exact
revision or explicit omission. Neither reference changes active context. Legacy
threat context without an immutable revision requires import or explicit omission.
Each context excerpt is limited to 8 KiB, with omissions recorded.

Responses are limited to 128 KiB and the approved finding count. Every row must
have valid required fields, a supplied discovery path, an in-prefix line,
selected CWE ids and bounded evidence anchors into supplied text. Unsupported
fields, invented paths/lines, context-only targets, malformed rows and excessive
arrays fail without repair or partial finding imports. These checks establish
supplied-source references, not finding truth. Observations remain unverified;
human decisions and recurrence are separate.

Native Review inspection exposed a missing handoff: parsed citations were
only in message/artifact text, leaving the structured evidence section empty.
Findings now include an unscored model-claim row plus deduplicated source
citations with actual supplied quotes, capped at 256 bytes each. Context-only
quotes retain their role. Model claims never become observed-source citations.
The two additive evidence kinds use the legacy zero confidence field as a
placeholder; presentation explicitly says unscored and does not reinterpret
legacy zero values. Source grounding preserves literal filenames, including
whitespace. The finding remains unverified after evidence insertion.

Detected source drift or cancellation before ledger publication withholds the
generated candidates. Frozen raw output, input and original source identity
remain readable. Run-specific inert artifact paths prevent later passes from
overwriting earlier artifacts. Publication failures retain consumption and warn
when partial ledger writes may exist. The existing ledger still captures file
provenance during insertion; this guard does not provide an atomic filesystem
snapshot transaction. That broader provenance boundary remains open.

Unrelated legacy options remain declared but reject explicit and stored values.
Remove those settings before this standalone action. No module is deleted.
The obsolete private recursive-query wrapper, permissive class parser and
inventory formatter were removed after reference checks. The separate legacy
production-context collector remains for its own audit. DAG dependency metadata
does not schedule or consume the CWE proposal; callers supply the selected classes.
This change does not register another automatic `sast:scan` engine.

Focused tests cover shared dispatch, ledger/artifact consumption, immutable
scope and context, failures, cancellation, source drift, unknown costs and
protected Review capacity. A bridge probe confirms that the source-only profiles
mount no MCP tools even with the compatibility switch forced on. There are
481 distinct focused Rust passes, one ignored registry fixture exporter,
a passing workspace build and ten passing quick gates. The risk proxy covers
384 changed code files and fifteen supporting checks. These are local dirty
draft receipts, not signed publication verification.

Final sequential J318/J304 have 91 machine passes, zero failures,
108 capture pairs and thirteen pending human judgments. All six sizes,
no-color output, thirteen frozen binaries and source/runtime manifests are
verified. J318 retains one observation, three structured evidence rows, one
human FP decision, two reservations and unused protected Review capacity.
J304 retains the six fixed intercepted requests, learned context, decisions,
export and retirement across restart. Zero new live provider requests occur.
The earlier failed fixture assertions and the capture-before-resize-barrier pair
remain archived. No-color tail qualification now requires a rendered narrow
frame and actual receipt-tail text, rather than accepting the Replay heading.

Inspection of 28 ANSI cell replays plus four final confirmation frames found
usable paging, retained controls and the corrected no-color tail.
These are rendered tmux cells, not OS screenshots or human acceptance. Narrow
frozen inputs remain dense, long evidence rationale truncates, and failed-output
logs are noisy. The dedicated failure reader was not inspected in this pair.
Reference parity and operator delight remain open. Source-revision guards
remain distinct from the open atomic snapshot/publication requirement.

The complete registry has 189 actions; the visible 118-tool catalog is byte
identical to the preceding checkpoint. Only this hidden descriptor changed.
The policy tuple fingerprint is unchanged, but does not cover maturity,
allowance or option definitions; those have separate dump and execution
checks. Eight hidden Core actions still need full qualification, including
three descriptor-only actions. Moving discovery to Labs does not certify it
as production-ready. No module was retired.

Live detection quality, broad human UX and reference parity remain unqualified.
Fourteen earlier real requests remain spent, with no live allowance remaining.
Publication stays **Keep as draft** on `main`; all nine broad milestones remain
open. Evidence: `/tmp/kuzushi-deep-discovery-20261016`.

The later [captured-source increment](captured-observation-sources-2026-10-16.md)
replaces this adapter's insertion-time source read with authenticated retained
bytes and original-snapshot references. The limitation described above remains
historical for this adapter and current for other insertion paths. Global source
migration, complete SHA-transition UX and broad acceptance remain open.
