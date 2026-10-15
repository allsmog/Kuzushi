# Dependency version-policy inspection and partial coverage

October 10, 2026. Five initial shared-dispatch tests reproduced missing nested
manifest discovery and malformed documents returning apparently clean results.
The former implementation enumerated several root-only manifest groups with
separate directory reads. Its catalog description also claimed stale-version
and known-vulnerability signals that these heuristics do not establish.

## Supported behavior

`dep-hygiene:check` remains Core for dependency version-policy signals requiring
owner review. It does not query advisories, install packages, execute target
source or call a model. Existing package-specific heuristics and identities
remain. Declared `context:build` dependency metadata does not execute context
preparation in the shared dispatcher; direct inspection needs no context index.

One shared bounded regular-file walk now finds recognized root and nested
manifests. It excludes symlinks and directories named `.git`, `.kuzushi`,
`node_modules`, `vendor`, `target`, `dist`, `build`, `.venv` and `venv`.
The limits are 100000 entries, 50000 files and 64 directory levels. Traversal
limit or early cancellation fails before any manifest inspection. The shared
walk uses bounded recursion, with a hard depth guard.

Content reads have a 16 MiB per-file ceiling and a shared 512 MiB allowance.
The inspector opens contained regular files, reserves their observed size plus
one before reading, and retains reservations after decoding or parse failure.
Oversized documents are omitted explicitly, without parsing a prefix. JSON,
TOML, YAML and XML syntax is checked before heuristic inspection. Other
formats retain their existing text heuristics. Cancellation between documents
retains earlier observations and records remaining work as incomplete.

The additive `data.inspection` receipt includes enumerated regular files,
discovered/attempted/inspected manifests, reserved bytes, limits, exclusions and
all gaps. It does not count every excluded entry or claim full repository
coverage. Named root manifest symlinks add explicit gaps for legacy behavior;
other symlinks remain excluded. Direct results now use the shared pre/post
source identity binding. That binding performs additional source IO outside the
inspector's content-read allowance. This is not a whole-operation byte ceiling.

Whole-target and contained directory inspection remain available. The tool
descriptor rejects undeclared `scanScopeRef`; SAST rejects accepted exact-file
membership for this engine before discovery. It cannot silently widen an
accepted file scope. Scanner `scan_artifacts` preserves observed findings and
coverage errors. Legacy `check_dependency_hygiene` and `ScanEngine::scan`, whose
return shapes cannot disclose gaps, refuse incomplete work instead of returning
a misleading clean report. Public report formats and scanner construction stay
compatible; callers must handle the newly honest errors.

## Native reading and recovery

Sequential J180 inspects owned JSON files with a root wildcard constraint,
nested floating tag, malformed sibling and excluded vendor manifest. A separate
CLI child workspace inspects only its contained manifest. The fixture explicitly
prepares deterministic context before SAST rather than crediting dependency
metadata as ordering. Source hashes are recorded before work and checked after
each stage. No target source, package manager or provider request runs.

The first run stopped at the harness's one-row typed-command matcher. Its long
SAST command now uses paste input. The second run exposed a real presentation
defect: SAST retained the malformed-file gap in JSON warnings but omitted the
reason from readable output. Shared result text now includes each recorded
partial engine reason, so shell and plain consumers can read it.

Final J180 is at
`/tmp/kuzushi-dependency-hygiene-audit-20261010/reading-tui/20261010-181437/J180`.
It records 16 machine passes, zero failures and 20 authenticated live text/ANSI
captures. Native SHA-256 is
`80b4d43de7c9de796639017152c81fb1e252c590d3ab304e5f6aa3da7fe97dda`.
Reading spans 160x48, 120x36, 96x89, 80x24, 60x20 and 40x12. Compact paging
reaches inspection counts, reservations, limits and the invalid sibling. Review
shows actual nested/root source excerpts and signal-only assertions. Report
shows two reviewed findings, zero confirmations, selected partial inspection,
workspace-history qualification and unavailable spend. No-color restart retains
four observations and two scripted deferrals without another scan or request.

Three scoped assistant screen judgments are separate from raw REVIEW_REQUIRED
and operator approval false. Startup history and long paths still require
multiple compact pages; loading-state polish and full reference-product comfort
remain open. The fixture is unversioned and does not qualify a SHA transition.
Workspace-history JSON preserves findings and decisions without per-run coverage
receipts; the selected partial receipt remains readable in Report and saved run
results. Optional allowance tables remain absent, rather than fabricated zeros.
Scripted deferrals are fixture decisions, not operator acceptance of the UI.

The third run retained the newly visible reason, but its assertion expected
`invalid JSON document` on one row when wrapping split the phrase. The final
assertion uses the stable engine label and manifest path. The screen also exposed
stopped-chain copy calling a partial result failed. Chain and planning notices
now describe stopping/pausing and direct the operator to the actual outcome.
No live journey or fixture was edited during its process. All failed runs and
original process outputs are retained.

## Verification and limits

Six actual prepared-dispatch contracts, 54 dependency-engine checks, 86 SAST
contracts and one shell partial-result regression pass, 147 distinct checks.
The shared SAST contract now requires the malformed-file reason in `output`,
instead of accepting its presence anywhere in JSON. A valid accepted scope
contract verifies exact-file refusal before discovery. Workspace build and all
ten repository summary gates pass. The risk proxy passes 23 changed code files,
including the previously staged source-reading and graph changes. The first
summary stopped at an assessment wording rule; its failing receipt and focused
diagnostic remain preserved. The corrected description passes the focused gate
and the final summary. The unsigned precommit receipt truthfully records a dirty
tree and is not a publishable clean-commit receipt.

Heuristic precision across every ecosystem, dynamic manifest constructs,
permissions and concurrent filesystem races, inner parser/read cancellation
latency, large repositories and every CLI setting remain unqualified. This
increment adds no automatic jobs, repetitions, model fallback or retirement.
Human screen acceptance, reference-product comfort and all nine broad delivery
milestones remain open. Work remains on main without a new commit or push.
