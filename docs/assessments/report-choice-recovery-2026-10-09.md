# Report choice recovery, October 9, 2026

The main investigation's Report surface previously lost its chosen format and
destinations on restart. This increment saves presentation choices in an
operator-owned, target-keyed namespace and restores them without restoring
approval, investigation selection or an export receipt.

The schema-1 document contains the canonical target, selected format,
completeness, six canonical format/destination pairs and the provenance-detail
preference. It has no model, credential, budget, scope approval or study fields.
CLI export defaults and prepared tool options remain unchanged. Target-local
copies cannot steer the reader. The target directory key deliberately survives
SHA changes without carrying finding decisions or source-applicability claims.

Core IO uses the existing bounded, symlink-checked workspace-state helpers.
Reads/writes are limited to 32 KiB and each destination to 4096 bytes without
control characters. Missing files retain session defaults; malformed, oversized,
foreign and unsupported-version files produce visible errors. Validation occurs
before route mutation or installation. Per-format destinations stay independent.

`S` saves current choices without exporting. Explicit export also saves valid
choices for the current target. It checks the existing saved file first and
leaves damaged bytes unchanged; the user can explicitly replace them through
`S`. Preference failure remains separate from the actual export outcome.
Opening Report restores once for that target and keeps an existing session's
choices/draft intact. Restoring choices does not enable workspace-history export,
select a prior study, start work or switch a model.

Native testing exposed Shift-encoded `S` falling into the composer. The modal
handler now accepts ordinary and Shift encodings. An active path editor still
owns typed `S`, while Enter/Ctrl+S saves its field. The wider Report suite also
exposed a stale worker test which called the input-aware recommender permanently
runtime-free. It now distinguishes potential runtime support from the default
free input and explicit model-ranking input. No execution policy changed there.

Evidence root: /tmp/kuzushi-report-recovery-20261009.
Final J153: /tmp/kuzushi-report-recovery-20261009/final-tui/20261009-200037/J153.
Native SHA-256:
5357f5f479699ae5ef3697624ab3972d11bfeb4214a16374802ed4a121faaf75.

The final journey has 26 machine passes, zero failures and 20 populated
authenticated text/ANSI pairs. All native hashes, dimensions and ANSI-stripped
text agree. Six viewport sizes, two no-color restarts, actual 40x12 paging to
the save controls, local explicit export and explicit damaged-file repair are
covered. Four scoped assistant judgments stay separate from raw REVIEW_REQUIRED
and operator approval false. These are terminal-state/layout checks, not a
physical contrast, latency or full reference-product parity claim.

The fixture is comment-only owned source with an isolated credential-free home.
Saving/restoring creates no export. Only explicit Enter creates an empty native
`kuzushi.workspace.findings.v2` envelope with count zero. Malformed preference
bytes remain identical through that export, and explicit `S` repairs them.
Source/configuration hashes remain unchanged. There are no finding observations,
decisions, work attempts, campaign approvals, provider requests, scanners or
target execution. No synthetic findings or completed scans are inserted.

There are 203 distinct focused tests: five Core store checks, five TUI preference
checks, 167 Report regressions and 32 keybinding checks, with overlap removed.
They cover Unicode destinations, target isolation, ignored target-authored
preferences, malformed/oversized files, symlinks, failed saves retaining valid
bytes, explicit repair and editor input ownership. Workspace build and the
CRAP-risk proxy for 568 changed code files pass. All ten repository summary steps pass. The receipt records dirty source and
`driftedDuringRun: true`; the flag includes initial dirty state and does not
prove a concurrent edit. Final documentation checks follow this update.

Retained failures include an omitted exhaustive effect-test case, Shift+S
escaping the reader, a stale recommender-runtime assertion, a wrapped text
assertion and an incorrect empty-export array assumption. The stronger native
fixture checks the actual export envelope and actual narrow save controls.

This closes the Report-format/destination restart gap recorded in the owned
J121 investigation. It does not qualify live-provider usefulness or the complete
investigation. Multi-session preference conflict handling, total IO latency,
platform behavior, full input/selection continuity and full TUI acceptance remain
open. Visible module qualification stays 55 of 109 with 54 unassigned; all nine
broad delivery milestones remain open. Work stays uncommitted on main, with no
product commit/push, OAuth renewal or inference.
