# Catalog import functionality and recovery

This audit covers `taint-iris-next:import-sinks` as a runtime-free metadata
importer through prepared dispatch, native CLI and the shell. Its distinct role
is importing recorded catalog signals while preserving existing metadata.
It remains Core; detection engines, source tracing and model judgment receive
no qualification from this audit.

Nine new dispatch tests failed before the repairs. A successful write returned
the nested status `imported` without a canonical run status, so normalization
reported failure. Unreadable saved catalogs were treated as absent and could
be replaced during default merge. Input paths lost trailing spaces, reads
followed leaf symlinks, cancellation was unchecked, and imports could own a
Scan phase result. Skipped rows did not produce a canonical partial outcome.

The importer now returns completed or partial status at the shared boundary,
requires its declared input file, preserves literal filenames and reads at most
64 MiB from a regular file. Parsing admits at most 100,000 nonempty lines and
checks cancellation between lines. Default merge refuses unreadable, malformed
or oversized saved metadata. Explicit `merge=false` remains the recovery choice.
Publication rejects serialized catalogs above the existing 8 MiB reader limit
before replacing the prior file. Existing contained atomic publication is reused.

Skipped unusable rows remain importable as partial work. Their count and warning
appear in both the envelope and displayed result body. The import does not create
findings, accept context or complete Scan. Its declared Scan phase and public
aliases remain for compatibility; `phase_result=false` makes its auxiliary role
explicit. The historical clean nested status and catalog payload remain intact.

## Verification

Sixty distinct focused Rust tests pass across prepared imports, catalog readers
and publication, cancellation, unchanged policy tuples and TUI phase ownership.
The locked workspace build passes. The CRAP-risk proxy passes over 504 changed
code files. The full Rust suite was not run for this increment.

All ten exact quick-plan commands pass, including 391 Node tests, workspace
checking, architecture/model-safety contracts and the changed-code risk proxy.
Package commands ran directly without disabling the known pinned package-manager
signature verification. New Rust test files and the modified import blocks were
formatted locally; unrelated legacy formatting differences remain untouched.

Native CLI checks return completed with exit 0, partial with exit 4 and failed
with exit 3, including a public input alias and a literal trailing-space path.
Plain output has no ANSI. Source bytes remain unchanged.

Final sequential J233 records 12 machine passes, zero failures and 14 live
text/ANSI capture pairs at six sizes and no-color restart. It preserves the
malformed catalog before explicit replacement, then reads one imported row and
two skipped rows as partial work. Both result receipts survive restart unchanged.
The owned source remains unchanged. There are no model events, provider calls,
finding observations, review decisions, investigation attempts or phase attempts.
Absent accounting tables are recorded as absent rather than measured zeros.

The raw result remains `REVIEW_REQUIRED`, with four human judgments pending and
operator approval false. The refusal names preservation and explicit replacement.
The partial body explains the skipped input and metadata-only boundary. At 40x12,
a retained notice initially crowds the receipt body. Dismissing it with the
advertised Esc control and paging reaches the warning; eight further Page Down
presses were observed. This accessibility check does not establish a delightful
default narrow layout. Compact notice allocation remains a concrete TUI gap.

Retained evidence includes all nine initial failing tests, an intermediate
fixture mismatch between macOS canonical and alias temporary paths, an initial
fixture assumption that lazy accounting tables existed, and the missing displayed
warning found by native testing. The stream check uses the authenticated item
type discriminator. Fixtures changed only after their journey processes ended.

Native SHA-256:
`3e632bae92baa1fd66f53a687b465f018ccdc3c8865cdfa88c345d24cfa8bdae`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/sink-import-reviewed-tui/20261013-074910/J233`.
Tests, CLI results, retained failures and assistant screen review:
`/tmp/kuzushi-tui-integration-20261012/sink-import-audit`.

## Remaining qualification

Classification usefulness, signal clipping, all language options, aggregate merge
complexity, cancellation during publication and broader platform behavior remain
open. The target catalog is mutable metadata, so this is not evidence of immutable
scan-context consumption. Scanner execution, live-model quality, Git SHA verdicts
and complete reference UX acceptance remain outside this fixture. No module is
promoted, retired or deleted. Twenty-one in-scope operator tools remain without
assigned functional verdicts. The live allowance stays exhausted at six of six.
