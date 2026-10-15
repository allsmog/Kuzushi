# Selectable options and inline editing

The options surface now keeps the selected setting and its effective value
visible at 40x12. Wide terminals pair a selectable list with full detail;
narrow terminals show the selected detail with bounded paging. Experimental
support appears before the tool name, so a long identifier cannot hide it.
Standard, Advanced and Missing filters use the existing descriptor model.
Structured workflow inputs remain visible and read-only. Their owning plan or
context picker supplies them.

Enter opens a separate Unicode field editor. Session save and explicit global
save reuse shared descriptor coercion, option precedence and persistence effects.
Literal text keeps quotes, whitespace and newlines. Invalid values preserve the
field and previous stored value. Typing, tabs, newlines and paste share a 64 KiB
bound. Long validation errors are page-readable. Escape retains field text and
cursor across navigation and tool switching. Resize and editing preserve the
main composer. Quit discloses retained option drafts without revealing content;
staying returns to the same field. Drafts remain process-local.

Global persistence acknowledges the actual write result. A failed write names
the in-memory change and offers a retry. Successful global saves disclose any
higher-priority session or workspace override. Neither saving defaults nor
inspecting options changes an approved plan's frozen input, authorizes work or
dispatches a job. Existing command syntax and store formats remain compatible.

Seventy-seven distinct focused options tests pass, including six-viewport
rendering, immutable composer state, literal multiline values, field bounds,
workflow reference refusal, exit/stay recovery, effective-value precedence,
failed persistence and bounded detail/error paging. The locked workspace build
passes. Final sequential J218 records 45 machine passes, zero failures and 28
live text/ANSI/provenance capture sets at six sizes, with no-color restart:
`/tmp/kuzushi-options-browser-20261011/complete-tui/20261011-212956/J218`.
Its frozen executable is
`/tmp/kuzushi-options-browser-20261011/complete-native/kuzushi`, SHA-256
`b4a1394c806ac1d7ee966ed3efd51cd20f449f6e4d6dc8eddc9f856aa8ec7c2a`.
All owned fixture source-file hashes match and no jobs are dispatched. Temporary
fixture captures leave target Git/source fields unavailable; the fixture's
complete source hashes provide the separate source-integrity check. The four
human judgments remain raw `REVIEW_REQUIRED`; assistant capture inspection is
recorded separately and does not set operator approval. Final repository checks
are saved at `/tmp/kuzushi-options-browser-20261011/completion-verification.json`.
Dirty or drifted receipts remain unsigned.

The first J218 attempt is retained at
`/tmp/kuzushi-options-browser-20261011/native-tui/20261011-212027/J218`.
It correctly persisted global 9 while session 7 retained precedence, but its
assertion incorrectly expected effective 9. The capture also exposed an
incomplete global-save explanation. The implementation now names the override;
the journey separately verifies persistent and effective values and explicitly
clears the session override before using global 9. The failed receipt is not
rewritten.

The second attempt retains 44 passing checks and no machine failures at
`/tmp/kuzushi-options-browser-20261011/verified-tui/20261011-212501/J218`.
Assistant inspection found that clearing the session override left its old
notice visible. Shared set/unset storage now clears stale notices. The final
journey explicitly asserts that the override notice is gone, and its fixture
authenticates all source files rather than just the two seeded metadata files.

This increment addresses the small-terminal defect recorded by the architecture
audit. It does not qualify full reference UX parity, complete the module audit
or close a broad delivery milestone. Live model validation adds zero requests;
the earlier bounded Review remains exhausted at six of six. Exploit development,
reproducer work and vulnerability patching remain outside this workflow.
