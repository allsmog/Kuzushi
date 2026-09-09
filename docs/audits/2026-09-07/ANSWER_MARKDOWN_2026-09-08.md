# Reading model answers

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted hardening.

Answers now render Markdown with visible heading and emphasis styles, numbered
and nested lists, task markers, quotes, code blocks, links and tables. Raw
conversation text remains unchanged. Code indentation and blank lines are kept;
`↪` identifies a wrapped continuation, and tabs display as four spaces. Link
labels remain beside their destinations. Wide tables use aligned columns;
narrow tables show labeled records so each cell stays associated with its header.

## Evidence and implementation

Two initial renderer/content regressions failed: heading punctuation remained
literal and narrow tables lacked usable header/value relationships. Source
inspection also showed that the old whitespace wrapper flattened code indentation;
the final checks require that indentation to survive. The replacement uses
[pulldown-cmark 0.13.4](https://docs.rs/pulldown-cmark/0.13.4/pulldown_cmark/),
with table, task-list, strikethrough and footnote parsing enabled. It adds that
parser and its unicase dependency to the existing lockfile; Unicode segmentation
uses the already locked version.

A pure renderer builds styled lines, wraps by grapheme/display width, and keeps
code whitespace separate from prose wrapping. The existing answer cache retains
one line projection for a chat generation, width and history selection. Terminal
rendering uses its styles; plain rendering derives text from those same lines.
Questions and runtime errors retain their existing literal presentation.

[Markdown rendering](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/shared/markdown/mod.rs),
[table projection](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/shared/markdown/tables.rs),
[answer document](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/answers.rs).

Links and images are displayed as text without fetching their destinations.
HTML remains inert literal text, terminal control characters are escaped, and
incomplete code fences remain readable. Nesting beyond 64 levels uses a wrapped
literal projection of the complete source instead of recursively rendering it.
This is a presentation fallback; it does not change model or runtime selection.

## Sequential terminal acceptance

The rebuilt ordinary executable used the existing accepted Map over six real
Rust descriptor-crate files. A deliberately selected local bridge returned a
response headed **Local display check**, explicitly identifying itself as a
presentation test. The bridge records only envelope type and selected model and
has no network implementation. These are local response checks, not additional
OpenAI requests or evidence of authentication recovery.

The first pass rendered the response beside the real Map at 160×48. Headings,
list hierarchy, preserved code indentation, a marked long-code continuation and
an aligned table were visible. Page reading reached the complete response at
120×36, 80×24 and 40×12; the narrow table switched to labeled records. Returning
to the workspace and back restored the answer's scroll position.

That pass also exposed excessive chrome at 40×12: only two answer rows remained,
requiring 34 pages for the 67-row response. A new full-layout regression failed
on that geometry. While Answers owns input in a terminal at most 16 rows high,
Kuzushi now suppresses the duplicated generic transcript/keybinding footer. The
status row, captured context, scroll position and a complete short reply/return
hint remain. Workspace focus restores its usual chrome.

[Before the compact-reading correction](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-markdown/05-reading-40x12-33.txt).
Final executable, page ranges, source/config integrity and gate results are in the
[revalidation receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-markdown/REVALIDATION.json).

The final rebuilt pass shows **five** answer rows at 40×12. The same 67-row
response now needs **14 pages**, and the last page exposes its complete final
receipt. The 120×36 and 80×24 checks also reach the end. A held Unicode reply
survives resizing, workspace focus and reopening the editor. The final terminal
exits with status 0 after confirmation; both owned sessions are closed. The six
source files, seven protected model files and saved model configuration are
unchanged. Exactly two local preflight/answer pairs produced two Ask runs.

[Final compact reading](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-markdown/11-final-reading-40x12-13.txt),
[restored Unicode reply](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-markdown/18-final-draft-restored.txt).

Nine parser/rendering unit tests cover formatting, wrapping, Unicode, inert
content and excessive nesting. Four new answer integration checks cover the real
frame, literal questions, plain-output evidence and compact reading geometry.
The final Answer group passes **43 tests**, and the Chrome group **15**; groups
overlap with earlier Markdown checks. Full repository-gate status is recorded in
the linked revalidation receipt.

## Comparison and limits

OpenCode's session TextPart already renders streaming Markdown, syntax styles and
grid tables. Kuzushi now has a structured reading surface for completed Answers.
Code blocks are visually identified and preserve layout; lexical syntax
highlighting remains open. At this checkpoint token streaming remained open: the OpenAI OAuth adapter
buffered `response.text()`, and the TUI received only terminal answer/failure
events. The subsequent [streaming pass](ANSWER_STREAMING_2026-09-08.md) closes
that gap for OpenAI OAuth Ask and verifies a real streamed follow-up.

[OpenCode TextPart](~/clone-references/opencode/packages/tui/src/routes/session/index.tsx:1686),
[Kuzushi OAuth transport](~/vibe-code/Kuzushi/scripts/langgraph-bridge/oauth-models.mjs:78).

Evidence is Ratatui buffers and owned terminal text/ANSI. The local fixture's
zero cost is not a provider measurement. Fresh OAuth login/expiry, live
cancellation, conversation resumption, full phase acceptance and a full TUI-suite
rerun are not established by these checks. No native screenshot, commit, push,
independent review or clean-release certification is claimed. The
[broad interaction checklist](INTERACTION_HARDENING.md) stays open.
