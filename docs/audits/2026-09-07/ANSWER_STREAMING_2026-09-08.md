# Incremental Ask responses

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted hardening.

OpenAI OAuth Ask now displays public response text while the model is answering.
The ordinary executable completed two real GPT-5.5 turns using the existing
OAuth credential and saved medium reasoning setting. In the same-session
follow-up, the word **Evidence** was visible at **2.907 seconds**, while the pane
still said **IN PROGRESS**; completion arrived at **4.508 seconds**. These are
terminal-observation timings from this machine, not a latency benchmark.

[Visible partial response](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-streaming/15-real-visible-partial.txt),
[completed follow-up](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-streaming/16-real-followup-terminal.txt),
[timing receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-streaming/real-followup-timing.json).

## What changed

The previous OAuth transport requested streaming but waited for `response.text()`;
the bridge and TUI then exchanged only a final answer or failure. The new
provider test initially failed because no text callback occurred before EOF.

An ephemeral observer on the existing LangGraph runtime now enables optional
`text-v1` response frames. Public text reaches the current job as a nonterminal
event. Queue backpressure preserves each fragment, and existing generation
checks reject stale events. The text is not written as a lifecycle event or
completed assistant turn. Model, provider and runtime selection remain explicit.

The OpenAI OAuth path decodes UTF-8 and SSE incrementally, rejects malformed or
incomplete termination, and preserves tool names, arguments and usage. API-backed
LangChain models aggregate their message chunks while publishing only text blocks.
Reasoning blocks are excluded from both the preview and displayed final text.
Anthropic OAuth still uses its existing buffered response path.

The process reader retains the existing bounded capture and cancellation
supervision. A terminal result is mandatory for framed output; truncated frames,
text before start and events after the result fail. Existing custom bridges that
return one JSON document still work without invented progress. Both new JavaScript
runtime modules are included in the package; their regression tests run in `pnpm test`.

Answers follows the response until the operator scrolls. A new model invocation
resets its preview, and only a successful final answer replaces it. Failure or
cancellation retains an **INCOMPLETE** preview. That text remains readable in
local conversation history but is excluded from completed output sent to a later
model call. Progress does not clear operator questions, finish the job, move
focus or overwrite a reply draft.

[Provider decoding](~/vibe-code/Kuzushi/scripts/langgraph-bridge/oauth-response-stream.mjs),
[bridge framing](~/vibe-code/Kuzushi/crates/kuzushi-openai/src/langgraph_runtime/response_frames.rs),
[Ask event handling](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/agent_session/ask_agent/agent_events.rs),
[answer projection](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/answers/document.rs).

## Sequential terminal checks

Two local bridge runs used the existing accepted Map over six real Rust source
files. The fixture explicitly identified its output as a local streaming check
and made no network requests. The first run showed incremental text at 120×36
and 40×12, preserved manual scroll and an unsent Unicode reply across workspace
focus and resize, then replaced the preview with its final result. The second
run was canceled after its first fragment; the shell stayed usable and displayed
that fragment as incomplete. All three owned terminal sessions exited with status 0.

[Compact streaming](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-streaming/02-local-40x12.txt),
[retained reply](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-streaming/06b-local-resumed-draft.txt),
[canceled partial response](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-streaming/10-local-cancelled.txt).

The first real OAuth turn completed in 5.200 seconds. Its earliest recorded
fragment at 3.342 seconds was Markdown syntax, so that capture proves progress
state, not visible answer words. The subsequent plain-text follow-up supplies
the direct visible-word timing cited above. Both run receipts say completed and
retain unresolved provider spend; zero observed cost is not a price measurement.
Six source files, seven protected model files and the saved configuration have
identical before/after hashes. Four new Ask runs account for the two local and
two real requests. No Scan was launched.

[Run receipts](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-streaming/run-receipts.json),
[target/config integrity](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-streaming/live-final.json).

## Validation and remaining comparison

Focused checks pass: 51 Rust bridge/runtime tests, 48 Answer tests, eight job-hub
tests and one incomplete-history test. The 138 JavaScript bridge tests include
UTF-8 fragmentation, incomplete termination, tool argument/usage preservation,
reasoning exclusion, retries, query/next-step framing and legacy compatibility.
These groups overlap and are not a full TUI-suite rerun. Process tests prove that
a text callback can unblock a child before its final output, and that cancellation
stops a child after partial text. The queue test crosses its 4,096-event capacity
without losing or reordering fragments.

The normal CRAP-risk gate passes. The repository quick gate and exact final
source hashes are recorded in the [revalidation receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/answer-streaming/REVALIDATION.json).
Initial checks caught omitted package files and unsorted test imports; both were
corrected. Verification is on a dirty working tree and does not certify a release.

OpenCode already renders streaming Markdown through its [session TextPart](~/clone-references/opencode/packages/tui/src/routes/session/index.tsx:1686).
The buffered OpenAI OAuth Ask gap is now closed in Kuzushi's tested path.
OpenCode still has stronger syntax styling and provider/session controls. Live
API-key and Anthropic OAuth streaming, real-provider cancellation, fresh OAuth
login/expiry, conversation resumption after restart, large-response performance
and full Scan/Review/Prove/Fix/Report acceptance remain open. The auxiliary
read-only Ask uses the same observer and has protocol coverage; a live concurrent
scan/Ask check remains open. No native screenshot, independent review, commit,
push or release publication is claimed. The [broad interaction checklist](INTERACTION_HARDENING.md)
stays open.
