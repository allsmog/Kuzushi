# OAuth preflight and context failure recovery

October 5, 2026. These fixes were found while preparing an isolated live-model
test. The requested live inference remains pending the operator's exact
allowance choice. This increment uses offline transport fixtures only.

## Changes

The bridge previously constructed an OAuth client with an expired token after
refresh failed. It now validates the stored expiry after refresh and reports a
typed authentication failure before client construction. Missing, malformed and
non-finite expiry values fail too. The credential file is preserved, and a
subscription model never substitutes an API-key client. Current access-only
credentials retain the selected model and reasoning effort.

Context planning previously displayed an output-token limit that the OpenAI
subscription OAuth adapter cannot enforce. It now says requested output and
distinguishes adapter enforcement from the approved provider-request allowance.
The option retains its existing name, aliases and default. Strict output-token
and dollar ceilings remain unavailable on this OAuth path.

The context result previously reported reason unavailable even when its failed
run recorded provider authentication failure. Campaign snapshots now use a
matching terminal run's error when the dispatcher supplied no reason. Explicit
dispatcher reasons retain priority. The existing safe diagnostic projection
redacts secrets, escapes controls and caps length. Reads neither repair nor
rewrite metadata. Unrelated tools, live runs and invalid references cannot
supply this fallback. Finding counts also use the bounded artifact reader,
rejecting paths that escape the run store.

## Verification

- Four focused OAuth readiness tests pass. The full adapter suite passes
  167 tests, including real bridge entrypoints with intercepted transport.
  Three preexisting test fixtures now include the valid expiry already required
  by the Rust credential contract. No readiness check was weakened.
- Five focused campaign projection tests pass, covering correlation, safe
  bounded text, reason precedence, unchanged metadata and escaped count reads.
  The existing campaign finding-count regression and context recovery test pass.
- Thirteen TUI context-workflow tests pass. Workspace build passes. The
  CRAP-risk proxy passes 243 changed code files.
- J86 at `/tmp/kuzushi-bounded-investigations-tui/20261005-191951/J86/` passes
  23 machine checks and five separate screen judgments. It captures all six
  terminal sizes, pages to the full result tail at 40x12, confirms an initial
  exit with unsaved planning choices and restores the failure after an actual
  no-color restart. The final idle exit is immediate.
- The fixture proves one failed work attempt, one mocked token refresh, zero
  provider reservations and zero live network or inference requests. The
  context job does not produce or accept a Map. Both unused context/scan calls
  and protected review remain visible.
- Text, ANSI, dimensions, native binary hashes and the bridge source hash are
  in `manual-review.json`. Native SHA-256 is
  `0a92a03ce44d89b092fba3393b760bff4811b42d28494de17ff523c2ae3c822d`.
  Raw `REVIEW_REQUIRED` and all five failed predecessors remain unchanged.
- Ten-gate quick verification passes in
  `.git/bounded-investigations/oauth-context-final-verification.json`, finished
  `2026-10-06T02:19:32.832Z`. Dirty source and conservative drift are explicit.
  Full CI, cross-platform checks and live provider validation remain open.
  This receipt precedes the final documentation closeout.

## Live test and remaining work

The prepared test uses GPT-6 Luna with low reasoning, the normal LangGraph
bridge and a private access-only copy of the current same-account OpenAI OAuth
login. Normal credential stores and model settings are unchanged. It has a
frozen source-only context job and a proposed three-pass discovery plan using
the existing read-only static-analysis profile. No live work is approved or
started. Its brief is `/tmp/kuzushi-live-model-ua7rhauw/test-brief.json`.

The pending choices are eight provider requests, including two protected for
review, or two requests for a context smoke test. Internal turns and potentially
billable retries consume the same cap. Expired test credentials must be
revalidated before launch. The normal adapter still cannot enforce an output
ceiling or provide a strict dollar estimate.

The generic recovery heading and long identifiers still occupy too much reading
space. The complete module audit, live scan quality, scope-aware model sessions,
monorepo scheduling, context experiments and reviewed lessons remain unfinished.
These local fixes do not complete reference interaction parity or the accepted
end-to-end investigation plan.
