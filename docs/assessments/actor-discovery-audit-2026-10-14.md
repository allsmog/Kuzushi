# Actor-guided discovery keeps the operator's query limits

`offense-review:threat-hunt` makes discovery queries around actors and threats
in a selected threat model. It previously forced high reasoning even when the
runtime selected medium. A truncated response could retry with twice the
requested output tokens, a 16,000-token floor and a 65,535-token ceiling. Those
changes were internal and not declared in the tool's options.

The query now inherits selected reasoning unless the operator supplies the
declared thinkingLevel option. thinking_level, reasoningEffort and effort are
compatibility aliases. maxOutputTokens requests 256 to 32,768 tokens per query,
defaulting to 4,096; max_output_tokens and maxTokens remain aliases.
maxModelTurns allows one to 16 turns, defaulting to four, with max_model_turns
as an alias. The single truncation retry clones the same model, reasoning,
token and turn limits. The existing single structured repair also keeps those
settings. Every potentially billable request remains subject to the shared
allowance. Requested output tokens are not a strict dollar ceiling or proof
that every provider enforces the same token limit.

The native OAuth interception confirms that the selected medium reasoning
reaches the request, but its body does not include max_output_tokens. The adapter
therefore does not establish a strict output-token ceiling here. The option is
labeled requested, and approved provider-call limits remain the spending
boundary. A strict dollar cap is unavailable. The receipt summary now leads
with partial coverage and independent review; the previous absolute target path
pushed that qualification below the first visible screen.

Declared maxActors is one to eight and runsPerActor one to three; their defaults
remain five and one. maxFindings is one to 500. Direct capability parsing now
rejects invalid or out-of-range values rather than quietly clamping them or
substituting defaults. The canonical module boundary validates the same ranges.
Actor enumeration and source inventory still need operation-wide qualification.

The canonical action is now Labs and **Discover actor-guided observations**.
The retained `carlini-threat-hunt:run` alias shares the options and executor.
Both remain auxiliary Scan work and cannot own a Scan checkpoint. Valid results
are partial, with additive coverage.complete=false, promptSourceFiles and
observationsVerified=false fields. Existing findings, actor counts, knowledge
context, source and cost fields remain readable. An empty response does not
resolve earlier findings. The DAG dependency on threat-model construction is
metadata for headless execution, which requires existing context. The shell
separately presents an explicit prerequisite plan and consumes approved steps;
registration alone is not credited as that execution ordering.

Cancellation is checked before work and before publication after the actor
queries. It does not qualify interruption inside inventory preparation or
per-node append work. Completed actor responses have staged checkpoints, but
whole-tool failure can still prevent final ledger publication. Paid partial
retention, whole-operation bounds and finding/source-generation isolation remain
open. A fresh repetition must use a distinct work identity; resuming the same
work can reuse authenticated checkpoints and must remain distinguishable.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | Context-guided source observations beyond general discovery. Useful detection and precision remain unqualified. |
| Phase | Scan authorization retained without checkpoint ownership. Compatibility alias uses the same executor. |
| Inputs | Target, existing or bound threat-model context, selected model, finite actor/repetition settings and approved allowance. Accepted exact-file discovery scope is unsupported. |
| Execution | Prepared dispatch and owned structured responses exercise real model request construction, normalization, persistence and source receipts. |
| Outputs | Nonempty owned fixture findings reach the ledger with typed deltas; repeated work and an empty fresh response preserve honest deltas. New valid receipts stay partial. |
| Failure | Malformed output, repair/retry cost, rejected locations, missing context, invalid limits, protected capacity and cancellation have focused checks. Failed multi-actor publication remains open. |
| Resources | Selected reasoning is preserved; retries keep the same caps. Shared reservations protect Review. Per-query provider enforcement and total IO/memory bounds remain unqualified. |
| Scope | Bounded source snippets and actor context inform discovery; no complete-repository claim, immutable scanContextRef or calibrated coverage evidence. |
| Interfaces | Exact tools and legacy report fields remain. Declared settings flow through shared preparation rather than per-mode parsing. Full configuration and interface coverage remain open. |
| Product value | Hidden reasoning/token expansion is removed and experimental defaults are honest. Real-model usefulness and final UX parity remain unproven. |

Fifty distinct focused Rust checks and the locked workspace build pass. The
184-tool dispatch-policy fingerprint is unchanged. The full Rust suite was not run.

Initial checks found older registry fixtures without allowance approval. They
now reserve and settle through the real binding. Reusing one work identity for
separate test repetitions reused staged results; the fixtures now give each
fresh request its own identity. The CRAP check found an overlong input builder;
extracting prompt-context validation resolves it. Retained failures and focused
verification are recorded under
`/tmp/kuzushi-tui-integration-20261012/actor-discovery-audit`.

Final J244 records 14 machine passes, zero failures and 14 authenticated capture
pairs across six sizes and no-color restart. It explicitly approves deterministic
context preparation, uses the selected immutable actor-context revision and
retains the active context and human decision. One fully intercepted GPT-5.5
medium request commits one Discovery call; one protected Review call remains.
The result stays partial and creates no phase continuation. Four human questions
remain pending, operatorApproved is false and raw status is REVIEW_REQUIRED.
The source, receipt digest and decision counts remain unchanged after restart.
Product SHA-256:
`2303772ff1f7c6953fd33c48bbd4a6e225fb2d04951b359bbdd315e264721edc`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/actor-discovery-readable-tui/20261014-002854/J244`.

Sequential J121 on the same immutable build records 109 machine passes, zero
failures and 87 authenticated capture pairs. Its four responses are fully
intercepted, with zero live requests or source execution. Finite plans, protected
Review, partial reports, source reassessment and restart retain their receipts.
Fifteen human questions remain pending and operatorApproved is false. Captures:
`/tmp/kuzushi-tui-integration-20261012/actor-discovery-complete-tui/20261014-003113/J121`.

The ten checked-in quick gates pass, including 391 Node checks and the CRAP-risk
proxy over 589 changed code files. These checks cover the accumulated worktree;
they do not replace the pending human review or establish useful real detection.

Retained native failures include an invalid context link, an unhandled
prerequisite plan and a coverage warning below the visible receipt. The corrected
fixture links its source question and approves deterministic preparation; the
product summary now makes the coverage limitation visible. None of those earlier
attempts is credited as a passing journey. JSON/plain CLI checks reject missing
model, unsupported scope, excessive actor/repetition counts and invalid token
settings before execution.

The registry retains 113 visible actions: 87 Core, 21 Labs and five Compatibility.
Ten in-scope actions remain unassigned. Useful model output, exact source scopes,
provider token enforcement, paid partial publication and human UX review remain
open. No broad milestone closes.

No exploit, reproducer, patch generation or target execution is performed in
this increment. The live allowance remains exhausted at six of six. Provider
validation uses fully intercepted owned examples; useful real detection and
the broader investigation acceptance remain open. No module is deleted and no
broad milestone closes.
