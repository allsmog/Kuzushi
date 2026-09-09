# Unresolved Review and Setup disclosure — September 8, 2026

The real GPT-5.5 OAuth canary run exposed a classification defect: Review acknowledged unsafe local code, then rejected all four candidates because it could not establish a caller or runtime entry point. The deep-auditor contract required a Boolean answer, and any `false` assessment with confidence at least 0.5 became a false positive.

The repaired analysis accepts `triggerable: null` for unresolved reachability or impact. An `implausible_trigger` refutation with no inspected `first_link` also remains `needs_review`, with an explanatory annotation and the original rationale. Supported positive assessments and guard refutations keep the same thresholds. Historical decisions are preserved; no existing verdict was rewritten behind the operator's back.

A real explicit rerun on the same source produced four `needs_review`, zero true positives, zero false positives and zero failed reviews. The original four rejection decisions remain in history. Accepting the completed Review and restarting keeps Review required for the four unresolved candidates. Completion of a tool run does not forge completion of the investigation.

Setup now displays the actual public model selector and credential type in its ready rows. Live 120×36, 80×24 and 40×12 checks show `openai-oauth:gpt-5.5` and `OAuth ready` both while Plan owns focus and beside selected Start Map. Those checks launched no model work.

## Scope and receipts

This is a labeled workflow test over the repository's planted C canary, not a blind scanner-accuracy evaluation or a claim of production vulnerabilities. Its comments and expected-finding manifest are available to the model; the manifest was never imported as findings. The five tracked source files are unchanged in a separate clean local clone at Kuzushi `586a6fda6d336dd4373b17bfa84c72c21ec68daa`, scoped to `tests/fixtures/canary-target`. A fresh copy of those five files was used only for Setup checks. The earlier descriptor target, its accepted engagement, exports and Ask evidence remain unchanged.

Evidence root: [~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/canary-workflow](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/canary-workflow).

| Stage | Real receipt | Outcome |
|---|---|---|
| Map | `88e5a8b6-b479-465e-8d56-83be20f80cf3` | Model-backed Map completed and explicitly selected; four run references include deterministic work and recommendation refresh. |
| Scan | `185c4f7a-abaf-461b-bf97-fbdc0bb5cb68` | Agentic SAST and threat-model hunt completed; four candidates; explicitly selected. |
| Review before repair | `tool-1788913099299-033785943422` | Four unsupported false-positive decisions; original attempt `74db64a2-0588-4fdd-af89-64dc7b74d24e` remains unselected. |
| Explicit retriage | `tool-1788913803124-6212ea589632` | Four needs-review decisions in 83 seconds by run timestamps; UI plan receipt reports 82 seconds. |
| Review selection | `857aa463-4354-4990-aa25-e1e1f0317280` | Selected after inspection; restart remains at Review with four unresolved candidates. |

Both Review results bind snapshot `59e8cf9341eb20d6cdf8e14c35839a1b559085abd2ddc648af550ba17899bbbd` and source tree `4b349818cd341d08ac2fc19b8a055430c35a35414c2657da977ac03887480433`. All model-backed runs used the `openai-oauth:gpt-5.5` selection; the saved operator configuration remains medium reasoning. Provider spend is unresolved; an observed zero is not a zero-cost claim.

The original two-engine Scan recipe incorrectly assumed the planner's initial cursor/selection. It added Systems/MSan to the intended engines and launched four planned tasks. The first Agentic SAST call was canceled after 24 seconds; the other three did not run. The failed journey is retained. A stopped inspection established the actual defaults before the successful two-engine retry.

All 30 explicit review questions have recorded judgments across 12 sequential J54 runs: 25 pass, four fail and one not exercised. Three historical failures are superseded by observed repairs or the corrected script; the Prove backend-disclosure failure remains open. The 71 captures retain ANSI and live/shell provenance. One historical machine assertion failed; successful later checks do not erase it. See [REVIEW_JUDGMENTS.json](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/canary-workflow/REVIEW_JUDGMENTS.json).

## Changes and verification

Production changes are confined to Setup's readiness projection and the deep-auditor analysis, parsing, classification and synthesis instructions. The nullable raw analysis keeps existing Boolean JSON readable. Rust callers constructing `VulnAnalysis` now use `Option<bool>`; the migration is documented in `RELEASING.md` and `docs/modules.md`. Persisted `TriageVerdict` formats and module names are unchanged. No provider, runtime or model substitution was added.

- 69 focused Setup tests, 43 deep-auditor tests and 59 triage tests pass. The six new regressions cover unresolved assessments, the observed no-caller refutation, supported guard/path refutations, legacy Boolean responses and low-confidence outcomes.
- Normal `pnpm quality:crap-risk` passes for 260 cumulative changed code files. The count includes earlier work in this dirty checkout.
- `pnpm verify:quick:summary` passes all ten steps, finishing `2026-09-09T00:31:50.865Z`. Its receipt is dirty and drifted during the run; it is local verification, not release certification or a full Rust-suite/coverage/cross-platform result.
- Final native SHA-256: `5b0dafb0d3c9cba463c83498e43c4673c0603835e5cceb72cd23d9414e7efddd`. The native build reports seven existing TUI warnings.
- The earlier target's 401 captured files, the canary's five source files, existing run results and operator configuration are preserved. The canary database passes `quick_check` and retains eight decision rows: four earlier rejections and four new needs-review decisions.

The work is uncommitted. Director self-review is recorded with the evidence; no independent or post-commit review is claimed.

## Remaining observed work

Opening Prove at 80 columns preserves F-0001, `decision:needs_review`, its source location and the reality-derived requirement to finish Review. Its investigation card distinguishes static analysis from local reproduction, but local reproduction still says “sandboxed PoC execution here” without checking backend availability. On this Mac, neither bubblewrap nor Podman is available on PATH, and the verifier currently permits execution only through bubblewrap. The card also shows a model ladder for the deterministic empirical branch. Capture `20260908-173312/J54/08-prove-local-plan.txt` records this unresolved failure. No Prove or Fix tool was dispatched, and no empirical proof or patch was manufactured.

The next pass needs to make that preflight truthful and audit the shared empirical dispatch and acceptance contracts. Source inspection shows `verify:finding` with `mode=empirical` delegates directly to the exploit executor, while its descriptor still declares an always-required model and the selected-proof reader classifies `verify:finding` as a model result. These paths need focused execution/policy/receipt tests before a repair can be accepted; the present pass does not claim they work.

The canary's missing integration callers also prevent it from proving a complete reachable-vulnerability → execution → patch journey. A supported execution environment and source-grounded entry path are still needed for that acceptance. All ten broad interaction-hardening requirements remain open, including full Prove/Fix, remaining input/focus behavior, fresh/expired auth, aggregate cost and broader resumption.

Cyber-program model access is separate from these product defects. The host model list includes Daybreak, but access through Kuzushi's OAuth transport has not been verified, and the operator has not selected a replacement for GPT-5.5. The saved model remains unchanged.
