# TUI DevEx Audit Journeys

## J184: Review model identity and source history

The current source-history journey first reads the newly recorded Review in
Replay and checks its selected-model summary. Its owned fixture performs two
prepared dispatches through explicit synthetic allowance accounting. The helper
also checks classification cost on the model stage and retained compatibility
tags. Continue through both source revisions, six-size Review, scripted human
deferral, export and no-color restart. These outcomes are labeled synthetic and
create no live provider request. Human judgments remain separate from assertions.

## J283: Frozen source input for standard Review

Use an owned inert source-reader fixture with one labeled synthetic observation
and an authenticated source receipt. Explicitly select standard Review and cited
source, then prepare one job without granting calls or starting work. Read the
exact supplied text, limits and omissions at six terminal sizes, return to the
plan and recover its immutable input after no-color restart. The helper seeds
only fixture data and verifies zero approvals, attempts and provider requests.
It never dispatches a product tool. Judge source readability, deliberate policy
selection and recovery separately from machine checks and model usefulness.

## J282: Actual application Review, uncertainty and restart

Read the completed, separately approved Review on the retained owned application
fixture. Start no work. Inspect its single consumed job at six terminal sizes,
then the original Scan's three-pass recurrence and automatic needs-review
opinion. Preserve unknown charges, three observations, zero human decisions and
the exact reduced allowance through export and no-color restart. Helpers must
assert unchanged source/context/configuration and exactly four requests before
and after reading. Judge opinion authority and unresolved evidence separately
from request execution. Unused protected capacity is not another approved job.

## J280: Visible Setup recovery through Report

Use an owned two-file public-example fixture and a manual context document.
Choose import, edit its path and start Map through Setup. Observe the workspace
policy refusal, inspect the complete Start Map cause, explicitly repair only
the fixture's ignored policy path, then retry the same selection. Accept Map,
use guided `next`, select three `secret-scan` passes and approve zero model
capacity with one worker. Preserve six observations, record two human FP
decisions, export and recover the exact study after no-color restart. Helpers
must not create plans, jobs or product dispatches. Judge explanation, reading,
approval and recovery separately from machine checks. The initial launch guard
and the driver's session-exit ownership check must remain enforced.

Scripted developer-experience audits for the Rust Ratatui shell
(`crates/kuzushi-tui`), driven live under **tmux** — the only layer that
exercises the TUI the way an operator does (real keystrokes, real timing, real
Target/Setup gates) rather than reading pre-rendered buffers.

This is the **journey catalog**. It is the source of truth for *what* we audit
and *why*. The keystroke scripts, capture cadence, and pass/fail encodings are a
separate concern (a project skill / driver); this doc defines the journeys they
implement.

## How to read a journey

Every journey is judged at each checkpoint against the
**signifier ↔ state ↔ intent** invariant:

1. **State** — what does the operator actually know right now?
2. **Intent** — what does the screen suggest they do next?
3. **Honesty** — is anything on screen lying (a glyph, status, or keybind that
   contradicts reality)?

A journey is a *task completion*, not a screen tour: it has a persona, a real
goal, and it fails if the operator would get stuck, misled, or dead-ended —
even when nothing crashes.

## Driver primitives (tmux 3.6a)

```bash
tmux new-session -d -s <name> -x <cols> -y <rows> \
  'cd /workspace/Kuzushi && <env> ./target/debug/kuzushi <args>'
tmux capture-pane -t <name> -p      # plain text  → content / honesty audit
tmux capture-pane -t <name> -e -p   # with ANSI    → color / style audit
tmux send-keys   -t <name> <keys>   # real keystrokes: Tab Enter Escape C-c j k, literal text
tmux kill-session -t <name>
```

Knobs:
- `KUZUSHI_REDUCED_MOTION=1` — freeze the spinner for stable content captures
  (leave OFF when auditing motion itself, J15).
- Generous `sleep` after each keystroke — background workers are async.
- Unique session names prevent collisions. Run journeys sequentially unless the
  operator explicitly approves parallel execution.
- `-e` capture is mandatory for J15 (palette): it is the only way to see the
  escape sequences and catch truecolor-only rendering.

Run **deep** journeys (J4–J10) before **broad** ones (J13). Prior-audit
findings are cited inline so a re-run knows what it is re-checking; see
`memory/tui-headless-devex-audit-2026-07.md` and
`memory/new-user-journey-audit-2026-07.md` for the source audits.

Those July screen descriptions are historical evidence, not the current UI
contract. The current journey is
`Target → Setup → Map ↔ Run Focus → Scan ↔ Run Focus → Review → Prove → Fix → Report`.

---

## A. Target, Setup & first contact

### J1 — Keyless first launch  ⭐ highest priority
- **Persona:** brand-new user, no credentials.
- **Env:** unset `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / etc.; `HOME` → temp
  dir; no existing `.kuzushi`.
- **Launch:** bare `kuzushi` on a real TTY.
- **Journey:** select Target, then inspect aggregate Setup rows in dependency
  order: Target, Map plan, Model, Credentials, Prompt, Budget, Start Map.
- **Verify:** a deterministic runtime-free Map plan can start without a model;
  model-backed work names the missing compatible model/credential; unset budget
  says `not enforced`; every editor returns to the same plan/cursor/scroll and
  never launches work merely because a prompt was saved.
- **Historical risk:** the July disconnected picker gate and credential dead
  end are superseded. Fail if any Target → Model → Credentials → Planning
  wizard or empty generic Workbench reappears.

### J2 — Offline demo path
- **Persona:** evaluator who won't paste a key yet.
- **Launch:** `kuzushi demo`; plus the in-gate `d` offline route.
- **Goal:** reach a real scanner signal with a redacted location and an honest
  `signal_only` proof state — zero key, zero network.
- **Judge:** does the demo make the value legible, or just print logs?

### J3 — Explicit-target consent
- **Persona:** user sitting in a repo dir, runs bare `kuzushi`.
- **Verify:** target picker *offers* cwd as a row but requires an explicit
  Enter; Esc opts into targetless browsing; nothing silently falls back to cwd
  (PR #64 promise).
- **Judge:** is "you are about to scan THIS directory" unmistakable?

### J49 — Setup target-facts honesty  ⭐ release-blocking (keyless)
- **Journey (keyless, seeded git repo):** launch `--target <repo>` at a git repo
  with one dirty file; Setup discloses the target path, the `dirty` working-tree
  state, the `branch@revision`, and a detected-`languages:` row. The facts are
  filesystem/git-derived, so no model key is needed.
- **Verify:** with a dirty working tree the facts read `dirty`, never `clean`;
  the disclosed path is the operator-designated repo, never cwd-substituted.
- **Judge:** nothing claims "confirmed" beyond the target binding the operator
  explicitly gave, and no language/build guess is dressed up as a verified fact.

### J53 — Ready Map resume keeps durable evidence primary  ⭐ release-blocking (keyless)

Also verifies that Shift+Tab can browse persisted Scan and Review/findings
projections while Map remains the current journey phase; page navigation must
never be mistaken for workflow advancement.

- **Journey:** run the deterministic Map plan on the offline reference target,
  leave its successful result unresolved, inspect the embedded DFD, browse the
  incomplete Scan and Review pages, restart, and explicitly select the result.
- **Verify:** Summary remains the primary Map body before and after restart;
  `RESULT READY` is a compact actionable receipt; the terminal
  `module-recommender` detail stays behind Open/replay; Tab-to-DFD works before
  choosing an action; Shift+Tab reaches the findings projection without
  changing the journey phase; restart never auto-accepts the attempt or
  restores the prior tab.
- **Judge:** completed support work reads as context for a decision, not as a
  replacement application screen, while explicit operator control remains clear.

## B. Core operator loop

### J4 — Bounty operator, scan to finding
- **Persona:** bug-bounty hunter with a key.
- **Launch:** `--target <fixture repo>`.
- **Journey:** Setup → Start Map → Map → Run Focus → Review → open a finding →
  Prove. Use `workbench`, `next`, `findings`, and `open <id>` along the way.
- **Checkpoints:** phase chip (`組 map 1/4`) matches on-disk reality, not a
  fabricated phase; page visits do not advance reality; Map never shows an
  unrelated retained run; Review confidence-first sort holds; Prove keeps
  identity, STATUS, NEXT, proof, sources, and stale-proof warning visible.

### J54 — Accepted Map to Scan and Report
- **Persona:** returning operator with an accepted, current Map and explicit target.
- **Launch:** `--target <existing mapped target>` using the saved operator config.
- **Sequence:** inspect the resting Scan page, open its planner, choose an explicit
  scanner scope, execute, inspect the terminal result, deliberately select it,
  and follow the truthful next action. A clean result may lead to Report;
  unavailable engines must not become a clean bill of health.
- **Judge:** scope and engine choices are understandable, execution stays bounded
  by the selected plan, partial/failure states retain recovery, and selection
  survives restart. Judge narrow reading and export after the primary flow.
- **Evidence:** use the existing real source and Map artifacts; do not seed
  findings or regenerate the Map to satisfy a screen assertion. Record source,
  Map and config hashes outside the target before/after the run. The script is
  extended as each observed checkpoint is accepted; unexercised steps stay open.
- **Current checkpoint:** inspect and execute the Review planner against the saved
  accepted Scan, inspect its model-backed decisions and explicit result acceptance,
  then follow the reality-derived next action. Preserve source/Map/config hashes.
  First restart after shared decision-read repairs to inspect the persisted local
  decisions and available rerun controls; this checkpoint launches no model work.
  After the explicit source-bound rerun and acceptance, the current recipe checks
  restart and the Report exit at 80 columns. The current Report checkpoint also
  checks truthful cost coverage, cursor editing/cancel, a directory-path export
  failure, a corrected Unicode-path SARIF retry, receipt paging and return to
  Review. Read back the actual export and compare protected hashes afterward.
  After that recovery checkpoint, export all six formats at 120 columns and
  read each file back against the same two reviewed identities. Keep the
  previous recipe with its evidence; each journey runs sequentially.
  Finally, at 40×12, page Report, edit a long Unicode destination, check quit
  disclosure and Stay, then cancel the edit and return. This final variant
  exports nothing and must preserve all existing exported files.
  The next checkpoint cancels a real GPT-5.5 OAuth Ask after public response
  text starts, checks the retained incomplete answer and reply, then sends an
  explicit short follow-up. Restart and inspect Answers for truthful conversation
  recovery. Keep cancellation distinct from provider failure and inspect each
  run receipt; do not count incomplete text as completed model history. This
  checkpoint launches only Ask and preserves the accepted engagement and exports.
  After repair, send a short real Ask, exit, reopen its context-bound history,
  and explicitly request a follow-up that depends on that history. Clear the
  conversation and restart once more; the cleared answer must not return.
  At 40×12, cancel a streamed real answer, confirm exit with the retained draft,
  restart, page the incomplete response, edit the restored submitted question,
  and explicitly retry. Clear the conversation before exiting with a status check.
  The actionable-phase checkpoint uses a separate clean local clone at the same
  Kuzushi commit, scoped to `tests/fixtures/canary-target`. This is labeled
  planted source code. Let the real model-backed scan produce findings and the
  real Review/Prove/Fix paths produce their own decisions and evidence; do not
  import the expected-finding manifest as results. After real Review exposed
  unsupported no-caller refutations, preserve that unaccepted result and
  explicitly retriage after correcting the unresolved-assessment contract.
  Inspect Setup disclosure on a fresh copy of the same five source files at
  40, 80 and 120 columns; that copy receives no model work or finding imports.
  First inspect fresh Setup
  and its Map plan, then extend the recipe after each observed state. Preserve
  the earlier descriptor target and its accepted engagement unchanged.
  After accepting the canary Map, select Agentic SAST and Threat-model-driven
  hunt in Scan, inspect their saved result and leave acceptance for a separate
  observed checkpoint. This remains a labeled canary workflow check.
  The earlier reading/navigation recipe is retained with the
  [September 8 Review audit](../audits/2026-09-07/REVIEW_READING_2026-09-08.md).
  Do not invent verdicts to advance the phase. Prove/Fix/Report remain open.

Prove preflight variant (2026-09-08): resume the existing accepted Review, converge on Navigate after dismissing startup notices, open the selected finding in Prove, inspect static and local modes, try the unavailable local action, read the full card with successive Page Down captures, and close it with Escape. Run J54 sequentially at 80×24 and 40×12 against the existing canary checkout. No model or target execution is launched by this inspection. Earlier recipes are archived in the external prove-dispatch evidence folder.

Model Prove variant (2026-09-08): continue with the same F-0001, selected
GPT-5.5 OAuth model and one static analysis pass. Require the live Review,
investigation and drafted-command states before sending launch keys; a missing
prerequisite must stop the journey. Inspect the resulting model assessment and
its evidence before acceptance, then restart to check persistence. Source-only
analysis must remain distinct from runtime reproduction, and unresolved Review
findings must not be marked complete by visiting Prove. Preserve the prior
recipe and source/config/run hashes in the external model-prove evidence folder.

J54 result-reading checkpoint: run one explicit same-model static verification
for the existing canary F-0001, then inspect its pending result at 80×24 and
40×12. Page the complete receipt without selecting it, restart, and verify
that a fresh result opens on its assessment. Read the entire narrow result
before using it, then check that selection preserves model-only evidence and
required Review. Use required live-state checks before launch keys. Preserve
all earlier run files and archive each recipe in the external
prove-result-reading evidence folder. No new finding or verdict is seeded.

J54 inconclusive-assessment checkpoint (2026-09-08): the first result-reading
run returned insufficient finding detail but was mislabeled as a negative
assessment. The old result remains unselected. The 40-column reading and
selection-rejection journey passed after correcting a wrapped-text assertion.
Rerun one explicit GPT-5.5 OAuth static pass with the corrected nullable
assessment contract. Inspect its actual outcome at 80 columns, then restart at
40 columns. An inconclusive result must show partial status, retain cost and
source receipts, offer inspection/retry and never replace the prior accepted
proof or advance to Fix. Do not require the nondeterministic model to produce
a particular conclusion. Preserve recipes and prior evidence.

J54 final scroll check: selection and restart passed at 40 columns, but the
longer result exposed an unreachable final lineage row. The shared pane now
measures the actual wrapped Paragraph. Run one fresh same-model pass and read
its result at 80 and 40 columns, requiring the final lineage row before judging
completion. This final reading check does not select another proof.

J54 detail-controls checkpoint: with the existing final Prove result still
pending, inspect Trace sequentially at 40×12 and 80×24. Check its visible controls, Page Down and Enter;
Enter should only draft trace expansion, never dispatch it. Clear any draft
before exit. Close Trace with Escape, inspect Investigation, switch between the two details, and return to the same result. Revalidate result selection and source/run hashes. Run sequentially
and retain failures. No model call or proof selection is requested by this
inspection; use test fixtures for potentially destructive result hotkeys.

J54 Trace execution checkpoint (2026-09-08): submit one explicit expansion for
canary F-0001 using the selected GPT-5.5 OAuth model. Require the Trace view and
visible command prefix before launch, observe Run Focus, and inspect the actual
completion without requiring a particular number of steps or verdict. Read all
returned questions/evidence notes and restart to compare the durable view. Do
not accept or discard the pending Prove result. Preserve prior run/result,
source, config and proof hashes; retain the previous recipe. Run sequentially.

J54 Trace recovery checkpoint: reopen the existing saved real expansion and page
through its completion receipt, question, evidence notes and source-identity
limitation at 80 and 40 columns. This variant makes no model call and does not
accept/discard any Prove result. Proof-result classification remains a separate
known defect. Archive each recipe before switching terminal size.

### J5 — Report the work
- **Continues J4:** Fix → `report`; exercise SARIF, Markdown bundle, JSONL,
  JSON, and CSV in that order, plus completeness All/Open/Complete and edited
  target-relative destinations.
- **Judge:** is the path from "I have findings" to "I have a submittable
  artifact" discoverable without docs? Success/error must remain on Report with
  count, absolute path/error, timestamp, Retry, Back to Fix, and explicit
  Reveal Destination.
- **Verify:** all formats carry additive remediation metadata when present.

### J6 — Recon intake
- **Persona:** operator with an amass/httpx/nuclei/nmap export.
- **Goal:** reach `recon:import`.
- **Known risk:** flagged **unreachable (BLOCKER)** in the July devex audit.
  This journey exists to confirm whether an operator can get there at all.

### J7 — Findings triage & dismissal
- **Journey:** filter Review so the pinned finding disappears, then move through
  Review → Prove → Fix, suppress one finding, and record a decision.
- **Judge:** is dismissal/suppression state honest and durable, and can the
  operator tell a *suppressed* finding from a *gone* one?
- **Verify:** the exact pinned identity and active filter are disclosed; verify,
  suppress, patch, and apply target only the finding visibly named on screen;
  the reveal-queue action restores it before action.

## C. Honesty & resilience (capture *during* transitions)

These require captures mid-transition — exactly what static buffer snapshots
cannot see.

### J8 — Interrupt mid-run  ⭐
- **Journey:** start a scan, press `Ctrl+C` once mid-flight, immediately capture
  Run Focus + contextual Jobs, press it again while cleanup is pending, then
  press it once after cleanup reaches terminal.
- **Known risk:** canceled→✓done bug — a killed job rendering as successfully
  completed. Single most important honesty check.
- **Verify:** final cancellation restores the exact launch origin with one
  receipt; manual Run Focus inspection and background-owned work do not
  auto-return or steal focus; the second press during cleanup does not exit,
  the post-cleanup press does, and no Kuzushi worker/bridge process remains.

### J9 — Jobs / steer queue
- **Journey:** launch work, press `s` in Run Focus and queue a valid
  `run <tool> …`, reject an invalid command inline, press `b` to background,
  open `jobs`, then `jobs -k <id>` a scoped cancel.
- **Verify:** live vs. stale-disk rows are labeled truthfully; scoped kill
  aborts only the addressed slot.
- **Known risk:** steer-queue starvation flagged in branch review.

### J10 — Autonomy dial
- **Journey:** `Ctrl+↑` / `Ctrl+↓` and the `autonomy` / `posture` verb across
  recon/hunt/confirm/fix.
- **Verify:** the `⛭` chip shows `⚠` only when it actually throttles the walker;
  raising the dial never forges phase progress.

## D. Discoverability & navigation

### J11 — "What can this thing do?"
- **Persona:** returning user who forgot the verbs.
- **Journey:** `help` → `tools` / `modules` → ghost-text / command palette.
- **Known risk:** 67 flat tools + dead ghost-text = discoverability wall. Judge
  whether the surface is navigable or a wall.

### J12 — Run Focus / contextual viz
- **Journey:** run a scan; confirm Run Focus owns the foreground; after origin
  restoration, confirm the viz deck (`viz` / `scene`) opens only when its
  artifact has content. Tab through terrain, DFD, heatmap, attack path, and
  attack tree/exploit-chain content.
- **Judge:** DFDs and the other durable visualizations remain available without
  replacing the workflow page. Background completion emits a notice only.
- **Verify:** Help/Controls/Capabilities are modal; Jobs/Replay/Trace/viz are
  full-frame contextual decks; replacing one does not nest origins; Esc restores
  the exact original page and input mode.

### J13 — Deep view tour (broad, shallow)
- **Journey:** capture Target, Setup, each Map/Review/Prove/Fix page, Run Focus,
  Report, then each contextual modal/deck and remaining diagnostic route.
- **Judge:** top-bar / footer / status chrome stays truthful per view. This is a
  chrome-truthfulness sweep, deliberately broad; run after the deep journeys.

## E. Responsive & environment matrix

### J14 — Narrow terminal
- **Journey:** re-run J1/J4 at **60×20**, **80×24**, and the historical failure
  size **96×89**; also sample 40×12, 120×36, and 160×48 off-screen.
- **Exercises:** at 96×89, Steps and Output begin on the same row, no generic
  prompt row exists, and no blank canyon separates progress from output. At
  60×20, Run Focus stacks; below 50 columns or body height 14 it uses one
  Tab-switched viewport.
- **Judge:** narrow Prove retains identity/status/next/proof/sources/staleness;
  findings/detail stay readable and nothing truncates behind chrome.

### J15 — Palette / TERM matrix
- **Journey:** launch under `TERM=xterm-256color` (emulated macOS Terminal) vs.
  truecolor, capturing with `-e`; also `KUZUSHI_THEME=high-contrast` and
  `KUZUSHI_REDUCED_MOTION=1`.
- **Known risk:** truecolor-only palette breaks macOS Terminal.
- **Judge:** legibility, not merely non-crash.

### J16 — Headless / plain parity
- **Journey:** `--plain` and a non-TTY pipe of Setup, Run Focus, all phase
  pages, receipts, and Report.
- **Judge:** plain output stays useful (no ANSI dependency, no interaction-only
  state), serializes Steps then Output, prints exact equivalent commands, and
  honors the mode-parity contract in
  `docs/assessments/mode-parity.md`.

### J17 — Canonical five-phase cockpit reference
- **Journey:** load the deterministic offline reference fixture, enter Navigate
  mode, and use keys 1–5 to capture Map, Scan, Review, Prove, and Fix from the
  same durable workspace reality.
- **Verify:** every capture comes from the live alternate screen; page visits do
  not advance reality; each phase retains its truthful task hierarchy and NEXT
  action; legacy Hunt/Confirm labels never reappear.
- **Patch lifecycle coverage:** automated draft/apply/reverify state transitions
  live in
  `crates/kuzushi-bdd-tui/features/cockpit_patch_lifecycle.feature`; J17 is the
  visual five-phase reference rather than a second mutation harness.

### J25 — Real-target Map and durable-page truth
- **Journey:** require an explicit existing `KUZUSHI_DEVEX_TARGET`, enter through
  the installed `kz` wrapper when `KUZUSHI_NATIVE_BIN` pins the freshly built
  native, then capture Map, Scan, Review, Prove, and Fix sequentially.
- **Evidence contract:** record the target's canonical path, HEAD, and complete
  source-status receipt before and after, excluding only normal `.kuzushi`
  writes. Any drift is a machine failure. Each capture records both the wrapper
  and delegated native hashes plus requested and actual terminal dimensions.
- **Verify:** wait for explicit page identity before every capture. Machine
  assertions establish only reachability and identity; every `ask:` remains
  `REVIEW REQUIRED` until an auditor answers it from the referenced screen.
- **Judge:** target/revision facts are real, stored receipts remain distinct
  from live progress, locked phases explain their prerequisite without
  manufacturing evidence, and remediation never implies unapproved mutation.

---

## F. Model-ladder verification & split-verdict escalation (P1/P3)

These journeys audit the shipped `verify:finding` model ladder (P1 `gateModel`,
the Prove `MODEL LADDER` card) and split-verdict escalation (P3 tie-break
disclosure). The deterministic arms rely on the F4 phase-fixture extension
(`crates/kuzushi-tui/src/app/devex_phase_fixture/`): two seeded findings —
`escalated-split-fixture` (gate + panel×2 + `escalated=openai:gpt-strong`,
`split`) and `refused-split-fixture` (`refused=same-model`) — plus two seeded run
dirs (`verify-escalated-run`, `verify-refused-run`) whose `items.jsonl` carry the
gate → panel → escalation stage labels and a refusal danger notice. All keyless
and deterministic; the one live arm (J34-L) SKIPs honestly without a key.

### J30 — verify options: discoverability, storage, honesty  ⭐ release-blocking
- **Journey:** open `options verify:finding`; confirm `gateModel`/`escalationModel`
  are hidden under Standard and appear under `show advanced`; `setg` both; confirm
  the stored rows sort first; store a malformed `gateModel` and dispatch.
- **Judge:** the advanced rows describe what the gate trusts (rejection-only) and
  that escalation fires only on a split; a malformed value is accepted at `setg`
  but rejected legibly at dispatch (`gateModel is not a valid model spec`), never
  silently dropped or defaulted; nothing implies `gateModel` gates `Start Map`.
- **Plain parity:** the same rows serialize through the non-TTY stdin script with
  no ANSI, no box-drawing dependency.

### J31 — Prove MODEL LADDER card: preview ≡ drafted command  ⭐ release-blocking
- **Journey:** with stored gate/escalation models, open the Prove `v`
  investigation card; read the `MODEL LADDER` rows; press Enter to draft.
- **Judge (identity contract):** the ladder reads top-down in execution order
  (gate → panel → escalate); the drafted `run verify:finding {…}` JSON is
  byte-identical to the card preview; the unset branch shows `gate: not set` and
  OMITS the keys from the draft (no invented default); the card drafts but never
  runs (`expect-not: ACTIVITY`).

### J32 — escalated split: Prove discloses, never promotes  ⭐ release-blocking
- **Journey:** `open escalated-split-fixture` → Prove.
- **Judge (P3 invariant):** the split escalation renders `⚖ … resolved by
  openai:gpt-strong (tie-break)` as an ADDITIVE disclosure; the finding stays
  ModelAssessed/Unverified — no `Confirmed`, no `runtime_verified`, rung unmoved;
  the `⚖` glyph is explained in words, not color alone.

### J33 — refused escalation: warning, not success  ⭐ release-blocking
- **Journey:** `open refused-split-fixture` → Prove.
- **Judge:** the refusal renders in warn/danger tone (`⚠ … tie-break refused …
  verdict unchanged`) with NO green `✓` on the row (the pre-P3
  `append_proof_notes` hazard); the completion context reads completed-with-a-
  warning, never a clean verification; the ≤90-char stage note fits the context
  strip.

### J34 — Run Focus / replay stage-label ordering
- **Journey (deterministic):** `replay verify-escalated-run` renders the three
  stage labels; `replay verify-refused-run` renders the refusal.
- **Judge:** stages appear gate → panel → escalation with three DIFFERENT model
  names, each explaining WHY it ran (the trust rule); the refusal run never shows
  a completed `escalation · tie-break (` stage and tones the refusal Danger/Warn.
- **Plain parity:** `runs trace <run-id>` prints the same three labels, same
  order, no ANSI — the shared-core proof the stage story is not shell chrome.
- **J34-L (advisory, live):** `require-any-env` a key, run a real split with
  `VERIFY_PASSES 2` + a distinct `escalationModel`; accept SKIP and accept that a
  real panel may not split — assert only that IF the escalation stage appears it
  is labeled and ordered.

### J35 — router role `MODEL_TRIAGE_ESCALATION` end-to-end (regression R2)
- **Journey:** `setg MODEL_TRIAGE_ESCALATION openai:gpt-strong`; `run router:show`.
- **Judge:** the `triage_escalation` row reports the value as `operatorOverride`
  AND effective — proving the `setg` reached the router, not merely echoed the
  stored key. **Negative arm:** on a fresh HOME the `triage_escalation` row must
  NOT display the operator default as its effective escalation route (escalation
  refuses inheritance; a row that shows the primary model as the tie-break route
  is a lying screen).

---

## G. Deep-auditor taint tools, worklist & grammar honesty (P2/P5/P6)

Batch 2 of the tmux/UX plan (§2 journeys J36–J48). These encode the deep-auditor
taint-tool option surface, degraded-state signifiers, the risk worklist (Map
section + scene page + verb/origin-restore + headless parity), and tree-sitter
grammar honesty. The
release-blocking keyless set is J36, J37a, J38 (steps 1–3, incl. regression R1),
J39, J42, J43, J44, J45, J46, J47, J48. The live/model arms (J37b, J38 steps 4–5,
J40, J41) are advisory and SKIP honestly. J39's deterministic arm relies on the
F4 fixture extension: a sixth-finding stable fingerprint `audited-dataflow-fixture`
carrying seeded `deep-audit:evidence` audit events (source + sink + a falsifying
`guard` witness mined off a cpg-rs path, `origin: cpg_path`), written through the
real `record_finding_audit_event` path.

**Verified UI-string corrections against the current build** (the plan's captured
strings were aspirational — these are what the code actually renders):
- Health cpg-graph Warn row: `no graph — deep-audit runs grep-only` / remedy
  `run cpg:build (or taintTools=build)`. The old "graphs build implicitly on
  first hunt" sentence is gone (`ui_view_models/health.rs`).
- AUDITED DATAFLOW rows render `<kind> · <file:line>` (e.g. `guard · …`), NOT
  `guard@…`; the cpg-mined origin reads `deep auditor (cpg-rs path)`, NOT
  "cpg-rs witness"; guard notes are prefixed `falsifying evidence · `
  (`findings/presentation/detail/dataflow_evidence.rs`, `detail_pane.rs`).
- Worklist legend words: fan-in → `not implemented (Phase B)`, prefilter →
  `not tracked (Phase A)`, systems → `not requested`; empty panel title
  `no risk worklist` with CTAs `context:build` / `worklist:rank`; rows carry the
  RAW `92/100` display (`viz_data/worklist.rs`, `scene/worklist.rs`).
- **Known gap (filed, not blocked):** the worklist `⚠ degraded — no cpg graph`
  banner and the F (call-graph fan-in) citation appearing after `cpg:build` are
  Phase-B wiring — the render-path fold passes `fan_in: None`, so the fan-in
  contributor is `NotRequested` ("not implemented (Phase B)"), never `Degraded`,
  and `cpg:build` does not yet feed the worklist. J43/J44 assert the shipped
  honest representation (dim legend, contiguous ranks, raw display, unranked
  footer) and do NOT assert the unwired banner/F-appears.

### J36 — `taintTools` discoverability (Standard, not Advanced)  ⭐ release-blocking
- **Journey:** `options triage:run` — `taintTools` is visible WITHOUT `show
  advanced`, default `available`, choices `off`/`available`/`build`; the
  description says unavailable graphs degrade to grep-only.
- **Judge:** an operator can tell from the description alone what degradation
  means. **R3 arm:** `options deep-audit:run` now declares `passes`/`temperature`.
- **Negative (headless):** `run triage:run {"taintTools":"nope"}` rejects at the
  canonical boundary naming the three choices (`must be one of off|available|build`).
- **Plain parity:** the same rows serialize through the non-TTY stdin script.

### J37 — degraded taint: amber where it claims  ⭐ release-blocking (37a keyless)
- **J37a (keyless):** on a graph-absent target, `health` tones the cpg-graph row
  Warn with `grep-only` and the `run cpg:build` remedy; the pre-P2 "graphs build
  implicitly on first hunt" sentence is gone.
- **J37b (advisory, key-gated):** a real `triage:run {"strategy":"deep"}` shows
  the `taint tooling · unavailable` degraded line and proceeds grep-only.

### J38 — cpg lifecycle: build → planning row → health  ⭐ release-blocking (1–3)
- **Steps 1–3 (keyless):** headless `run cpg:build` writes `.kuzushi/cpg-rs`; the
  planning picker's Build-code-property-graph row reads `cached` (regression R1 —
  pre-fix it showed Missing/not-built forever because the probe looked for the
  never-written `.kuzushi/cpg.bin`); `health` then tones the cpg-graph row Pass
  (`backend=cpg-rs`), the cache-backed R1 consumer surface.
- **Steps 4–5 (advisory, key-gated):** deep triage emits `queried taint:` progress
  and `0 paths (sources N / sinks M)` honesty; latest-wins coalescing.

### J39 — AUDITED DATAFLOW reaches Review/Prove  ⭐ release-blocking
- **Journey (keyless):** `open audited-dataflow-fixture` → Review detail shows the
  `AUDITED DATAFLOW` section after EVIDENCE with `deep auditor (cpg-rs path)`
  rows and a `guard · …` row noted `falsifying evidence · …`; Prove shows the same
  cited witness.
- **Judge:** the guard row is visibly a FALSIFIER; the finding's proof rung is
  UNCHANGED by the presence of dataflow evidence (deferred-promotion guard).

### J42 — fresh target: empty is empty  ⭐ release-blocking
- **Journey (keyless):** on a target with no context snapshot, `worklist` lands on
  the `no risk worklist` guidance panel (one hint line + `context:build` /
  `worklist:rank` CTAs), zero fabricated rows.
- **Judge:** the scene page rail does NOT carry a worklist tab while empty
  (gate-on-non-empty, the EntryPoints precedent); the explicit verb still lands
  on the panel rather than dumping a first-timer on the DFD.

### J43 — degraded worklist: honest states, contiguous ranks  ⭐ release-blocking
- **Journey (keyless, seeded snapshot):** with an attack-surface snapshot but no
  cpg graph, `worklist` shows contiguous `#1..#N` ranks, RAW `92/100` glyph rows
  (never a laundered float), and the CONTRIBUTORS legend distinguishing three
  states: `not requested` (systems), `not implemented (Phase B)` (fan-in),
  `not tracked (Phase A)` (prefilter).
- **Judge:** the three non-live states render distinctly (word, not color); the
  unranked footer counts zero-signal files. (See Known gap re: the fan-in
  degraded banner.)

### J44 — signal-appears / raw-display honesty  ⭐ release-blocking
- **Journey (keyless):** re-open `worklist` after `cpg:build`; diff the captures.
- **Judge:** the previously-shown A-scores are not retro-zeroed (the earlier
  ranking was honest about what it had); rows keep the RAW `A 92/100` display, not
  a laundered `0.71`. (F-citation appearance is Phase-B — see Known gap.)

### J45 — Map WORKLIST section: width + plain parity  ⭐ release-blocking
- **Journey:** Workbench → Map renders the `WORKLIST` divider with top-5 rows and
  the "run `worklist` for all N" affordance across width cells (150/120/80).
- **Plain parity:** the Map plain projection (`map.rs plain_lines`, a SEPARATE
  projection) also emits `WORKLIST`; glyphs (`A`, `#1`) survive style-stripping.

### J46 — worklist verb + origin restore  ⭐ release-blocking (keyless)
- **Journey (keyless, seeded snapshot):** from a stable origin view (`setup`),
  the `worklist` verb opens the full-frame worklist deck (rank rows, or the
  `no risk worklist` guidance panel when the shell has no hydrated run-artifact
  attack surface — the deck reads the run artifact, not the seeded context
  snapshot). `Esc` then restores the exact origin chrome.
- **Judge:** the contextual-utility non-nesting contract holds — opening the
  deck captured the origin, and leaving restores it without cancellation or a
  nested utility stack.

### J47 — headless parity: `run worklist:rank`  ⭐ release-blocking
- **Journey:** `run worklist:rank` emits `data` with `rows` (carrying
  `citations{raw,rawDisplay,normalized,normalization}`), `contributors` STATES,
  `unranked`, and `rankedTotal` — the same truth the TUI renders, machine-readable.
- **Negatives:** an unknown key is rejected at the canonical boundary; a run
  without `--target` errors naming the tool and never substitutes cwd.

### J48 — doctor / health disclose the grammar set  ⭐ release-blocking
- **Journey:** headless `doctor` carries a `treesitter` row listing the shared
  supported-language const (includes `cpp`, `rust`); per the G4 fix it PROBES the
  sidecar — Ok when the binary resolves, Warn when `KUZUSHI_MCP_TREESITTER_BIN`
  points at a missing path.
- **Judge:** the language list is the shared const, not a hand-copied sixth copy.

---

## Out of scope (manual only)

**Real OAuth login** (`auth login openai` / `auth login anthropic`) is
intentionally excluded from the automated set: completing a real handshake needs
live credentials and a browser round-trip that must not run unattended. Spot-
check it by hand.

## Priority order

1. **J1** keyless first launch, **J8** interrupt honesty — highest value re-runs.
   **J49** Setup target-facts honesty rides with the Target/Setup set (keyless,
   release-blocking). **J53** guards ready-Map resume and compact successful
   result choices (keyless, release-blocking).
2. J4, J5, J7, J17 — the durable cockpit, reporting, and phase reference.
3. J6, J9, J10, J11, J12 — control surfaces & discoverability.
4. J14, J15, J16 — environment matrix.
5. J13 — broad chrome sweep, last.
6. J30–J35 — model-ladder / split-verdict escalation honesty (P1/P3),
   release-blocking keyless set; J34-L is advisory/live.
7. J36–J48 — deep-auditor taint tools, worklist, and grammar honesty (P2/P5/P6),
   release-blocking keyless set (J36, J37a, J38 steps 1–3, J39, J42–J47, J48);
   J37b, J38 steps 4–5, J40, J41 are advisory/live.

J54 Trace result-ownership checkpoint (2026-09-09): recover the prior pending
verification at 80×24, inspect preserved Trace history, then run one explicit
same-model OAuth expansion and inspect its return, cost, source receipt and
complete notes. Restart sequentially at 80×24 and 40×12. Trace must create no
selectable phase attempt, and both workflow ledgers and the selected proof must
remain unchanged. Archive each recipe before changing variants; judge each
review item. No proof acceptance or discard is part of this checkpoint.

J54 immediate-completion checkpoint (2026-09-09): the foreground Trace return
must already show the new saved run and source status. Its informational
completion notice must not consume Escape; one Escape returns to the existing
pending verification. Warning/error notices retain explicit dismissal. Verify
full outcome recovery at 80/40 columns, preserve all 36 baseline run/result
files and both phase ledgers, and judge every captured review item.

The first immediate-completion trial matched a prior successful receipt after a missing-analysis-component failure. Preserve that failed evidence. Build the source workspace sidecars before retrying; reject the old receipt id and cross-check the displayed new id against its successful canonical result. A generic source-status match alone is insufficient.

J54 failure-notice checkpoint (2026-09-09): use an explicitly labeled, process-local missing tree-sitter helper override to repeat the observed failure without removing installed binaries. Require the error on the returned Trace screen, inspect the build remedy, dismiss the alert then return to the same verification, and reopen Activity for the failed run. Preserve existing sources, receipts, workflow and proof; do not mistake retained old Trace evidence for a new success.

J54 Replay reader checkpoint (2026-09-09): open the existing failed run
`tool-1788968317049-a1f28c471d3d`, wait for its healthy saved projection, and
page the complete failure remedy and timeline at 80/40 columns. Replay is a
dedicated reader; do not use generic Escape-to-Navigate convergence after
opening it. Its footer must disclose Escape back and measured paging. Check
return from repeated end paging, then one Escape to the original verification.
Exercise resize through the real reducer/render-geometry regression; do not
claim live resizing from separate fixed-size launches. No new model call, result selection or target change is required.

At 40 columns, the generic `submit:` helper cannot validate a long run-id command on one visible prompt row. For this saved-run checkpoint, require the fresh Prompt cue, type the exact command, require its unique visible suffix, then press Enter. Preserve the failed setup trial and require the healthy Replay projection before judging reader behavior.

### J62 — Observation gaps preserve human review

- **Persona:** operator comparing two source revisions after a previously confirmed finding is absent from a later scan.
- **Fixture:** two real offline `secret-scan` jobs, a labeled human confirmation, distinct Git commits, and seven export paths. No provider calls or target-code execution.
- **Journey:** filter to `state:not_observed`, inspect the selected Review detail, zoom and resize, compare the two runs, then restart and revisit the same finding.
- **Verify:** the original confirmation survives; no `fixed` or `removed` result is inferred. The gap carries both real run references and event provenance into reports. Keyboard controls, scroll and source navigation remain readable across the viewport matrix.
- **Judge:** absence must never look like proof of a fix. Small terminals must offer a readable detail surface, and returning from comparison must not lose the finding.

### J63 — Review completes at Report

- **Persona:** operator finishing review and exporting a source-analysis investigation.
- **Fixture:** J62's two real offline scans and seeded confirmation; a second decision is entered through the real TUI. No provider calls or target-code execution.
- **Journey:** open the remaining finding, record a deferral, open Report with `r`, return to the same zoom, use `next`, select JSON, inspect all six viewports, export, then restart without color.
- **Verify:** Review ends at Report; completed review does not add proof or patch work. JSON retains both decisions and the cross-revision observation-gap receipt. The 40-column capture must show the actual destination, not merely its label. Session spending is separate from unknown workspace total.
- **Judge:** the export population, destination, result and return controls must be understandable; opening Report must preserve the reading position and draft. Raw timestamps and diagnostic clutter remain product-quality work even when this bounded journey passes.

### J60 — Paged allowance review (current recipe)

- **Fixture:** a real offline three-job study and durable allowance, with no provider requests or discovery execution.
- **Journey:** inspect the draft, open its approval, read all six sizes, attempt approval before the last page, cancel, reopen, approve at 40×12, then restart without color and inspect the saved status in Logs.
- **Verify:** the exact terms and full plan digest remain reachable; paging and Escape are always visible. Cancellation starts no work. Only the final-page `y` approves. The persisted ledger contains one revision, three jobs, zero attempts and zero calls.
- **Judge:** model, limits, protected review, dollar uncertainty and the distinction between approval and execution must be clear. Status discoverability and the full study editor remain separate product gaps.

Capture adapters derive plain text from one ANSI capture so a redraw cannot pair
the text of one screen with the appearance of another. Failed captures remain
preserved; passing machine predicates still require recorded screen review.


### J64 — Finite study form and saved allowance

- **Fixture:** a real three-pass `secret-scan` study under the selected model's
  configuration. Only deterministic source scanning runs; no provider calls or
  target-code execution.
- **Journey:** choose scan options, prepare the study, inspect the source/context
  receipt at all six sizes, enter call limits, approve at 40×12, open jobs, start
  separately, inspect completion, then restart without color and reopen with `a`.
- **Verify:** draft and approval start no jobs; the exact plan executes three
  attempts, keeps zero provider reservations, and restores the same investigation
  and limits. Required artifact checks stop the journey before dependent actions.
- **Judge:** visible actions, selected-row visibility, scope/context readability,
  spending uncertainty, the distinction between approval and execution, and
  direct access to saved status. This proves the offline study path, not live
  model quality or the entire context/scoping/learning roadmap.

### J65 — Immutable context selection within a study

- **Fixture:** two labeled imported threat-model revisions; deterministic reads
  and study compilation only. No provider calls, job starts or target execution.
- **Journey:** open the study's context browser, inspect the inactive revision,
  page through summary and complete document at all six viewports, accept it,
  compile a study, then explicitly omit context and compile a replacement draft.
- **Verify:** inspection is required before using a revision; each plan binds
  the selected reference or explicit omission; the active workspace context and
  investigation identity remain unchanged. Shared prepared dispatch reads the
  same authenticated document used by scanners.
- **Judge:** context identity, source limitations, selection, paging, acceptance,
  cancellation and fresh-plan approval remain understandable. This journey
  does not validate model-backed context generation or editing.

### J66 — Context generation plan and allowance

- **Fixture:** labeled imported contexts; real source-only planning and approval.
  This journey deliberately starts no model-backed job and admits no provider call.
- **Journey:** open generation from the context picker, set total/protected calls,
  prepare one fixed job, inspect summary and exact options across all six
  viewports, approve through the paged terms, then reopen the approved plan after
  restart with no color. The separate launch control remains unpressed.
- **Verify:** one job, one worker, one attempt, exact model and source identity,
  retained active context, durable limits and zero starts/provider calls.
- **Judge:** planning, approval and launch are distinct; budget fields, paging,
  exact options and back controls stay visible; approval reveals the next action.
  Core integration tests exercise the real generator and subsequent scan study
  with a mocked provider; this journey does not establish live model quality.

### J67 — Setup opens the approved context workflow

- **Fixture:** a fresh repository, two deterministic preparation selections and
  one source-only context job. Planning and local approval only; no model calls.
- **Journey:** select context generation in Setup, open Allowance, set limits,
  prepare a draft, go Back and reopen it, inspect all six viewports and exact
  inputs, approve the fixed plan and open its three named jobs. Confirm session
  exit, require the harness shell to own the terminal, then restart without color.
- **Verify:** selected tasks, draft identity, source/model, five total calls and
  two protected review calls survive Back and restart. The ledger admits exactly
  three jobs with one attempt each, but records zero starts and provider calls.
  ANSI inspection rejects colors in the recovered no-color screen.
- **Judge:** preparation, generation, allowance approval and launch have distinct
  states and visible actions. Small screens retain the action and paging; full
  terms and both preparation tools remain reachable. The quit prompt identifies
  volatile Setup choices without implying the saved plan or active work is lost.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20260910-041224/J67/`
  records 35 machine checks and 16 manual screen judgments passing. Earlier
  failed runs remain retained, including invalid restart evidence caught by ANSI
  review. A launch command typed into a still-running application is not restart
  evidence; `require-exit` now prevents that error.

### J68 — Inspect the selected context's data-flow diagram

- **Fixture:** two explicitly labeled, imported contexts with distinct diagrams;
  the selected revision differs from the active workspace revision. Real offline
  reads and three-pass study compilation only; no provider requests or scans.
- **Journey:** require inspection before `v`, open the selected diagram, read
  component evidence, inspect flows and boundaries across all six viewports,
  return and reopen at the same element, select context for the study, then
  prove process exit before recovering the saved study in a no-color session.
- **Verify:** diagram keys dispatch no generation or scan work. The compiled
  plan binds the inspected revision; the active model stays unchanged. Every
  component, flow and boundary remains reachable, including full evidence at
  40×12. Internal and reverse arrow direction has focused shared-renderer tests.
- **Judge:** revision identity, grounding status, real direction, evidence,
  paging, Back and acceptance remain clear. The recipe separates Escape from
  the next character key so the terminal cannot interpret them as an Alt chord.
  This is context inspection, not the remaining accepted Map/DFD bridge or full
  context editing workflow.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20260910-044815/J68/`
  records 29 machine checks and all 12 manual judgments passing. The earlier
  `044356` run remains manually failed despite green machine checks: its
  boundary context count disagreed with the full detail reader. Both now use
  the same selected-context lookup. Earlier recipe and arrow failures remain
  retained as failed evidence too.

### J69: Recover generated context and inspect unusable results

- **Fixture:** real offline plan creation, approval and exact context reads.
  The result is an explicitly labeled imported document; queue completion and
  failure are injected to exercise recovery. No generator, scan job or provider
  request runs. Generation execution has separate mocked-provider core tests.
- **Journey:** prepare and approve the Setup Map plan, return to its recovered
  result, inspect and select its exact context, compile the next three-pass
  study, inspect missing output across all six viewport sizes, prove exit and
  recover in a fresh no-color process, then inspect a failed job and request a
  separately approved replacement draft.
- **Verify:** the same investigation and allowance survive every transition.
  The scan plan records the selected inactive context. Missing and stopped
  output requires inspection. Unknown costs remain unavailable; completed
  context plans advertise result review. Back does not start or replace work.
- **Judge:** state, action, complete failure reasons, cost uncertainty, paging,
  comfortable reading width and return navigation agree with the recorded work.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261004-235128/J69/`
  has 53 passing machine checks and 16 passing manual judgments. Earlier runs
  remain failed evidence: `233652` and `233808` exposed recipe assumptions about
  preloaded context; `233942` exposed stale Setup guidance, clipped notices and
  false zero-cost presentation; `234851` retained a failed expectation that
  incorrectly required a naturally wrapped failure reason on one line.
  This checkpoint does not establish durable Map acceptance or live model
  quality. The broader reference quality bar remains open.

### J70: Accept recorded Map context and retain its exact revision

- **Fixture:** two explicitly labeled imported contexts with different diagrams.
  Real offline `context:build`, `threat-model:import`, `campaign:study` and exact
  context reads. Queue outcomes and Map selection are produced by the TUI;
  no generation, discovery or provider request runs. Grounding failure is
  intentionally visible.
- **Journey:** review and accept Alpha while Beta stays globally active, inspect
  the recorded DFD at all six sizes, prepare a three-pass draft, inspect its
  exact context, prove process exit and recover without color. Remove the
  accepted immutable object, restart and inspect recorded runs from the
  smallest failure card.
- **Verify:** the accepted run reference supplies both Map and the study draft;
  ordinary preparation cannot freeze active Beta first. The draft contains
  three jobs, one worker and no approval. Missing evidence cannot substitute
  another context. Enter opens history without starting work; shared accounting
  records no provider reservations or discovery attempts.
- **Judge:** acceptance, failed grounding, exact identity, keyboard controls,
  resize, source limitations and failure recovery remain understandable. The
  single-row DFD inspector names the selection at 40×12, and its recovery card
  places the inspection action before a potentially long error.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-013949/J70/`
  records 37 passing machine checks and all 15 manual judgments passing.
  The harness retains `REVIEW_REQUIRED`; judgments are recorded separately in
  `manual-review.json`. Earlier failed evidence remains, including `010453`
  (active context froze into the draft), `011725` (hidden recovery reason) and
  `013021` (blank resize capture and hidden narrow-screen action despite green
  machine checks). The recipe now requires a rendered live frame after resize.
  This is an imported-context acceptance proof. J71 covers the generated
  campaign handoff; full reference parity remains open.

### J71: Review generated context as a durable Map

- **Fixture:** the real source-only context generator runs through shared
  observed dispatch under an approved offline allowance and a mocked provider.
  Its exact immutable revision and recorded result are real; the completed
  campaign queue is injected. Another labeled context stays globally active.
  No live provider or discovery job runs.
- **Journey:** recover the completed context plan, inspect result controls at
  all six sizes, use `m Review Map`, explicitly accept the recorded result,
  inspect the DFD, verify process exit and restart without color. Change source,
  refuse another handoff, dismiss the error and inspect the old exact revision.
- **Verify:** one durable Map, one operator decision, one consumed provider
  reservation and no new discovery attempt. Declared generated artifacts exist.
  Source drift and active-model substitution cannot create new Map evidence.
  Grounding and Git revision remain unrecorded in this offline fixture.
- **Judge:** controls, budget disclosure, exact context, acceptance, diagram
  readability, restart and historical inspection remain understandable. A
  recorded diagram cannot appear beside a claim that no threat model exists.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-023106/J71/`
  records 34 machine passes and all 12 manual judgments passing. Harness status
  stays `REVIEW_REQUIRED`; `manual-review.json` holds the separate judgments.
  Earlier failures are retained: `021654` and `021832` caught fixture artifact
  assertions, `021914` caught a missing phase-history refresh, and `022406`
  caught contradictory empty-state guidance and a selection/view assertion.
  `022842` passed the shorter recipe before historical error dismissal was added.

### J72: Accepted Map carries accounting into a scan study

- **Fixture:** J71's real offline generator, mocked provider and injected
  completed context queue. One approved provider reservation is already spent;
  another context remains globally active. No live call or discovery job runs.
  The isolated repository reuses an existing local commit as Git metadata;
  its worktree deliberately differs from that commit. No commit is created.
- **Journey:** explicitly accept generated Map, open ordinary `scan batch`,
  inspect inherited allowance across all six sizes, prepare three exact-context
  passes and separately approve that plan. Verify process exit, restart without
  color, open a fresh form and recover the existing approved study. Remove its
  approval rows while retaining call reservations and refuse new implicit work.
  Change source content while retaining both the same SHA and dirty flag,
  then refuse an implicit draft from the stale accepted Map.
- **Verify:** one investigation, one consumed call, five total calls, two
  protected review calls and exactly three unstarted discovery jobs. Planning
  creates no approval; replacement approval advances revision without refunding
  consumption. Missing approval cannot appear as a reset or zero budget.
- **Judge:** retained consumption, current approval, distinct start action,
  resize, complete term review, restart and recovery remain understandable.
  This fixture proves accounting handoff, not nondeterministic finding quality
  or completion of all three provider-backed discovery passes.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-034035/J72/`
  records 44 machine passes and all 14 separately recorded screen judgments
  passing. The harness remains `REVIEW_REQUIRED`; `manual-review.json` records
  the judgments and capture hashes. Actual viewport dimensions and no-color
  ANSI were inspected. The fixture leaves only two context/scan calls available
  for three planned discovery jobs; it proves no promise of complete execution.
  Earlier failures and judgments remain: `025933`, `031035` and `031448` found
  wrapped-text assertions; `031204` found unborn Git metadata; `031720` found
  a wrapped work-refusal assertion; `032652` found misleading worker-policy
  classification after source drift. At `033146` all machine checks passed,
  but manual review rejected a partial redraw containing stale Run Focus
  controls. The recipe now waits for draft completion and the final form footer.
  The narrow form needs eighteen detail pages and repeated error prefixes still
  merit polish; reference interaction parity remains open.

### J73: Execute three fresh passes under the retained investigation

- **Fixture:** J72's real offline context generator and accepted Map, followed
  by real scan-batch controller and agentic scanner execution. Every provider
  fetch is intercepted in a preload; isolated credentials contain only a test
  placeholder. Findings are labeled synthetic observations about a greeting
  program. No live provider, proof execution or patching is involved.
- **Journey:** accept generated Map, configure one source-only engine, compile
  three jobs and explicitly revise total calls to six while preserving two
  protected review calls. Approve the exact plan, open jobs, separately start
  them, then inspect consolidated observations.
- **Verify:** exactly three fresh bridge processes receive identical frozen
  prompts without assistant history or the unrelated active context. Completed
  discovery outcomes come from real execution, not an injected queue. Existing
  context spending remains and new discovery cannot silently add work.
- **Judge:** approval and start remain distinct, completed work is understandable
  and recurrence remains separate from finding confidence. Navigation-mode paste
  hands input visibly to the composer without submitting. Actual paging at 40x12
  reaches both observations. The Scan result requires explicit acceptance before
  human false-positive and deferral decisions, local report export and actual
  no-color restart. An observation missing from a later pass cannot be presented
  as fixed.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-052517/J73/`
  has 53 machine checks and 15 separate passing screen judgments. The raw
  harness remains `REVIEW_REQUIRED`; `manual-review.json` records each capture
  hash and the fixture limits. This proves the offline operator path, not live
  discovery quality or complete module readiness.

### J74: Finish retained discovery after an allowance stop

- **Fixture:** J73's real dispatcher and scanner with fully intercepted
  transport. The accepted context has already committed one call. A five-call
  total with two protected review calls admits only two discovery requests.
  The third attempt reaches real shared admission and is refused before fetch.
- **Journey:** approve three fixed jobs with the displayed net call capacity,
  start them separately, inspect two completed and one failed pass, acknowledge
  the partial Scan through its visible keyboard action, record a human decision,
  export retained findings, exit and restart with no color.
- **Verify:** no third provider fetch, no new jobs, no implicit allowance
  increase and no refund of the retained context or completed calls. The failed
  run keeps its host-captured source receipt and remains failed. Partial
  selection requires explicit acknowledgement. Restart retains that decision,
  the five-call ceiling and two protected review calls without retrying work.
- **Judge:** incomplete work and unknown dollars stay visible. Approval shows
  existing commitments and discovery capacity after protected review. Partial
  work can reach triage and local finding export without claiming completion.
- **Limits:** the partial Scan uses its honest degraded receipt layout. Finding
  exports still need a full investigation coverage and allowance receipt. No
  live quality, scope-enforcement or full-interface readiness claim follows.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-055219/J74/`
  has 51 machine checks and seven separate passing screen judgments. Raw
  `REVIEW_REQUIRED` is retained alongside `manual-review.json`. The earlier
  failed source-receipt recovery run is preserved with its failed judgment.

### J75: Report the selected study with durable provenance and accounting

- **Fixture:** J74's real admission stop, accepted generated context and human
  false-positive decision, with every provider transport intercepted. Findings
  remain labeled synthetic. No live model, proof execution or patch work runs.
- **Journey:** open Report from the acknowledged partial Scan, switch explicitly
  between study and workspace history, export JSON, verify all six formats,
  inspect full provenance and page top/tail at every supported size. Exit and
  restart without color, then open Report directly without visiting Campaign.
- **Verify:** two completed and one failed job, two observations folded into one
  finding, one human decision, exact accepted context and authenticated source
  identities. Three committed calls retain two protected review calls. Unknown
  dollars serialize as null in the report-only accounting receipt. Export starts
  no new jobs or provider calls. Every format writes a companion receipt;
  Markdown includes its manifest digest.
- **Judge:** scope, incomplete coverage, recurrence, source/context and allowance
  remain readable. `s` chooses history explicitly; `p` reveals provenance and
  receipt details. Study facts precede long paths. Report omits the process-local
  cost sidebar that would conflict with the shared investigation accounting.
  Pager and return controls remain available at 40x12.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-070922/J75/`
  records 72 machine passes and all 21 separately recorded screen judgments
  passing, with capture/ANSI hashes and actual dimensions. Raw
  `REVIEW_REQUIRED` remains unchanged. Earlier runs retain the duplicated
  historical generation count (`064627`), conflicting wide-screen cost sidebar
  (`065534`) and unsettled resize capture (`070400`). The last issue required
  waiting for the actual Report divider rather than footer text.
- **Limits:** partial Scan is still noisy. No live quality, complete inventory or
  engine coverage, raw-artifact bundle, revision-bound human verdict or complete
  reference interaction parity is established by this journey.

### J76: Capability selection, preparation and draft ownership

- **Fixture:** a fresh target and isolated profile, without model or credentials.
  No tool or provider work executes.
- **Journey:** open capabilities from Setup, select Deep threat map with arrows,
  load its command without submitting, clear the draft and retain selection
  through all six viewport sizes. Confirm exit and repeat without color.
- **Verify:** MODEL REQUIRED follows the selected row; loading states no work
  started. Keyboard ownership and footer agree. The deterministic option and
  explicit tool-model override use shared input preparation without fallback.
- **Judge:** selection, prerequisites and loading remain understandable at
  40x12. Draft controls replace picker controls when editing. Registration and
  a selected model never become an execution-readiness claim.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-075324/J76/`
  has 22 machine passes and nine separately recorded passing judgments with
  text/ANSI hashes and actual dimensions. Raw REVIEW_REQUIRED remains intact.
  Earlier failures preserve the incorrect driver mode (`072734`), conflicting
  Esc ownership (`074048`) and explicit reopening that reset the resize test's
  selection (`075131`).
- **Limits:** preparation and navigation only. This does not certify external
  dependencies, credentials, scope enforcement, allowance, useful module
  output or complete reference interaction parity. At 40x12 the full key list
  remains available through the visible `/keys` control.

### J77: Discovery scope refusal and explicit revision

- **Fixture:** isolated profile and two source directories, without model or
  credentials. Only planning executes; no scanner or provider starts.
- **Journey:** request a file through the native secret scanner, attempt a
  study draft, inspect the refusal across six sizes and page to recovery at
  40x12. Return to Options, explicitly select its directory and prepare a new
  three-job, one-worker draft. Exit and repeat the refusal without color.
- **Verify:** unsupported membership publishes no plan; the revised plan pins
  `service` in every job, requires approval and has no admitted work or calls.
- **Judge:** rejection, uncertainty, scope tradeoff and recovery remain readable;
  a revised draft and completed approval are distinct states.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-083800/J77/`
  records 19 machine passes and nine separate screen passes with text/ANSI
  hashes and dimensions. Raw REVIEW_REQUIRED stays unchanged. The earlier
  `082413` run preserves one machine failure and one manual failure caused by
  incorrect exit and paging expectations.
- **Limits:** this proves the refusal and revision route, not the planned
  first-class scope editor, model access isolation, scan quality or complete
  reference interaction parity. Per-engine evidence is in
  [the scope audit](../assessments/discovery-scope-2026-10-05.md).

### J78: Native rule gaps retain observations through Review and restart

- **Fixture:** installed Semgrep with an explicit local rule, one readable
  matching source file and one incompatible rule. Labeled imported context
  is accepted through the TUI. No remote rules, model, proof or patch work runs.
- **Journey:** start one scoped native scan, inspect its partial outcome across
  six sizes, read the engine gap, explicitly acknowledge partial coverage,
  review the retained fixture observation, open Report and restart without color.
- **Verify:** the actual scanner reports an incompatible rule and one observation.
  Authenticated coverage, source identity and selected scope survive restart.
  Selection requires an explicit partial acknowledgement. No new jobs start.
- **Judge:** retained evidence and missing coverage remain distinct, including
  in narrow layouts. Reading, acceptance and return controls match their actions.
- **Limits:** this exercises a local rule and an explicit rule omission, not
  useful default rule coverage or scanner precision. Unreadable source identity
  still blocks discovery. Fatal engine errors and cancellation need further
  retention work. Native engines do not consume the accepted threat model;
  this journey does not certify accepted-context isolation or a report export.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-101159/J78/`
  records 25 machine passes and 10 separate passing screen judgments at all six
  sizes, actual 40x12 paging, explicit selection and a fresh no-color restart.
  `manual-review.json` retains dimensions and text/ANSI/native hashes. The raw
  `REVIEW_REQUIRED` report and earlier failed runs remain unchanged.

### J79: Standalone partial Semgrep through selection and restart

- **Fixture:** installed Semgrep with explicit local rules and one labeled
  observation. One incompatible rule creates a real omission. One whole-repository
  job runs with an isolated home and no model calls or remote rule selectors.
- **Journey:** inspect the partial result at six sizes, page the concrete
  omission at 40x12, explicitly acknowledge it, review the observation, open
  Report and recover Scan after actual exit and a no-color restart.
- **Verify:** partial envelope and findings lifecycle agree. Authenticated
  source identity, retained observation and acknowledgement survive restart.
  No additional scan is created. DAG metadata is not credited as prerequisite
  execution.
- **Judge:** the actual omitted rule is readable before acceptance, controls
  match their actions, and review completeness remains distinct from coverage.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-105209/J79/`
  records 22 machine passes and nine separate passing screen judgments.
  Text/ANSI/native hashes and actual dimensions are in `manual-review.json`.
  Raw `REVIEW_REQUIRED`, recipe failures and their separate judgments remain.
- **Limits:** no useful default rule, precision, CodeQL execution, accepted
  context inheritance or report export claim. Source-drift ledger settlement,
  cancellation, scoped standalone target membership and full interface parity
  need further evidence.

### J80: Failed and canceled native plans retain observations

- **Fixture:** two separately initiated three-scope plans. Installed Semgrep
  analyzes scope a using an explicit labeled local rule; b is a labeled failure
  or cancellation seam, and c must never run. No model calls or remote rules.
- **Journey:** inspect failed evidence across six sizes, page the omitted scope
  at 40x12, open the retained observation, explicitly initiate the second plan,
  cancel it with Ctrl+C, open Report and recover after actual no-color restart.
- **Verify:** failed/canceled ledger status, authenticated source identity,
  retained count, stage delta and fixed native job dispositions agree. Each
  plan invokes a/b only; neither is selected as completed. Both attempts persist.
- **Judge:** pending-result paging reads evidence without accepting it, failure
  and cancellation are distinct, retained observations remain unverified, and
  Report discloses stopped work without a complete coverage claim.
- **Evidence:** `/tmp/kuzushi-bounded-investigations-tui/20261005-120452/J80/`
  records 20 machine passes and 12 separately judged passing captures. Actual
  dimensions and text/ANSI/native hashes are in `manual-review.json`. Raw
  REVIEW_REQUIRED and failed predecessors remain unchanged.
- **Limits:** local installed-scanner evidence plus a labeled stop seam does not
  certify useful defaults, precision, live models, accepted-context inheritance,
  native resource limits or standalone aborts. The fixture is unversioned;
  Git SHA transitions, older-run navigation, human decisions and export are not
  exercised by this journey. Full reference interaction parity remains open.


## J81: Scope review, acceptance and changed source

Persona: an operator dividing a repository before approving scan work. Run
sequentially with the native binary and no provider credentials. Build inventory
explicitly, inspect all six viewport sizes, split into named scopes while
preserving a loose root file, rename, read concrete file membership, acknowledge
inventory limitations and accept boundaries. Change fixture source, attempt an
edit, and inspect the retained form and unchanged accepted revision. Exit and
restart with no color, then reopen the durable scope review.

Machine assertions authenticate saved revision numbers and exact memberships,
require no campaign plans or provider/work reservations, and require live
alternate-screen captures. Judgment checks cover reading controls, visible
editing actions, multiline field ownership, source disclosure and narrow-terminal
craft. This journey does not validate AI proposals, scan compilation, context
inheritance, real provider spending, or fixed/future findings. The fixture has an
unborn Git repository, so unavailable SHA remains explicit. It is content-drift
evidence, not Git SHA transition evidence.


## J82: Responsive scope locks and explicit recovery

Run the native TUI sequentially against a labeled filesystem fixture with a
300-level directory chain and 128 empty sibling directories. A separate bounded
Python process holds the real inventory lock, then the real strategy ledger lock.
The operator explicitly creates inventory and refreshes history, resizes to
40x12, cancels each wait, releases each holder and retries. Machine assertions
verify a live lock-holder PID, running/canceled module receipts, an unchanged
proposal queue, a whole-repository draft and no scan plans or provider/work
reservations. Screen judgments cover responsive cancellation, honest active
states, retained boundaries and explicit retry. This is local source-metadata
work, not scanner or live model validation. It does not prove every platform,
wall-clock bound for blocked filesystem calls, million-entry performance, or
end-to-end scoped study execution.


## J84: Study engine choices and recovery

Run sequentially with an isolated home and no provider credentials. Begin with
accepted source inventory and imported labeled context, then open a study from
one accepted boundary. Inspect inherited automatic selection, reject an
unsupported model engine, read at all six viewport sizes and reach the final
resource guidance at 40x12. Apply one native engine, paste multiline input,
cancel a second edit, and prepare three fixed jobs without approving or starting
them. Exit the process, restart with no color, reopen the saved campaign and
apply identical choices. The saved plan must remain unchanged.

Judge scope explanations, visible reading position, input ownership, reversible
choices and restart honesty. Fixture checks require one saved study, three
unstarted jobs, exact scope membership and no provider/work reservations.

Evidence: `/tmp/kuzushi-bounded-investigations-tui/20261005-180208/J84/` records
29 machine passes and eight separate passing screen judgments. The raw report
remains `REVIEW_REQUIRED`; `manual-review.json` retains text/ANSI/native hashes,
actual dimensions and limits. Failed runs at `174109`, `175448` and `175737`
retain their driver and reading defects. No discovery or model request runs.
This does not certify scanner usefulness, resource ceilings, live model behavior,
Git SHA comparisons, multi-scope execution or full reference interaction parity.
See the [selector assessment](../assessments/study-engine-selector-2026-10-05.md).


## J86: Expired OAuth refuses inference

Use an isolated home with explicitly labeled expired OAuth credentials and an
offline refresh transport. Run one approved context job through real prepared
dispatch. The refresh stub rejects authentication; the bridge must stop before
inference and retain one failed work attempt, zero provider reservations and the
same eight-call allowance with two protected review calls.

Inspect the context result at all six sizes. It must show the recorded
authentication cause, requested output rather than an unenforced token ceiling,
source/plan identity and unconsumed calls. Page to final recovery guidance at
40x12, confirm exit when the initial planning choices are unsaved, then restart
without color and reopen the same result. Recovery starts no new work.

Evidence: `/tmp/kuzushi-bounded-investigations-tui/20261005-191951/J86/` records
23 machine passes and five separate passing screen judgments. Raw
`REVIEW_REQUIRED` remains. `manual-review.json` includes text/ANSI/native hashes,
actual dimensions and bridge source hash. Failed predecessors retain driver
phrase/exit mistakes and the real missing-failure-reason defect. This is an
offline auth-failure test; it does not certify live model quality or quota use.
See the [OAuth recovery assessment](../assessments/oauth-preflight-context-recovery-2026-10-05.md).

## J87: Scoped study filter recovery

The accepted scope picker starts a study over saved global filters. The engine
picker names the conflict and exposes local clear/apply/cancel actions. Cancel
restores the prior study; apply retains accounting and creates a new finite
draft. Six sizes, actual narrow paging, exit and no-color restart are covered.

Evidence: `/tmp/kuzushi-bounded-investigations-tui/20261005-194110/J87/` records
28 machine checks and five separate passing screen judgments. Global options
remain byte-for-byte unchanged, the exact three jobs are retained and no scan
or model request starts. Raw `REVIEW_REQUIRED` remains. Earlier failed host-home
checks and clipped small-screen controls are retained in the recovery assessment.


## J88: One optional scope proposal

Review the inventory, preserve multiline operator priorities and accepted context,
then approve one model job under a shared allowance. An intercepted, labeled
response exercises the real executor without live inference. Review and accept
the resulting boundaries separately; the next three-pass scan draft retains the
proposal expense and requires its own approval. Inspect six terminal sizes,
actual paging, cancellation of model selection, exit and no-color restart.

Machine checks cover immutable source membership, existing exclusions, unchanged
global context, one request and no discovery. Judge visible controls, boundary
acceptance and honest spending separately. This does not establish live model
usefulness or complete monorepo execution.

## J89: Recorded live OAuth failures and bounded work

Use an existing live validation target through `KUZUSHI_DEVEX_TARGET`. Read its
failed context job, incomplete three-pass campaign and shared allowance in the
native TUI. No inference or discovery is launched by this journey. Confirm that
failures, source identity, consumed requests, protected Review calls and unknown
dollar usage survive actual exit and no-color restart. Host checks compare the
source bytes and durable reservations before and after. Missing live evidence
fails setup instead of substituting a synthetic run.


J88 final evidence: `/tmp/kuzushi-bounded-investigations-tui/20261005-215320/J88/`.
35 machine checks and seven passing screen judgments; raw `REVIEW_REQUIRED`
remains. The response is intercepted and grouping synthetic. No discovery runs.
See the [scope proposal assessment](../assessments/ai-scope-proposal-2026-10-05.md).

J89 final evidence: `/tmp/kuzushi-bounded-investigations-tui/20261005-215745/J89/`.
21 machine checks and five passing screen judgments; raw `REVIEW_REQUIRED`
remains. Existing live receipts survive actual exit and no-color restart with
unchanged source bytes and ledger counts. The live workflow itself is partial.
See the [live test assessment](../assessments/live-oauth-bounded-validation-2026-10-05.md).


## J90: Rejected context output stays inspectable and unaccepted

Run one approved source-only context job with two explicitly intercepted invalid
responses. Retain the bounded diagnostic in its own run, keep ordinary failure
text redacted, and inspect it only through the displayed control. Exercise the
read-only surface at six viewport sizes, including actual narrow paging.
Acceptance, launch and new-draft keys must be inert while reading. Exit and
restart without color, read the same diagnostic and verify unchanged source,
two request reservations, one work attempt and no accepted context. Missing
or corrupted evidence must remain unavailable. This is an offline rejection
journey and does not establish live model quality.

J90 evidence: `/tmp/kuzushi-bounded-investigations-tui/20261005-230615/J90/`
records thirty machine passes and five separate passing screen judgments.
Raw `REVIEW_REQUIRED` remains. Changed recorded input produces an inspectable
unavailable state without revealing unauthenticated model text. Host checks
retain two intercepted requests, one attempt, unchanged source and no accepted
context. Failed predecessors remain in the
[diagnostic assessment](../assessments/rejected-context-output-2026-10-05.md).

## J91: Historical usage and spending tradeoffs

Execute a bounded offline scan with intercepted transport and synthetic
observations, then inspect one completed pass as usage evidence for a new
three-job plan. Requests remain visible without dollar pricing. Compare the
projection with net available scan calls, preserve protected Review capacity,
read all terms and cancel approval. No future job should start. Verify six
sizes, actual 40x12 paging, real exit and no-color restart of the frozen basis.

Evidence: `/tmp/kuzushi-bounded-investigations-tui/20261006-005118/J91/` has
18 machine passes and five separate passing screen judgments. Raw
`REVIEW_REQUIRED` remains. Four intercepted requests and one allowance revision
stay unchanged; the selected pass records two requests, all three future jobs
stay unstarted and source bytes remain unchanged. Failed cold-start, unsupported
dispatcher and driver predecessors remain in the
[resource assessment](../assessments/study-resource-preview-2026-10-06.md).


## J92: Bounded usage history and older baseline recovery

Inspect an explicitly selected older baseline outside a 100-record recent
choice window. Read exact usage and uncertain projections without new work.
Break its metadata, refresh, restore it and refresh again while preserving the
selection, draft and spending. Complete narrow paging, cancel approval, exit
and restart without color. The fixture history is explicitly synthetic; model
transport is intercepted and no live inference occurs.

Evidence: `/tmp/kuzushi-bounded-investigations-tui/20261006-014637/J92/` records
23 machine passes and five passing separate screen judgments, with raw
`REVIEW_REQUIRED` preserved. All six sizes were inspected; 40x12 reaches 44/44.
The earlier `20261006-014014/J92` retains a failing screen judgment for hidden
refresh controls and path-led error copy. The final screen exposes reload at
every width and retry before diagnostic detail. Four intercepted requests, one
approval revision and zero future starts remain unchanged.

## J93: Real Map artifacts and source framework facts

Build context, extract routes and create a partial deterministic Map through the
real prepared CLI dispatch with no model runtime. The labeled source fixture
contains Flask and FastAPI routes and is never executed. Inspect the persisted
DFD, its partial qualification and the entry-point source frameworks. Read all
evidence at six sizes, page to the actual 40x12 tail, exit and restart without
color. Source bytes and zero provider consumption must remain unchanged.

Evidence: `/tmp/kuzushi-bounded-investigations-tui/20261006-034301/J93/` records
21 machine passes and five separate passing screen judgments, with raw
`REVIEW_REQUIRED` retained. The 40x12 detail reaches rows 54-55/55. The first
run's wrong initial-page expectation and the second run's failing narrow-screen
judgment remain recorded. Standalone artifacts stay unaccepted across restart;
the compact overview puts source evidence before complete pageable provenance.
The earlier successful reading and acceptance captures remain too. See the
[Map functionality assessment](../assessments/map-module-functionality-2026-10-06.md)
for hashes, verification and remaining acceptance limits.

## J94: Existing context, partial Map acceptance and exact study inheritance

Produce a real partial deterministic Map and a separately active imported
context through CLI dispatch. Inspect the first exact revision, review its Map
without regeneration, acknowledge partial evidence and draft three one-worker
jobs. Retain the active second context. Read all six sizes, page the 40x12 tail,
exit and restart without color. No study is approved, no source is executed and
no provider call occurs.

Evidence: `/tmp/kuzushi-bounded-investigations-tui/20261006-050744/J94/` records
18 machine passes and five separate passing screen judgments. Raw
`REVIEW_REQUIRED` remains. Narrow paging reaches 51/51. Earlier missing
qualification, wrong study-row capture and premature result capture remain
recorded. The final wait requires the real acknowledgement control, and host
checks retain accepted partial Map, exact draft context, unchanged source and
active context, and zero provider work. See the
[context handoff assessment](../assessments/existing-context-map-2026-10-06.md)
for native hashes and remaining acceptance limits.

## J96: Actual OAuth context, inspection origin and Map acceptance

Inspect the completed diagnostic on the owned live source fixture with a
credential-free home. Navigate the exact DFD, read its full small-screen detail,
return to the saved result, accept Map explicitly and restart without color.
No new model or scan work may start. This is a stateful acceptance test; do not
reset the selected Map or its spending to replay pending assertions.

Evidence: `/tmp/kuzushi-experiment-main-20261006/tui/20261006-113921/J96/` records
21 machine passes and seven separate passing screen judgments. Raw
`REVIEW_REQUIRED` remains. Seven live requests, five work attempts and two
protected Review requests remain unchanged. All six sizes and actual detail
paging to 40-45/45 are covered. Earlier fixture/driver failures and the lost
inspection-origin defect remain recorded. See the
[live context assessment](../assessments/live-context-validation-2026-10-06.md)
for identities, limitations and the unapproved three-pass follow-up.

## J97: Accepted context, repository index and readable Summary

Read J96's already accepted exact revision without credentials or new work.
Distinguish absent optional repository index from accepted threat model, read the
full system description at wide sizes, and verify fresh-session accounting.
At 40x12, Page Up stays at the start, Page Down reads contiguous rows, Page Up
returns exactly and arrows reveal component identity. Resize and restart
without color while preserving source, acceptance and investigation spending.

Evidence: `/tmp/kuzushi-experiment-main-20261006/tui/20261006-131153/J97/` has
32 machine passes and six separate passing screen judgments, with raw
`REVIEW_REQUIRED` unchanged. All six sizes are inspected. Earlier resize,
narrow-reader and session-accounting failures remain recorded. Seven requests,
five attempts, revision-three allowance and two protected Review requests remain
unchanged. See the
[reader assessment](../assessments/accepted-context-reading-2026-10-06.md).

## J98: Decision source and later revisions

Use a credential-free, labeled synthetic finding with two real captured source
versions and synthetic commit metadata. Retain the human decision on source A
despite a later imported assessment. Read the decision/later source warning at
all six sizes, reveal hidden detail with Enter at 60 columns and page
contiguously at 40x12. Explicitly defer against source B with a reason, restart
without color and verify all three decisions, source bytes and original metadata
are retained. No scanner, provider call or source execution occurs.

Evidence: `/tmp/kuzushi-experiment-main-20261006/tui/20261006-144339/J98/`
has 26 machine passes and four separate passing screen judgments. Raw
`REVIEW_REQUIRED` remains unchanged. Failed predecessors retain their failures.
See the [source provenance assessment](../assessments/review-source-provenance-2026-10-06.md)
for the real store regressions, narrow-opening fix and synthetic-evidence limits.

## J99: Capability recovery and input ownership

Read selected model/input preparation, retain the full recovery command and
move/load/back controls across six sizes, and load a command without executing
it. The draft must own editing and remove the Enter-load cue. Restart without
color under an isolated synthetic unsupported model and inspect its diagnostic
route. Finally browse without a target: Enter must reopen explicit target
selection, preserving the absence of consent. No executor or provider runs.

Evidence: `/tmp/kuzushi-experiment-main-20261006/tui/20261006-152837/J99/`
records 39 machine passes and six separate passing screen judgments. Raw
`REVIEW_REQUIRED` remains. Failed and incomplete predecessor reviews remain
recorded. See the
[capability recovery assessment](../assessments/capability-recovery-guidance-2026-10-06.md).

## J100: Source reassessment and causal Review completion

Use the labeled synthetic decision-source fixture and shift the older projection
display date to 2099 while keeping its event provenance intact. Retain the old
verdict, label the row for reassessment and keep NEXT in Review on later source.
Read all six viewport sizes and page the detail contiguously at 40x12. Explicitly
defer against source B with a reason; the recorded event order must govern despite
the old future display date. Restart without color and compare export, all three
decisions, source bytes and earlier provenance. No provider, scanner or source
program runs.

Evidence: `/tmp/kuzushi-experiment-main-20261006/tui/20261006-164751/J100/`
records 24 machine passes and four separate passing screen judgments. Raw
`REVIEW_REQUIRED` remains. The preceding `162338` run retains its failed screen
review for the misleading compact `open` label. This verifies synthetic source
and clock behavior, with an actual findings store and captured file versions;
real Git transitions and scanner precision remain open. See the
[Review completion assessment](../assessments/review-source-completion-2026-10-06.md).

## J101: Large Review ledger and global filtering

Use the prepared labeled 1,000-finding fixture and six bounded external decision
writes. Read loaded/matching counts at all six sizes, sample key-to-echo latency,
retain draft ownership, expose the global filter shortcut at 40x12, retrieve an
omitted row through the canonical filter, then restart without color. Source and
observations remain unchanged. No model, scanner or target source runs.

Evidence: `/tmp/kuzushi-experiment-main-20261006/tui/20261006-175449/J101/`
records 29 machine passes and five separate passing screen judgments. Raw
`REVIEW_REQUIRED` and predecessor failures remain intact. See the
[large-ledger assessment](../assessments/large-review-ledger-2026-10-06.md)
for measured costs, limits and remaining responsiveness work.

## J95: Accepted scope in the study report

Accept a whole-repository scope with one operator exclusion through real
`pack:scopes` dispatch. Plan a three-pass, one-worker study from that boundary,
approve its allowance and run the three offline `secret-scan` jobs. Without any
refresh key, the completed Scan must appear as a result to select. Read the
Report boundary and its provenance at all six sizes, export JSON, restart
without color and export again. Move the accepted scope evidence aside and
confirm that study export is blocked while workspace history, naming every run,
remains an explicit choice. Finally change an unrelated source file: Report must
still show the earlier study, labeled as recorded on earlier source, export it,
and the Scan page must show the same attempt as earlier-source history. Source
is labeled and never executed; no provider call occurs.

Evidence: `/tmp/kuzushi-bounded-investigations-tui/20261006-101326/J95/` records
55 machine passes and nine passing screen judgments. Raw `REVIEW_REQUIRED`
remains. Run `20261006-061350` keeps the original failing source-change
judgment, and earlier runs keep their journey-script failures. See the
[report scope assessment](../assessments/report-scope-2026-10-06.md).


## J102: Complete Review ledger paging

Uses the existing labeled 1,000-finding fixture. Navigate both 500-row windows,
open the omitted finding by its whole-ledger alias, return through both pages,
inspect all six viewports, preserve a tiny-terminal draft, change the global
query and restart without color. Source hashes and observation/decision counts
must remain unchanged; opening details can record normal review-session history.
No scanner, provider or target-source execution occurs. Read every ask capture
and all detail-focused resize frames. Hidden controls, subset alias resolution,
wrong exact drafts or page/query mismatches fail the UX audit even if substring
machine checks pass. The harness remains unchanged. See the
[complete paging assessment](../assessments/complete-review-paging-2026-10-06.md).

## J103: Manual decision saves and input ownership

Uses the owned labeled 1,000-finding fixture for eight explicit human decisions
on one identity. Inspect saving versus recorded state, drafts at all six sizes,
rail identity, false-positive reversal and no-color restart. Six bounded 2-second
SQLite locks expose real pending commits without changing rows. The verifier checks
exact verdict/reason/author order, source hashes, unchanged observations and
bounded decision-count growth. Read every ask and related pending/draft frame.
Do not infer responsiveness from a completed save alone. No scanner, provider
or target-source execution occurs. The harness remains unchanged. See the
[manual decision assessment](../assessments/manual-decision-responsiveness-2026-10-06.md).

## J104: Filtered Review navigation and external decisions

Uses the owned labeled 1,000-finding fixture to open an identity outside a
one-row query. Inspect detail, action target, filter disclosure, draft ownership
and list navigation across six sizes. Two explicit synthetic human decisions
through the real CLI remove a row from an open-only query while the TUI runs.
Passive refresh must recover once with a notice; explicit invalid anchors and
cursors remain errors. Restart in no-color and verify exact decisions, unchanged
observations and source hashes. Read every ask and related resize capture.
No scanner, provider or target-source execution occurs. The driver stays unchanged.

## J105: Exact context editing, copy review and study binding

Imports two labeled contexts through real shared dispatch, edits the inactive
one through the native TUI and reviews the actual text changes before saving.
Inspect multiline Unicode input, retained draft/cursor, all six sizes, the
copy boundary and its new unverified state. Saving must preserve both original
objects, their metadata, the active pointer and compatibility mirror. Inspection
and study selection remain separate. Compile a three-pass draft bound to the
new exact reference and recover it after a real no-color restart. No jobs,
model requests or target-source execution run. Read every ask and related frame;
the fixture oracle verifies exact text, parent/copy references and durable
consumer binding. Keep raw failures and review-required status separate from
manual judgments. The driver stays unchanged.

## J106: Exact context source checks and historical source binding

Imports two labeled contexts, creates an inactive edited copy, and checks that
exact copy through shared dispatch in the native TUI. Review the action menu at
all six sizes, including reaching its final action at 40x12. Saving must retain
original objects, active context, source binding and mirror; inspection and
study selection remain separate. Compile an unapproved three-pass draft, then
change fixture content at the same SHA and make an empty fixture commit with
identical original content. Both changes must stop another check without
publishing a revision or rebinding history. A fresh no-color process recovers
the exact historical revision and unchanged unstarted draft. No jobs, model
requests or target-source execution run. Inspect every ask and related frame,
preserve raw results and use the fixture oracle for source/store claims.

## J112: Discovery allowance exhaustion and partial recovery

Run a fixed nine-job matrix against owned greeting source with intercepted
transport. Approve four calls, including two protected review calls. Two
discovery passes complete; the remaining seven must stay unstarted when
discovery capacity reaches zero. Reopening without another allowance must not
consume an attempt. Inspect saved limits, acknowledge partial evidence and
open a faithful scoped report. Restart without color, then explicitly review
and approve eleven total calls with the same protected allocation. Finish only
the original remaining jobs and inspect the complete report. Provider output
is labeled synthetic, every fetch is intercepted and no target source executes.
Read every ask and related capture; retain raw failures and review-required
status separately from screen judgments. Cancellation is a separate next
check. The driver stays unchanged.

## J111: Completed matrix handoff and explicit Scan acceptance

Generate fresh owned, labeled synthetic matrix receipts with nine completed
jobs, then recover them through the native dispatcher. Run recovery twice and
verify that it creates one unselected Scan
attempt, preserves the exact nine run references and starts no children or
provider requests. The labeled fixture explicitly skips Map; it does not claim
an accepted Map. Use the Scan result in Navigate mode, then open the ordinary
Report surface and check separate case recurrence and the shared allowance.
Inspect controls at narrow sizes and restart in no-color. Source, accepted
contexts, job attempts and provider accounting remain unchanged. No provider
transport runs. An initial archive-copy attempt failed because artifact paths
still named the original target; preserve that failure rather than rebinding
the historical receipts. Read every ask and related capture. Preserve raw failures and
review-required status separately from manual judgments. The driver stays
unchanged. Partial outcomes and source drift also have focused core tests;
this native journey covers completed-work recovery only.

## J108: Explicit context candidate, shared spending and historical comparison

Runs three Alpha baseline passes through the native SAST executor, then uses
the TUI to select and separately approve three Beta candidate passes while Gamma
remains globally active. The greeting source is owned and never executed; all
provider transport is intercepted and observations are labeled synthetic.
Before drafting, hide and restore the fixture's allowance table. Inspect the
read failure, work block and explicit retry without replacing the spending
account or losing commitments. Review comparison conditions at all six sizes,
including the final page at 40x12, and the unchanged eight-call allowance with
two protected review calls. Select actual candidate passes, compare source and
exact context receipts, and return to the same selected pass. Restart in no-color
and recover completed jobs and six committed intercepted requests. Read every
ask and related capture; preserve raw failures and review-required status. The
driver stays unchanged. This is one historical baseline pass versus fixed
candidate repetitions, not full matrix, live quality or complete investigation
acceptance.

## J113: Cooperative campaign Stop and reservation recovery

Launch a fixed nine-job matrix on owned greeting source with intercepted model
transport. One pass completes and the second request waits. Request Stop from
its visible deck control, preserve the composer draft and let the dispatcher
settle children and queue state without blocking the shell. Check that the
remaining seven jobs never start, the completed observation survives and the
in-flight reservation remains unresolved. Inspect the partial Scan receipt,
report, narrow layout and no-color restart. The synthetic transport has a
ninety-second ceiling; no live provider request or target-source execution runs.
Read every ask and related capture. Keep raw failures and review-required status
separate from manual screen judgments. The driver stays unchanged.

## J114: Reversible relationship review and independent finding verdicts

Import two labeled synthetic observations on owned greeting data and perform
one native dedupe request through intercepted transport. Review the proposed
relationship, refuse an empty reason, paste a multiline note at 40x12, accept
and explicitly unlink it. Read the recorded runs through paging. Check two
unchanged observations/identities, no rekeys and no finding verdicts throughout.
Inspect JSON, JSONL, SARIF, Markdown and CSV outputs, then recover the removed
relationship in no-color without another model request. Follow this reader's
advertised Escape control; the generic Navigate helper assumes `Esc prompt`
and is unsuitable here. Read every ask and related text/ANSI capture. Keep raw
failures and REVIEW_REQUIRED separate from manual verdicts. The driver stays
unchanged. This is metadata/control evidence, not live finding quality or
complete grouped Review and learning acceptance.

## J115: Complete grouped Review and exact member navigation

Import sixty-five labeled observations on owned greeting data. One intercepted
dedupe request proposes sixty-three links; shared prepared commands accept them
as grouping metadata. Check two groups with sixty-five original findings, page
all sixty-four duplicate members, read a selected member at 40x12 and open its
exact generation in ordinary Review. Return with `G`, unlink that member's
relationship with a reason, refresh stale grouping and recover three groups in
no-color. No finding verdict, rekey, new scan job or live provider request is
permitted. Read every ask and related text/ANSI capture. Keep raw failures and
REVIEW_REQUIRED separate from manual judgments. The driver is unchanged.

## J116: Selected run history and displayed observations

Record three labeled observations of one owned greeting. Select the middle
observation's parent Scan receipt. Grouped Review must show one finding,
explicitly distinguish selected history from its latest displayed observation,
and retain that distinction when opening a member, returning and restarting.
Read both identities at 40x12 through paging and inspect no-color recovery.
The real ledger, authenticated receipt reader and prepared group dispatch run
without a model. The fixture records no finding verdict or rekey and executes
no source. Keep raw REVIEW_REQUIRED separate from manual judgments.

## J117: Bounded atomic relationship review

Record four labeled greeting observations and three duplicate proposals.
Explicitly select the page, inspect each captured pair, require a reason and
preview the final confirmation before any write. Read the receipt at 40x12.
Accept the selection in one event, then attempt a held unlink batch after a
separate review changes one relationship. The entire stale batch must refuse.
Cancel, clear, refresh and review a fresh selection before unlinking it.
No-color restart must retain all observations and reviewed relationships.
The real writer, prepared dispatch and TUI run without a provider or source
execution. Read every ask and related text/ANSI capture; raw review status
remains separate from the manual judgment.

## J126: Exact agentic discovery with inherited context

Use owned source files and an accepted boundary with one discovery file and one
shared context file. Inspect the frozen three-pass, one-worker plan before
starting it. The native OAuth bridge uses intercepted transport and returns
two model turns per pass. It must read the shared context, refuse an unapproved
file, mount only Read/LS/Glob/Grep, and retain observations outside discovery
without importing them into the findings ledger. Inspect recurrence, a human
FP decision, allowance accounting, detailed Report at six terminal sizes, and
no-color restart. Six calls are approved within an eight-call allowance with
two protected for Review. No live inference, accepted Map, source execution,
recursive jobs, or SHA transition is demonstrated by this fixture. Read every
ask and authenticated text/ANSI capture. Preserve raw REVIEW_REQUIRED status
separately from implementation judgments. The driver stays unchanged.

## J127: Operator-selected finite scope study

Mark two accepted discovery boundaries in the scope tree. Open one study,
choose the constrained agentic engine, inspect the selected workload, set an
eight-call shared allowance with two protected for Review, and approve exactly
six jobs. Run three fresh passes per boundary on owned source with fully
intercepted transport. Check per-scope three-pass recurrence, the unplanned
integration boundary, durable human decisions, Report at six sizes, and
no-color restart. No live inference, accepted Map, source execution, recursive
work, SHA transition or scanner precision claim is supported. Read every ask
and authenticated capture. Preserve raw harness status separately from scoped
implementation judgments. The driver stays unchanged.

## J128: Per-boundary context associations

Select two accepted boundaries and open Source and context. Inspect an exact
revision, edit an inactive copy for one boundary, inspect and select that copy,
and explicitly omit context for the sibling. Check the common context, original
objects and sources stay unchanged. Review six viewport sizes, prepare and
approve the six-job draft with an eight-call allowance and two protected Review
calls, then restore inheritance for the overridden boundary. Check that the
new plan requires separate approval and retains the original accounting.
Restart without color and inspect the restored exact references and source
provenance. No jobs, model requests or source execution are performed. Read
each ask and authenticated capture; preserve the raw human-review status.

## J129: Accepted file-group context generation

Mark two accepted boundaries, including a group with disjoint paths. Preserve
an explicit sibling context omission while planning one bounded context
synthesis for the selected group. Review the model, source, inheritance and
shared allowance at six sizes. Approve one context job and run the real native
executor with fully intercepted transport. Check that only selected discovery
and shared-context excerpts reach the request, with no tools or repair call.
Restart without color, recover the result and the full scope draft, inspect its
DFD and source identity, and explicitly associate the revision with one boundary.
Prepare the six-job discovery draft and prove it is still unapproved and
unstarted, with shared spending and sibling omission intact. No live inference,
source execution or scanner-quality claim is supported. Read each ask and
authenticated capture separately from the machine checks.

## J130: Nine-boundary allowance halt and explicit resume

Prepare eight primary boundaries and one explicitly enabled shared discovery
boundary, with three fresh passes each and one worker. Approve four provider
calls with two protected for Review. Run two owned intercepted requests, verify
that 25 jobs remain unstarted, and refuse resume under the exhausted allowance.
Inspect the ninth boundary and frozen contexts at all six terminal sizes.
Acknowledge the partial result, inspect Report, and restart without color.
Explicitly approve a 29-call ceiling for the same 27 jobs, then resume the
remaining work. Bounded observation checkpoints watch the same dispatcher;
they neither retry work nor extend its allowance. Confirm three observations
per boundary and two protected Review calls still available. Preserve raw
human-review status. No live inference or source execution is performed.

## J131: Nine-boundary Stop and interrupted accounting

Launch the same 27-job plan with owned intercepted transport. Keep the second
request waiting, invoke the visible Stop action, and type a composer draft
while cancellation settles. Verify transport children exit, one pass completed,
one attempt interrupted, and 25 jobs remain unstarted. Preserve both committed
calls and the unresolved active reservation. Inspect the partial result and
Report, restart without color, and prove recovery launches no work. Machine
input latency checks and separately read captures establish only the observed
fixture behavior. They do not establish reference parity, live model quality,
or complete monorepo coverage. The journey driver stays unchanged.

## J132: Complete job identity and narrow Report reading

Use the owned halted nine-boundary plan. Navigate to the final integration
trial after restoring the cleared composer draft with Ctrl+_. Resize through
all six sizes and verify the
selected job remains distinct, with paused-work controls still visible. Open
the partial Report, page its entire 40x12 projection, and verify every boundary
can be read. Confirm source, fixed jobs and committed calls remain unchanged.
All transport is intercepted; this reader regression starts no further work.
Read both human questions independently from machine substring checks.

## J133: Per-case historical spending scenarios

Run six native jobs over two owned discovery boundaries with fully intercepted
transport. Keep integration discovery unplanned while its shared file provides
context. Prepare a second six-job plan using the first study as explicit usage
evidence. Verify three matched complete samples per case, a six-request
historical scenario, and unavailable dollar cost. Inspect the selectable prior
study and cancel across all six terminal sizes. Review a proposed 14-call
allowance beside six prior commitments, two protected Review calls and six
remaining discovery calls. Cancel approval, restart without color and inspect
the same frozen evidence. Assert no additional model requests or jobs started.
Read the four human questions and authenticated captures separately from raw
machine checks. The harness driver stays unchanged.

## J134: Cold prior-study history and failure recovery

Create owned prior receipts with six intercepted requests, 150 unstarted study
copies and one malformed record. Open the scope tree, mark two boundaries and
choose Usage evidence without visiting Campaign. Verify direct background
history loading, explicit selection, the retained prior study and partial-history
disclosure across all six sizes, including actual 40x12 paging. Temporarily make
the owned history directory unreadable as a directory, refresh, inspect the
failure with the previous selection retained, restore it and refresh again.
Cancel and select explicitly without approving or starting new jobs. Restart
without color and repeat the cold path. Assert source files and the original
six requests remain unchanged. Read the four human questions separately from
machine checks; raw `REVIEW_REQUIRED` remains unchanged.

## J135: Suppression module contracts and consumers

Import two labeled observations over owned comment-only source, record one
human dismissal, and exercise suppression add, list, remove and expiry through
the native shell. Inspect Review at all six sizes and restart without color.
Shared dispatch must retain both observations and the human decision. Exports
must reflect the managed rule state, and the implicit report must retain the
import analysis rather than an auxiliary review action. Check canonical paging,
missing rule identifiers and unknown options without any scanner, provider
request or source execution. Read the four human questions independently of
the raw machine verdict. The journey driver stays unchanged.

## J136: Bounded preparation inputs and recorded engine facts

Use an owned stalled version-probe fixture to exercise automatic study
preparation failure. Verify the dependency check stops, no plan is published,
and the draft and source remain intact. Wait past the temporary banner expiry
and verify that the failure remains readable until dismissal. Inspect it at six sizes and
expand its narrow reader with z, page its full failure and return to the same
draft. Replace the owned helper with a successful version
probe and create one oversized sparse CPG file; preparation must refuse its
comparison identity before jobs or requests exist. Prepare a new explicit
Semgrep plan only after dismissing the retained failure, using native dispatch
and an owned metadata-only executable. Its limits and navigation must remain intact.
Open its Source panel and inspect its actual recorded path and digest at all
six sizes, including expanded keyboard reading at 40x12 and return to the
original selected setting and scroll. Restart without color, open the selected
section reader again and retain the
same unapproved fixed plan. No scanner or model request is executed. Read
the five human questions separately from machine checks and keep the raw
review status. The journey driver stays unchanged.

## J137: Study Source sections

Prepare an unapproved three-job plan over owned comment-only source using a
metadata-only executable that is never run. Inspect Source Overview without a
raw options document, switch to recorded Inputs, then read complete prepared
Options. Tab and Shift+Tab preserve the selected field, draft and separate
positions; z expands the current view and returns to the form. Inspect all six
sizes, every prepared-option key through 40x12 paging, and no-color restart.
Preparation and view changes start no scanner or model request. The native
receipt, source hash and absence of a queue are authoritative. Read the three
human questions independently of raw REVIEW_REQUIRED. Run sequentially before
the J136 preparation regression; the driver stays unchanged.

## J138: Credential readiness

Use isolated, clearly synthetic OAuth metadata and an owned comment-only target.
Select model-backed Map work without starting it. Inspect an expired token with
a refresh token through Setup, Health and the credential chooser. Remove the
refresh token and verify repair blocks model-backed Setup. Inspect a locally
unexpired token as stored and unverified, then restart without color. All six
sizes must preserve the selected model, credential state and complete recovery
explanation. Confirm exit explicitly for the unsaved test selection. Verify that
source, credential bytes and allowance are unchanged and secret values never
appear in captures. No sign-in, refresh, model request or scanner runs. Read
the five human questions separately from raw REVIEW_REQUIRED; the driver stays
unchanged.


## J164: Compact campaign recovery in a finite native investigation

Use an isolated home and owned inert package/header metadata. Enter normal
Setup, import and accept its supplied context, then approve three license-policy
jobs with one worker and all provider-call capacity protected for Review.
Introduce an inert source comment change and inspect the real dispatcher refusal
at all six viewport sizes. At 40x12, inspect the expanded reader, return to the
composer, retain a draft through navigation and the command palette, then page
through the complete failure. Restore exact source bytes, execute the original
three jobs, review the consolidated policy finding, export and restart without
color. Inspect each judgment separately from machine results. No model request,
credential renewal, source execution, exploitation or vulnerability patching is
part of this journey. The harness stays unchanged.

## J165: Complete Campaign overview and policy receipts

Follow J164's owned finite package-policy investigation with an isolated home,
accepted imported context, three approved one-attempt jobs and one worker.
After real completion, inspect the Campaign overview at all six sizes and page
through the full identity, frozen workers, reported cost, plan policy and
occurrence evidence at 40x12. Preserve visible actions and selected jobs.
Inspect the same overview after no-color restart, then confirm the retained
Review decision and exported report. Judge reading and hierarchy separately
from machine checks. No provider request, real credential renewal, source
execution, exploitation or vulnerability patching occurs. The driver stays
unchanged.

## J166: Finite planning and protected allowance capacity

Seed only owned inert package/header metadata in an isolated home. Use real
shared CLI dispatch to draft three policy jobs and one context-generation job,
approve the exact policy plan, and refuse stale revisions, wrong digests,
invalid limits, unknown options and source drift. Start no jobs or model work.
Inspect allowance through the shell and transcript reader at all six sizes,
including complete 40x12 paging and no-color restart. Show capacity available
outside protected Review/Report and disclose unavailable legacy run evidence.
Verify unchanged source, exact approval, zero observations/reservations/work
attempts/decisions and absent dispatcher queues. Keep genuine Map acceptance
uncreated. Judge the three screen questions separately from machine checks.
