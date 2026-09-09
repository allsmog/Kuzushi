# TUI DevEx Audit Journeys

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
