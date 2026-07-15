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
  'cd /Users/operator/vibe-code/Kuzushi && <env> ./target/debug/kuzushi <args>'
tmux capture-pane -t <name> -p      # plain text  → content / honesty audit
tmux capture-pane -t <name> -e -p   # with ANSI    → color / style audit
tmux send-keys   -t <name> <keys>   # real keystrokes: Tab Enter Escape C-c j k, literal text
tmux kill-session -t <name>
```

Knobs:
- `KUZUSHI_REDUCED_MOTION=1` — freeze the spinner for stable content captures
  (leave OFF when auditing motion itself, J15).
- Generous `sleep` after each keystroke — background workers are async.
- Unique session names — independent journeys fan out one-agent-per-journey.
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
- **Journey:** start a scan, two-stage `Ctrl+C` mid-flight, immediately capture
  Run Focus + contextual Jobs.
- **Known risk:** canceled→✓done bug — a killed job rendering as successfully
  completed. Single most important honesty check.
- **Verify:** final cancellation restores the exact launch origin with one
  receipt; manual Run Focus inspection and background-owned work do not
  auto-return or steal focus.

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

---

## Out of scope (manual only)

**Real OAuth login** (`auth login openai` / `auth login anthropic`) is
intentionally excluded from the automated set: completing a real handshake needs
live credentials and a browser round-trip that must not run unattended. Spot-
check it by hand.

## Priority order

1. **J1** keyless first launch, **J8** interrupt honesty — highest value re-runs.
2. J4, J5, J7, J17 — the durable cockpit, reporting, and phase reference.
3. J6, J9, J10, J11, J12 — control surfaces & discoverability.
4. J14, J15, J16 — environment matrix.
5. J13 — broad chrome sweep, last.
