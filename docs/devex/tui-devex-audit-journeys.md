# TUI DevEx Audit Journeys

Scripted developer-experience audits for the Rust Ratatui shell
(`crates/kuzushi-tui`), driven live under **tmux** — the only layer that
exercises the TUI the way an operator does (real keystrokes, real timing, real
onboarding gates) rather than reading pre-rendered buffers.

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

---

## A. Onboarding & first contact

### J1 — Keyless first launch  ⭐ highest priority
- **Persona:** brand-new user, no credentials.
- **Env:** unset `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / etc.; `HOME` → temp
  dir; no existing `.kuzushi`.
- **Launch:** bare `kuzushi` on a real TTY.
- **Journey:** walk the ordered gate **Target → Model → Credentials →
  Planning**. At each step: is the operator told *why* they are stopped, is the
  next action obvious, do Esc and `d` (offline demo) work.
- **Known risk:** broken end-to-end in July; the credential dead-end dumped the
  operator on an empty Workbench instead of the inline credential-entry step.

### J2 — Offline demo path
- **Persona:** evaluator who won't paste a key yet.
- **Launch:** `kuzushi demo`; plus the in-gate `d` offline route.
- **Goal:** reach a real finding with evidence — zero key, zero network.
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
- **Journey:** land on Workbench → `next` (phase rail Map→Hunt→Confirm→Fix) →
  `scan` → wait → `findings` → `open <id>`.
- **Checkpoints:** phase chip (`組 map 1/4`) matches on-disk reality, not a
  fabricated phase; confidence-first sort holds; Confirmed-vs-guess is
  distinguishable.

### J5 — Export the work
- **Continues J4:** `export` / `workspace:export-findings` across
  `json|sarif|csv|markdown-bundle`.
- **Judge:** is the path from "I have findings" to "I have a submittable
  artifact" discoverable without docs?
- **Known risk:** export was uncommitted / orphaned in prior audits.

### J6 — Recon intake
- **Persona:** operator with an amass/httpx/nuclei/nmap export.
- **Goal:** reach `recon:import`.
- **Known risk:** flagged **unreachable (BLOCKER)** in the July devex audit.
  This journey exists to confirm whether an operator can get there at all.

### J7 — Findings triage & dismissal
- **Journey:** walk findings, dismiss a false positive, `suppress` one, record a
  `decision`.
- **Judge:** is dismissal/suppression state honest and durable, and can the
  operator tell a *suppressed* finding from a *gone* one?

## C. Honesty & resilience (capture *during* transitions)

These require captures mid-transition — exactly what static buffer snapshots
cannot see.

### J8 — Interrupt mid-run  ⭐
- **Journey:** start a scan, two-stage `Ctrl+C` mid-flight, immediately capture
  Jobs + Activity.
- **Known risk:** canceled→✓done bug — a killed job rendering as successfully
  completed. Single most important honesty check.

### J9 — Jobs / steer queue
- **Journey:** launch work, open `jobs`, queue a tool, `jobs -k <id>` a scoped
  cancel.
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

### J12 — Activity / viz auto-open
- **Journey:** run a scan; confirm Activity auto-opens; the viz gallery
  (`viz` / `scene`) auto-opens *only* when the artifact has content (no
  empty-page open); Tab through all five viz pages.
- **Judge:** the `empty_hint` guidance on a page with no backing artifact.

### J13 — Deep view tour (broad, shallow)
- **Journey:** cycle every verb-reachable `ShellView` (Catalog, Threat,
  Replay/Trace, Config, Options, KnowledgeBase, Story, History, …), capturing
  each.
- **Judge:** top-bar / footer / status chrome stays truthful per view. This is a
  chrome-truthfulness sweep, deliberately broad; run after the deep journeys.

## E. Responsive & environment matrix

### J14 — Narrow terminal
- **Journey:** re-run J1 and J4 at **60×20** and **80×24**.
- **Exercises:** adaptive-footer wrap (<70 cols) and compact-Workbench collapse.
- **Judge:** findings/detail stay readable; nothing truncates behind chrome.

### J15 — Palette / TERM matrix
- **Journey:** launch under `TERM=xterm-256color` (emulated macOS Terminal) vs.
  truecolor, capturing with `-e`; also `KUZUSHI_THEME=high-contrast` and
  `KUZUSHI_REDUCED_MOTION=1`.
- **Known risk:** truecolor-only palette breaks macOS Terminal.
- **Judge:** legibility, not merely non-crash.

### J16 — Headless / plain parity
- **Journey:** `--plain` and a non-TTY pipe of the same journeys.
- **Judge:** plain output stays useful (no ANSI dependency, no interaction-only
  state) and honors the mode-parity contract in
  `docs/assessments/mode-parity.md`.

---

## Out of scope (manual only)

**Real OAuth login** (`auth login openai` / `auth login anthropic`) is
intentionally excluded from the automated set: completing a real handshake needs
live credentials and a browser round-trip that must not run unattended. Spot-
check it by hand.

## Priority order

1. **J1** keyless first launch, **J8** interrupt honesty — highest value re-runs.
2. J4, J5, J6, J7 — the core task-completion loop.
3. J9, J10, J11, J12 — control surfaces & discoverability.
4. J14, J15, J16 — environment matrix.
5. J13 — broad chrome sweep, last.
