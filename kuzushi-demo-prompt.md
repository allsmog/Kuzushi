# Kuzushi TUI Demo — Design Prompt

## What you're building

A **scripted, offline TUI demo of Kuzushi** that plays inside a real terminal — not a web page, not a slide, not a video. Build it as a Node + Ink command (`kuzushi demo` or a sibling repo `kuzushi-demo`) that walks through a deterministic, looping operator session showing Kuzushi as a **cybersecurity copilot harness** — the shell where offense, defense, intel, and compliance modules share one workspace and one conversation.

This is for **live conference talks** (the operator already has a RootCon / Kazhackstan slot booked) and for the project's GitHub README — so it must run with a single command on a stranger's laptop, work with no API keys, no internet, no target repo, no `~/.kuzushi/` state, and produce identical output every run. It must also gracefully record to a `.cast` (asciinema) and `.gif` (VHS) so the same script doubles as the marketing artifact.

Audience watching it: senior product security engineers, AppSec leads, red teamers, compliance folks. They have seen Snyk, Semgrep, GitHub Advanced Security, ZAP, Burp. Don't pitch them on "AI security." Pitch them on **"one copilot, one conversation, real artifacts, real terminal."**

## Why TUI and not video / web

- **The product is a TUI.** A video lies; a web mockup lies harder. A TUI demo running in the same terminal as the real product is the most honest shape of the pitch.
- **Conference demos break.** No Wi-Fi, no API key, no target repo, no luck. A pre-scripted TUI runs from a thumb drive.
- **The same script becomes the asciinema / VHS artifact** that ships in the README, with zero divergence between "what you saw on stage" and "what's on the website."
- **It composes.** `kuzushi demo` lives next to `kuzushi shell`, `kuzushi scan`, `kuzushi run` — the pitch becomes "the demo is just another mode of the same harness."

## Product truth (use these facts, do not invent new ones)

**Tagline**: *崩し — Kuzushi — Security-Native AI Operating Environment.*

**One-liner**: *Find the vulnerability. Prove it's exploitable. Deploy a honeypot to detect it. Check if it violates PCI DSS. Generate the patch. One tool, one conversation.*

**Three execution modes** sharing one core (`ModuleRegistry`, `WorkspaceManager`, `MessageBus + DAG Orchestrator`, `AgentRuntime`, SQLite + vector store):
1. **Shell mode** (default `kuzushi`) — interactive Ink TUI copilot. The harness. **This is what the demo plays.**
2. **Scan mode** (`kuzushi scan <repo>`) — headless 40+ task SAST DAG; CI-native; SARIF + JUnit + JSON + JSONL audit log.
3. **Run mode** (`kuzushi run <module:tool>`) — pipe-able single-tool invocation for unix scripting.

**Shell views the demo cycles through** (these are real `ShellView`s in `src/ui/state.ts` — match them):

| Shell view | Enter with | What it shows |
|---|---|---|
| `catalog` | bare `kuzushi` | Loaded modules grouped by **OFFENSE / INTEL / GOVERNANCE / DEFENSE** |
| `module` | `/use <id>` | Per-module home — tools table + last-run summary |
| `module-run` | tool start (auto) | Live transcript: ⏺ tool header, ✓/→/○ steps, evidence tail, actor strip, findings |
| `actor-detail` | press `1..4` from `module-run` | Per-actor full transcript: ● Tool / ⎿ result / ✻ Thinking / ★ Finding |
| `findings` | `/findings` or `/f` | Severity-sorted, chain-aware list with filter chips and `F-NNNN` short IDs |
| `finding` | `/open F-NNNN` | Linear-style deep page: state strip, evidence chain, timeline |
| `tune` | `/tune` or `/t` | Six plain controls + free-text "house rules" (saved to `.kuzushi/house-rules/<moduleId>.md`) |
| `prompts-editor` | `/prompts` | Per-module prompt overrides — `edit/show/diff/reset/set <verb>` |
| `threat-dfd` | `/threats dfd` (or `1`) | ASCII DFD grouped by trust zone |
| `threat-stride` | `/threats stride` (or `2`) | Element × STRIDE heat matrix + impact × likelihood |
| `threat-stories` | `/threats stories` (or `3`) | Attacker narrative cards + input-categories rail |
| `threat-summary` | `/threats summary` (or `5`) | Counts, charts, drives, artifact paths |

**Modules to surface in the catalog** (keep the categories — they are the pitch):

| Module | Category | What it does |
|---|---|---|
| `sast` | offense | 40+ task SAST DAG: Semgrep, CodeQL, agentic detectors, AI triage, verification, PoC, patch |
| `randori` | intel | PASTA threat modeling (S1–S4 + narrative) — produces a `ThreatModelDocument` |
| `vuln-scout` | offense | Whitebox pentest skill pack — agentic SAST + taint, normalized findings |
| `tob` | offense | Trail of Bits skills audit — fp-check, sharp-edges, insecure-defaults, variant-analysis |
| `shinsa` | governance | ISO 27001 Annex A + NIST SP 800-53 Rev 5 with file:line evidence citations |
| `prompt-armor` | offense | LLM red teaming — 80+ attack plugins, 25+ mutation strategies |
| `variant` | offense | Lifts confirmed findings into portable signatures, hunts variants across the repo |
| `ndiff` | offense | CVE-diff n-day hunting and variant search |

**Operator verbs** worth surfacing: `/use`, `/findings`, `/open F-0001`, `/tune`, `/threats stride`, `/plan "<english>"`, `/prompt edit triage`, `/show runs`, `/replay 7f3a`, `/since main`, `/back`. Two-stage Ctrl+C (arms once, exits on second within 2s) is real — surface it once via the demo's footer hint.

**Why-not-just-Claude-Code differentiators** (drop one of these as a muted footer caption between scenes):
- The pipeline and the conversation are the same thing.
- Workspaces persist targets, findings, threat models, compliance state across sessions.
- Every agent response is grounded in your threat model + open findings + compliance gaps.
- Scope policies, engagement audit trails, 4-level autonomy per module.
- 15+ LLM providers including Ollama (airgapped). One install.

## Visual language (match the real product, don't redesign)

- **Reuse the actual Kuzushi UI components where possible.** The demo lives in this repo (or as a sibling) and imports `BannerSplash`, `ModuleCatalog`, `ModuleHome`, `ModuleRunView`, `FindingsView`, `ThreatStrideMatrix`, `TuneView`, `PromptsEditorView`, `ContextStrip`, `RuleHeader`, `KeybindFooter`, `ScreenContent`, `Table`, `Spinner`, `PulseDot`, `ProgressBar` from `src/ui/components/` and `src/ui/primitives/`. Don't re-implement. The demo's job is to feed these components scripted state, not to build a parallel UI.
- **Drive the same `UIStore` the real shell drives.** Construct a `UIStore` in demo mode and let your scene script call `store.update({...})` to advance frames. This guarantees pixel-identical output to the real product. The visual fidelity of the demo == the visual fidelity of the product, by construction.
- **Tokens come from `src/ui/tokens.ts`** — `danger` red (TP/exploitable), `success` green (mitigated), `warn` yellow (needs-review), `info` blue (by-design), `accent` blueBright (file links / PoC), `muted` gray. Honour `KUZUSHI_HIGH_CONTRAST=1` and `NO_COLOR` because the real components already do.
- **Glyphs**: `⏺ ✓ → ○ ● ⎿ ✻ ★ ◆ │ ╭╮╰╯ █▏▎▍▌▋▊▉ ░`. The wordmark is the real `BannerSplash` block-ASCII — don't re-art it.
- **Deterministic clock.** Replace `Date.now()` reads inside the demo with a virtual clock that the scene script ticks. This is the single most important technical detail: without it, frame timing drifts and the asciinema cast is non-reproducible. Pass the clock through the existing `useUiNow()` hook (or wrap it).
- **No animation gimmicks beyond what the real product does.** Spinners tick at the real `<Spinner>` cadence. Progress bars fill at the same `formatProgressBar` rate. The `actors` block pulses via the real `<PulseDot>`. Nothing more.

## Storyboard — the 75-second loop

Six scenes, deterministic, looping. **Total runtime ~75s; auto-loops with a 2s blank fade between iterations.** Each scene is a list of frame descriptors (state diff + dwell time) consumed by the runner.

The terminal title (set via OSC `]0;...`) advances with the scene: `kuzushi demo · catalog`, `… · sast`, `… · scan running`, `… · finding F-0001`, `… · threats`, `… · shinsa`.

### Scene 0 — Splash (0:00–0:04)

Mount `BannerSplash` with `workspace="acme-api"`, `target="./acme-api"`, and a fixed `tip` (don't randomize). Idle prompt visible: `kuzushi> ▌`. Cursor blinks at the real Ink cadence. No input yet.

### Scene 1 — Catalog (0:04–0:14)

Type `modules` into the input buffer at ~30 chars/sec. Press Enter. `shellView → catalog`. Render `ModuleCatalog` with the eight built-in modules grouped exactly as the table above, plus an `EXTERNAL` row for `@kuzushi/augur` to prove the loader works. The `DEFENSE` group renders empty with a muted `(roadmap: honeypot, yokai)` line. Footer: `use <id>  findings  ?  Ctrl+C exit`.

### Scene 2 — Focus a module + plan (0:14–0:32)

Type `/use sast`. Prompt rewrites to `kuzushi/sast>`. `shellView → module`. Render `ModuleHome` with the real tools-table rows from the actual `sast` module's `toolSummaries` (don't fabricate names — load them from the registry). Last-run row shows `never run for this workspace`.

Then type `/plan run harder, focus on auth, stop wasting money`. Render the real `PlanCard` with this diff state:

```
PLAN (haiku · 1.4s · $0.0008)
  preset:        standard   →  deep
  focus:         (none)     →  auth, authz, session
  cost cap:      $5.00      →  $1.50
  verify:        false      →  true

  Reasoning: "harder" lifts the preset, "auth" narrows tasks,
  "stop wasting money" caps the budget below the standard ceiling.

  [y] apply   [n / Esc] discard
```

Simulated keypress `y` collapses the card.

### Scene 3 — Run + live transcript (0:32–0:58) — **the money shot**

Type `scan`. Mode flips to `running` and `shellView → module-run`. Render the real `ModuleRunView` with scripted `moduleRun.steps`, `evidenceTail`, and `findings` updates. The script feeds the store frames like:

```
t=0.0s   step "context.build"   status running
t=1.2s   step "context.build"   status done · "node 22 · express 4 · pg 8"
t=1.2s   step "semgrep.scan"    status running
t=3.5s   step "semgrep.scan"    status done · "38 candidates · 2.3s"
t=3.5s   step "codeql.scan"     status running
t=15.3s  step "codeql.scan"     status done · "14 candidates · 11.8s"
…
t=18.0s  step "triage.run"      status running   progress 0/23
t=18.4s  step "triage.run"      progress 1/23   finding F-0001 appended
t=18.7s  step "triage.run"      progress 2/23   finding F-0002 appended
…
t=24.6s  step "triage.run"      progress 23/23  status done
t=24.6s  step "verify.finding"  status running  progress 0/3
```

The `actors` block is populated with three threat-hunt actors (`AUTH-01 active`, `SESSION-02 queued`, `UPLOAD-03 queued`); `AUTH-01` shows two scripted activity lines (`✓ Read src/api/auth/login.ts`, `→ grep "rate.?limit"`) via the real `agentActivity` map.

Findings list ends at:

```
F-0001  CRITICAL  ssrf      webhook.ts:91   tp 0.92  $0.0041
F-0002  HIGH      idor      users.ts:47     tp 0.87  $0.0033
F-0003  HIGH      brute     login.ts:23     tp 0.84  $0.0029
```

End the scene when `verify.finding` hits `→ 1/3` — don't play it out further.

### Scene 4 — Open a finding (0:58–1:10)

Type `/open F-0001`. `shellView → finding`. Render the linear-style deep page populated from a fixture finding:

```
kuzushi/sast/finding/F-0001                     critical · exploitable
─────────────────────────────────────────────────────────────────
SSRF in webhook integration handler                  cwe-918  ·  T1190

  state          confirmed_tp   verified   patch_proposed
  fingerprint    f1a2b3c4…      alias F-0001
  cost           $0.0041 triage  +  $0.012 verify

  evidence
    src/services/webhook.ts:91
        const r = await axios.get(req.body.url)
                                  ^^^^^^^^^^^^
        attacker-controlled URL → axios.get → no allowlist

    chain
      req.body.url   →   validateUrl()  [bypassable: only checks https://]
                     →   axios.get(url)
                     →   169.254.169.254/latest/meta-data/

  proof of exploit  (verified · sandbox)
    $ curl -X POST http://localhost:3000/api/integrations/webhook \
        -d '{"url":"http://169.254.169.254/latest/meta-data/iam/"}'
    HTTP/1.1 200 OK
    {"role":"acme-api-prod","accessKeyId":"AKIA…"}    ← IMDS leak

  proposed patch         (auto-patch · validated · re-scanned clean)
    + import { isAllowedWebhookHost } from "../security/allowlist"
    + if (!isAllowedWebhookHost(req.body.url)) return res.status(400)…

  timeline
    0:42  detected by agentic-sast
    0:48  triaged tp · sonnet 4.6
    1:03  verified · poc executed in docker sandbox
    1:11  patched · acme-api re-scanned clean
```

Footer: `e edit  ·  p apply patch  ·  s mark safe  ·  /back`.

### Scene 5 — Threats pivot (1:10–1:18)

Type `/threats stride`. `shellView → threat-stride`. Render the real `ThreatStrideMatrix` populated from `.kuzushi/threat-model.json` fixture (ship one in `demo/fixtures/`). Cells fill row by row over ~2s using the existing component — no custom animation; the script just nudges `shell.threatModel` step by step.

### Scene 6 — Governance punchline (1:18–1:24)

Type `/use shinsa` then `nist-quick-check ac-3`. Render a single Shinsa control-result card:

```
NIST SP 800-53 · AC-3 Access Enforcement                 ⚠ partial
  evidence
    src/api/users.ts:47    no ownership check  (linked: F-0002)
    src/middleware/auth.ts:12  rbac present
  gap → finding F-0002 already tracked
```

Hold for 3 seconds. Render an overlay caption in muted text under the footer: *"one finding from offense — one control gap in governance — same workspace."*

Fade for 2s, restart from Scene 0.

## Demo player controls (real, not cosmetic)

The runner registers these keybinds with the existing `useKeybindings()` hook so they show up in the real `KeybindFooter` exactly like every other Kuzushi screen:

| Key | What it does |
|---|---|
| `space` | Pause / resume the scene clock |
| `←` / `→` | Step to previous / next scene boundary |
| `r` | Restart from Scene 0 |
| `1`–`6` | Jump directly to scene N |
| `s` | Toggle "speaker notes" overlay (a small panel with the talking points for the current scene) |
| `c` | Toggle high-contrast mode (sets `KUZUSHI_HIGH_CONTRAST=1` for this run) |
| `q` / `Ctrl+C` | Exit |

The speaker-notes overlay is the conference-talk killer feature: a 4–6 line muted block at the bottom that tells the presenter what to say while the scene plays. Notes live next to the scene scripts in `demo/scenes/<scene>.notes.md` so they're version-controlled.

## CLI surface

```sh
kuzushi demo                       # play the full loop
kuzushi demo --scene 4             # jump straight to a scene (debug / rehearsal)
kuzushi demo --speed 0.5           # 0.25x..2x clock multiplier; default 1.0
kuzushi demo --no-loop             # play once and exit
kuzushi demo --speaker-notes       # start with the notes overlay open
kuzushi demo --record cast.json    # write an asciinema v2 cast to disk and exit on loop
kuzushi demo --record-vhs demo.tape # emit a VHS tape file you can `vhs render` into a gif
kuzushi demo --plain               # disable Ink, write the same scenes line-per-event
                                   # (sanity check for log capture; not for the talk)
```

`--record` is a dry pass: drives the same scene script against a captured `stdout` writer, deterministic clock, fixed terminal size (120×40). Output is committed at `assets/demo.cast` and rendered to `assets/demo.gif` via the `vhs` CI step. The README's hero `<img>` points at the GIF; the asciinema embed points at the cast.

## Technical specs

- **Stack**: Node 22+, TypeScript, Ink 5, React 18 — same as the real product. Drop the demo under `src/demo/` so it ships in the existing `kuzushi` binary as a subcommand. No second package, no second build, no second toolchain.
- **State**: one `UIStore` instance per run. The scene script is a pure `(store, clock) => void` array; each entry pushes a state diff and an optional `await clock.tick(ms)`. No external animation library. No `setInterval` outside the clock.
- **Determinism**:
  - Virtual clock the script ticks; replaces `Date.now()` reads via the existing `useUiNow()` indirection.
  - Fixed terminal size (`process.stdout.columns = 120`, `rows = 40`) when `--record` is set, so casts are reproducible.
  - All `Math.random()` removed — every "random" choice (banner tip, finding fingerprints) is seeded from the scene index.
  - Spinner / pulse cadence honour the virtual clock so frame N at speed=1.0 looks identical run to run.
- **Offline**: no network calls anywhere in demo mode. Runtime guards: when `--demo` is active, set `process.env.KUZUSHI_OFFLINE=1` and assert no `fetch` / agent runtime calls are made. Add a vitest test that runs the full scene script with the network stubbed and fails if anything tries to call out.
- **Fixtures live in `src/demo/fixtures/`**:
  - `module-catalog.json` — eight modules with descriptions
  - `sast-tools.json` — sast module's tool summaries
  - `threat-model.json` — randori output for Scene 5
  - `finding-F-0001.json` — fixture for Scene 4
  - `shinsa-ac-3.json` — control-result card for Scene 6
  - `actor-activity.jsonl` — per-frame activity lines for the threat-hunt actors
- **Tests**: `tests/demo/scenes.test.ts` plays each scene and asserts on the rendered frame text via `ink-testing-library`. Snapshot the final frame of each scene under `tests/demo/__snapshots__/`. CI fails if a UI change drifts the demo output.
- **Performance**: cold start under 500ms on an M-series Mac. Each frame render under 16ms (the existing components already satisfy this; the demo just shouldn't break it).
- **Accessibility**:
  - Honours `NO_COLOR` and `KUZUSHI_HIGH_CONTRAST=1` because the underlying components do.
  - When `process.stdout.isTTY` is false, fall back to the existing `plain-renderer.ts` path so `kuzushi demo | tee transcript.log` produces something useful.
  - `--speaker-notes` provides a screen-reader-friendly transcript track.

## Tone

- Imperative, technical, slightly cocky. *"Find it. Prove it. Patch it. Govern it."*
- Numbers stay concrete: `40+ task DAG`, `8 modules`, `15+ providers`, `4-level autonomy`. No rounding to "many."
- No "revolutionary," no "next-generation," no "AI-powered" as a descriptor. Use the actual mechanics: *"Claude Agent SDK runtime"*, *"DAG orchestrator"*, *"PASTA threat modeling"*.
- One Japanese flourish only — the 崩し glyph in the splash. Nothing more.

## Out of scope — do not add

- A web page, video, gif-only artifact (those are downstream from `--record`, not the deliverable).
- A real LLM call anywhere in the demo path.
- Any reference to roadmap modules (`blackbox`, `pwn`, `pentest`, `honeypot`, `yokai`, `revgraph`) as if they shipped — `VISION.md` is explicit that they're aspirational. One muted "(roadmap)" line in the catalog is the only mention.
- Support for resizing the terminal mid-record. The demo locks to 120×40 when recording.
- An interactive "play your own" mode where the operator types real input. The demo plays a script. Real interactivity is `kuzushi shell`.

## Deliverables

1. `src/demo/` — the scene runner (`runner.ts`), the deterministic clock (`clock.ts`), the scenes (`scenes/scene-0.ts` … `scenes/scene-6.ts`), and the fixtures (`fixtures/*.json`).
2. `src/cli/demo.ts` — the `kuzushi demo` subcommand wired into the existing CLI router with the flags above.
3. `tests/demo/scenes.test.ts` — per-scene snapshot tests using the existing testing setup.
4. `assets/demo.cast` and `assets/demo.gif` — committed recordings produced by `pnpm demo:record`.
5. A `pnpm demo`, `pnpm demo:record`, and `pnpm demo:render` script in `package.json`.
6. A six-line update to `README.md`'s hero block: replace any current screenshot with the GIF and an asciinema embed link.

Build it. Don't ask clarifying questions unless something here directly contradicts itself.
