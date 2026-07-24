# Blueprint: kuzushi-tui target architecture (no-compat rewrite)

Status: proposal. The retired unified-event sketch's `JobHub` design is
kept as the effect runtime's job component, while run activity now enters
through the typed lifecycle. Scope: `crates/kuzushi-tui` internals only —
the CLI entry, `kuzushi-core` dispatch boundary, `.kuzushi` artifacts,
and plain-mode output contracts are unchanged.

## Shape: Model – Update – Effect – View (TEA, in plain Rust)

No framework dependency (no tui-realm, no ECS, no tokio). Four layers
with one-way data flow:

```
crossterm events ─┐
JobHub events ────┼─→ Msg ─→ update(&mut Model, Msg) -> Vec<Effect> ─→ EffectRuntime
tick ─────────────┘              (pure, no IO)                          (spawns workers,
                                                                         fs, clipboard,
        Model ──→ view models ──→ ratatui Frame / plain lines            emits new Msgs)
```

The repo is already halfway there: reducers exist
(`app/state_transitions`, `app/reducers`), view models are pure
(`ui_view_models`), and `LiveRunEvent` proves the unified-event idea.
The rewrite makes the remaining implicit structure explicit and deletes
the god struct.

## 1. One `Msg` type — every state change has exactly one entry point

```rust
enum Msg {
    Term(TermEvent),        // Key / Paste / Mouse / Resize
    Tick(Instant),          // spinner, scene spin, ETA refresh
    Job(ShellEvent),        // Trace/Scan/Tool/Agent/Plan/Threat (see jobhub blueprint)
    Cmd(Command),           // parsed operator verb (typed line, palette, hotkey)
}
```

Key handling, command routing, and background-event application stop
being three separate mutation paths into `ShellApp`; they all become
`Msg` producers. The terminal loop shrinks to: collect Msgs → update →
run effects → redraw if changed.

## 2. `Model`: the god struct becomes a composition of owned sub-models

```rust
struct Model {
    session: Session,       // config, registry, option_store, model/auth state,
                            // cost, budget, target, scope, target_kind
    editor: LineEditor,     // input, cursor, history, completion, Ctrl+R search
    router: Router,         // view stack — see §3
    jobs: JobStatus,        // read-model of JobHub slots (running/label/abort)
    domain: DomainCache,    // findings, review decisions, chains, taint_flow,
                            // recon/carlini/sast snapshots, activity session
    engagement: Engagement, // workflow phase, planning queue/overrides/failures,
                            // pending chain/plan/patch, approvals + allow/denylists
    ui: UiPrefs,            // auto_open_activity, auto_open_viz, depth_stack,
                            // reduced motion, spinner phase
}
```

Rules:
- Every field lives in exactly one sub-model; no `pub` reach-through.
  Sub-model updates take `&mut SubModel` (+ explicitly passed
  collaborators), not `&mut Model`.
- `DomainCache` is read-only for views. Only effects (job results,
  store reloads) write it.
- The ~20 planning fields (`planning_*`) become one `Engagement` type
  with its own module, update fn, and tests — it is currently the
  largest hidden object in `ShellApp`.

## 3. `Router`: view state lives *in* the view variant

Today `ShellView` is a bare enum and every view's cursor/scroll/filter
is a loose field on `ShellApp` (`findings_cursor`, `help_scroll`,
`tools_filter`, `kb_scroll`, `story_return_view`,
`file_picker_return_view`, ...). Instead:

```rust
enum Route {
    Workbench(WorkbenchModel),   // focus, page, center mode, scroll, nav, cache
    Activity(ActivityModel),     // pane focus, verbose, paused, scroll
    Scene(SceneModel),           // page, spin, pitch, paused
    Findings(ListModel<FindingId>),
    Help(ScrollFilterModel),
    Picker(PickerModel),         // target / file / planning / model / auth
    // ...one variant per surface, each owning ALL its ephemeral state
}

struct Router {
    stack: Vec<Route>,           // bounded; `back` = pop
}
```

Consequences:
- `back` restores scroll/cursor/filter for free — the state travels
  with the stack entry. All `*_return_view` hacks and `prev_shell_view`
  are deleted.
- A view's keymap is `impl Route { fn on_key(&mut self, ...) -> Vec<Effect> }`
  next to its model — no more giant key-dispatch match over every
  view's foreign fields.
- Adding a view = one variant + one model + one view fn. Nothing added
  to a shared struct.

## 4. `update` is pure; side effects are data

```rust
fn update(model: &mut Model, msg: Msg) -> Vec<Effect>;

enum Effect {
    StartJob(JobSpec),           // tool run, scan, agent ask, plan, threat patch
    CancelJob(JobKind),
    ReloadFindings,              // FindingStore read
    ExportFindings(ExportSpec),
    PersistOption { key: String, value: String },
    OpenArtifact(PathBuf),
    Quit,
}
```

The `EffectRuntime` (owns `JobHub`, store handles, fs access) executes
effects and feeds results back as `Msg::Job(...)` / `Msg::Cmd(...)`.

Why this is the load-bearing decision: today reducers spawn threads,
read disk, and mutate view state in one function, so testing any
transition drags in the world. With effects-as-data, the entire
command surface is table-testable — `update(model, Cmd(Scan)) ==
[StartJob(scan_spec)]` with zero threads, zero tempdirs. This is also
what the CRAP gate keeps asking for: branchy logic with no side
effects.

## 5. Jobs: the `JobHub` blueprint, unchanged

Single `ShellEvent` channel, per-`JobKind` generation slots,
`JobTicket` + `PanicGuard` instead of disconnect inference. It slots in
as the `EffectRuntime`'s job component; `Model.jobs` is a plain
read-model the runtime refreshes (running flags, labels, abort state),
so views never touch channels.

## 6. View layer: keep what exists

`ui_view_models` (Model → render DTOs) and the ratatui/plain renderer
pair are already the right boundary. They change only in *input* —
reading from `Model`/`Route` sub-models instead of 150 loose fields.
Plain-mode parity rules from CLAUDE.md apply unchanged: every Route
renders to lines.

## What is deliberately NOT in the target

- **No async runtime.** Sync mpsc + tick drain is correct for a TUI;
  tokio adds Send bounds and select loops for zero user-visible gain.
- **No trait-object component framework.** Enum-of-models with match is
  more honest than `Box<dyn Component>` — exhaustiveness checks beat
  dynamic dispatch here.
- **No event sourcing / undo log.** Nothing in the product needs replay
  of UI state; run replay already works off `.kuzushi` artifacts.

## Rewrite order (no compat shims, each step compiles + tests green)

1. **Jobs + Msg loop** — land `JobHub`/`ShellEvent`, convert the
   terminal loop to the single Msg pipeline. Deletes
   `runtime_event_drains.rs` and 21+ plumbing fields.
2. **Effects** — introduce `Effect` + `EffectRuntime`; convert command
   handlers to return effects instead of spawning/IO inline. Reducer
   tests become pure table tests.
3. **Router** — `ShellView` → `Route(state)`, move every `*_scroll` /
   `*_cursor` / `*_filter` / `*_return_view` field into its variant.
   Rewrite key dispatch as per-Route handlers.
4. **Model split** — extract `Session`, `Engagement`, `DomainCache`,
   `UiPrefs`; delete `ShellApp`, rename the aggregate `Model`.
5. **Sweep** — `ui_view_models` signatures take sub-models; kill
   remaining `pub(crate)` reach-through; update
   `docs/assessments/mode-parity.md`.

Order matters: 1–2 make 3–4 mechanical (state moves stop touching
side-effectful code). The 9k-line `app/tests.rs` gets carved up
alongside each phase — tests move next to the sub-model they protect.
