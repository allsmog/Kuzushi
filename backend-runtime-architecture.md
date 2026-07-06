# Backend Runtime Architecture (Sanitized)

> **Scope.** This is a read-only architecture description of the backend runtime
> core of a Rust workspace. It describes the system purely as an asynchronous,
> single-process distributed system: how work is scheduled, how execution
> frames are produced and routed, how background producers reach a foreground
> loop, how in-memory runtime state is organized, and how state is serialized
> to the local disk. Product-specific, domain-specific, and framework-specific
> identifiers have been generalized. No remediation steps are proposed; this
> document identifies invariants, risks, and open questions only.

The workspace is split into two crates that matter here:

- `crates/<core-crate>` — the runtime engine: scheduling/concurrency, execution
  frame emission, and local disk serialization.
- `crates/<ui-crate>` — the foreground process: the polling loop, the
  state-routing bridges, and the local state matrix.

---

## 1. Asynchronous multi-step state machines

Work in the backend is modeled as **asynchronous multi-step state machines**.
A unit of work is started by a foreground command, advanced on a
thread-backed task producer, and observed by the foreground loop through a
channel. Each machine has an explicit lifecycle — *queued → active → done*, plus
two off-ramps: *stop-requested → stopped*, and a *terminal exception branch*.

### 1.1 How work is started, advanced, completed, stopped, or failed

A background unit of work is launched by a foreground handler that:

1. spawns a thread-backed task producer,
2. installs the receiving end of an in-process channel onto the foreground
   state object (as an `Option<Receiver<…>>`),
3. installs a stop-request handle (a cancellation token) alongside it, and
4. seeds the **local state matrix** with an initial machine in its *queued*
   state.

The producer advances the machine by emitting progress events and, at the end,
exactly one terminal event. Terminal states are represented by dedicated event
variants, e.g. a staged batch job emits:

```rust
enum StagedJobEvent {
    Stage(String),                 // advance: a named transition
    Finished { run_id, count, cost_usd },   // terminal: success
    Failed   { error: String },             // terminal: exception branch
}
```

and a single-frame job emits:

```rust
enum FrameJobEvent {
    Finished { name: String, result: serde_json::Value }, // terminal: success
    Failed   { name: String, error: String },             // terminal: exception
}
```

The foreground loop applies each event to its local state. A *Finished* event
drives the machine to its *done* state and applies the serialized result;
a *Failed* event drives it through the **terminal exception branch**, which
synthesizes a terminal execution frame carrying an elevated severity marker so
the failure is visible in the same feed as normal progress.

### 1.2 How state transitions are represented

Every long-running machine has three coordinated pieces of state:

- a **liveness flag** on the foreground state object (`running: bool`, or an
  `Option<name>` that is `Some` while active),
- an **installed receiver** (`Option<Receiver<…>>`), and
- an **installed stop-request handle** (`Option<CancelToken>`).

Transitions are never implicit: the terminal event handler clears the liveness
flag *before* the receiver is torn down (see §3.4). Transitions in the local
state matrix are enforced through a monotonic per-row state enum (§4.2) whose
terminal states are irreversible.

### 1.3 How terminal states propagate

A terminal event propagates in a fixed order within a single drain pass:

1. the event is dequeued from the channel,
2. the handler records a **serialized local runtime state** entry (run record)
   to disk,
3. the handler applies side effects (result caching, derived-output caching),
4. the handler flips the corresponding local-state-matrix row to its terminal
   state, and
5. after all events are applied, a teardown check observes the now-cleared
   liveness flag and drops the receiver and stop-request handle.

This ordering is the core invariant of the lifecycle: **liveness is cleared by
the event handler, and receiver teardown only reacts to that cleared flag.**

---

## 2. Immutable frame-processing runtime

The runtime's observability substrate is an **immutable frame-processing
runtime**. Every meaningful transition inside a running machine produces one
**immutable execution frame**. Frames are append-only, numbered, optionally
parented, and fanned out to two consumers: an **append-only frame log** on disk
and an in-memory consumer in the foreground loop.

### 2.1 The immutable frame type

Frames are values of a single cloneable, serializable struct (schema **v2**).
All fields are owned; there are no references, so a frame can be cheaply cloned
and shipped across a channel:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ExecutionFrame {          // canonical immutable frame
    n: usize,                    // monotonic frame number
    kind: String,                // category ("reasoning", "progress", "done", "refused", …)
    label: String,               // human-readable label
    latency_ms: Option<u64>,
    cost_usd: Option<f64>,
    module_id: Option<String>,   // owning subsystem namespace
    verb: Option<String>,        // action within the subsystem
    parent_step: Option<usize>,  // parent frame number (child linkage)
    severity: Option<String>,
    started_at_ms: Option<u64>,
    model: Option<String>,       // opaque capability-key metadata
    provider: Option<String>,
    prompt_hash: Option<String>, // FNV1a hash of the call inputs
}
```

The v2 fields (`module_id`, `verb`, `parent_step`, `severity`, `started_at_ms`,
and the last three metadata fields) are all optional, keeping the on-disk format
backward-compatible with a v1 frame log.

### 2.2 The frame builder and `.emit()` semantics

Frames are constructed through a short-lived builder that borrows a handle:

```rust
struct FrameBuilder<'a> { handle: &'a FrameHandle, step: Option<ExecutionFrame> }
```

The builder exposes chainable setters (`with_latency_ms`, `with_cost_usd`,
`with_severity`, `with_capability_metadata`, `with_label`). `.emit()` consumes
the builder, assigns the frame number inside the handle's emission critical
section, hands the frame to the sink via `sink.record(&frame)`, and returns the
assigned frame number. A `Drop` impl guarantees **auto-emit on drop**: if a
builder is dropped without an explicit `.emit()`, it still attempts to record
the frame. This prevents builder-local loss; foreground delivery remains
best-effort when the UI receiver has already been torn down (§2.3), while disk
append failures are counted and warned by `JsonlSink`.

### 2.3 The frame sink abstraction

Routing is behind one trait:

```rust
trait FrameSink: Send + Sync {
    fn record(&self, frame: &ExecutionFrame);
    fn run_artifact_location(&self) -> Option<(PathBuf, String)> { None }
}
```

Two implementors compose:

- **`JsonlSink`** — the **local persistence boundary**. `record` appends the
  frame to the append-only frame log and counts append failures in an
  `AtomicU64`; a failed append warns to stderr rather than panicking.
- **`BroadcastSink`** — a decorator holding `Arc<dyn FrameSink>` plus a
  `Sender<ExecutionFrame>`. Its `record` first delegates to the inner sink
  (durable append), then `send(frame.clone())` into the channel toward the
  foreground; a dropped receiver is ignored (`let _ = …`). This is the
  fan-out point of the **concurrent state-routing bridge** (§3). A dropped
  receiver can still miss foreground frames, but the durable append has already
  happened before the send attempt.

### 2.4 Append-only frame log

The append routine (`append_run_trace_step`) writes one JSON object per line:

```rust
let _guard = trace_append_lock(&path).lock();          // per-path serialization
let mut line = serde_json::to_string(frame)?; line.push('\n');
let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
file.write_all(line.as_bytes())?;                      // one write_all per line
```

There is **no buffering and no persistent file handle** — the file is opened,
one line is written, and it is closed on each frame. A process-wide
`OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>>` registry hands out one lock
per log path, so concurrent in-process appenders cannot interleave/torn-write a
JSONL line. Physical line order is append order. For `TraceHandle` producers,
semantic `n` order is made to match that append order by the handle-level
number+record emission lock (§2.5). Lower-level direct append helpers preserve
record framing but depend on their caller-supplied `n` values.

### 2.5 Frame numbering

Frame numbers are monotonic and assigned from a shared `Arc<AtomicUsize>`:

```rust
let _guard = self.inner.emit_lock.lock();
let n = self.inner.counter.fetch_add(1, Ordering::Relaxed) + 1;
step.n = n;
self.inner.sink.record(&step);
```

The counter and emission lock are registered per log path in an
`OnceLock<Mutex<HashMap<PathBuf, SharedTraceState>>>`, so every
`TraceHandle::jsonl` root that targets the same log shares one counter and one
number+record critical section. On first use the counter is **seeded from disk**
by scanning the existing log for the highest `n`, which makes numbering
continuous across process restarts that resume the same run.

### 2.6 Parent/child frame relationships

Parenting is resolved from three sources, in priority order:

1. an explicit `parent_step` field carried on the handle (set by
   `FrameHandle::child(parent)`),
2. a **task-local** parent (`task_local!` value installed by an async scope
   guard `with_parent_step`), which survives `.await` points and executor
   thread hops, and
3. a **thread-local** parent stack (`RefCell<Vec<usize>>`) pushed/popped by a
   synchronous RAII guard `parent_scope`.

An RAII "parent scope" guard groups a region of child frames under one parent
frame number; the async task-local form is the one safe to use across
`.await`, while the thread-local stack form is a synchronous-only fallback.

### 2.7 Wrapping blocking calls into frame-producing transitions

Blocking capability invocations are wrapped by a decorator runtime,
`FramedRuntime<'a>`, holding `inner: &'a dyn Runtime` and a `FrameHandle`. Each
wrapped blocking method becomes a **runtime frame transition**: it captures a
start `Instant`, records a "start" frame, calls through to `inner`, then records
a terminal frame carrying the measured `latency_ms` and, when present,
`cost_usd`. On the error path it records a frame with `kind = "refused"` and an
elevated severity. This means producers do **not** hand-log per-call frames; the
wrapper auto-emits them for every blocking call it fronts.

---

## 3. Concurrent state-routing bridges

Background producers never touch foreground state directly. They communicate
through **concurrent state-routing bridges**: `std::sync::mpsc` channels drained
by the **foreground polling loop**, turning progress events into local state
mutations and, in turn, redraws.

### 3.1 The foreground polling loop

The loop is a straightforward `while !should_quit { step }`:

```rust
fn foreground_loop(term, app) -> Result<()> {
    let mut state = ForegroundLoopState::default();     // { needs_redraw: bool }
    while !app.should_quit { foreground_step(term, app, &mut state)?; }
    Ok(())
}

fn foreground_step(term, app, state) -> Result<()> {
    refresh_redraw_state(term, app, state)?;            // drain + conditional draw
    state.needs_redraw |= poll_input_event(app)?;       // input with timeout
    Ok(())
}
```

`ForegroundLoopState` carries a single dirty flag, `needs_redraw`, initialized
`true` so the first frame always paints.

### 3.2 Redraw state

`refresh_redraw_state` runs a three-stage pipeline each iteration:

```rust
state.needs_redraw |= background_changed(app);          // tick + drains + view sync
state.needs_redraw |= clear_after_external_output(term, app)?;
state.needs_redraw  = draw_if_needed(term, app, state.needs_redraw)?; // returns false
```

`background_changed` ORs together three `bool`-returning mutators — a time tick
(spinner/animation/expiry), the **state-routing bridge** drain, and a view-sync
step. `draw_if_needed` renders only when the dirty flag is set and then resets
it to `false` for the next iteration. Render is never called from an event
handler; the dirty flag is the sole redraw trigger.

### 3.3 Input polling with an adaptive timeout

Input polling uses a timed poll then a blocking read:

```rust
if !event::poll(input_timeout(app))? { return Ok(false); }
apply_input_event(app, event::read()?)                  // one event per pass
```

The timeout is adaptive to how much redraw pressure exists: ~50 ms when an
animation is running, ~80 ms when background work is active, and ~250 ms when
idle. A poll timeout returns `false` and skips the read, which still lets the
next loop pass drain background events — so the loop makes progress on state
even with no input.

### 3.4 Draining multiple receivers in one pass

The bridge drains every installed receiver in a fixed sequence and ORs the
results:

```rust
fn drain_background_events(&mut self) -> bool {
    let mut changed = self.drain_staged_job_events();
    changed |= self.drain_frame_job_events();
    changed |= self.drain_delegated_call_events();
    changed |= self.drain_plan_events();
    changed |= self.drain_derived_output_events();
    changed |= self.drain_frame_events();               // execution frames
    changed
}
```

Each drain follows the same shape: **collect** every currently available item
with non-blocking `try_recv()` into a `Vec`, preserving whether the channel ended
as `Empty` or `Disconnected`; **apply** the buffered events in order; then run a
**teardown/disconnect check**. Draining is independent per channel and provides
no cross-channel ordering guarantee.

The frame-event drain is the in-memory consumer of §2.3's `BroadcastSink`: it
routes each `ExecutionFrame` into the session object's `apply_step` (§4).

### 3.5 How receiver teardown is decided

Teardown is driven by two signals: the machine's **liveness flag** and the
channel's connection state. Each drain first collects buffered events, applies
them, and then nulls the receiver and stop-request handle once the machine's
liveness flag has been cleared by the event handler, e.g.:

```rust
if self.tool_running.is_none() { self.tool_rx = None; self.tool_cancel = None; }
if !self.planner_running        { self.plan_rx = None; self.plan_cancel = None; }
```

A disconnected sender ends the `try_recv` loop with any buffered items already
collected. If the corresponding liveness flag is still set after those buffered
items are applied, the drain synthesizes the machine's existing `Failed` event
variant and routes it through the same terminal handler. That gives panic/kill
failures an off-ramp instead of leaving an Active row with a dead receiver. The
trace-frame receiver is kept while any background work is still live and is
closed after its channel disconnects.

### 3.6 How state changes trigger redraws

The chain is: producer `send` → next loop pass calls `background_changed` →
`drain_background_events` dequeues and applies (mutating the local state
matrix) → the drain returns `true` → `needs_redraw |= true` → `draw_if_needed`
repaints. Input events follow the parallel path through `poll_input_event`.
Both funnel into the single dirty flag.

---

## 4. Local state matrix

Foreground runtime state lives in a **local state matrix** centered on a
session object. It holds the set of running machines, the selected/focused
machine, a bounded live frame feed, per-task progress rows, and aggregated
rollups for hidden subsystems.

### 4.1 The session state object

```rust
struct RuntimeSession {
    run_id: String,
    started_at: Instant,
    tasks: BTreeMap<String, TaskRow>,          // keyed by "module_id:verb"
    step_task_ids: BTreeMap<usize, String>,    // frame number -> owning task
    subsystem_aggregate: SubsystemAggregate,   // hidden-subsystem rollup
    events: VecDeque<RecordedFrame>,           // ring-buffered feed (cap 2000)
    focus_task: Option<String>,
    pane_focus: PaneFocus,
    verbose_subsystems: bool,
    paused: bool,
    feed_scroll: usize, task_scroll: usize, task_cursor: usize,
    deck_page: DeckPage, deck_cursor: usize, deck_page_pinned_by_user: bool,
    paused_event_count: Option<usize>,
    feed_auto_tail: bool,
}
```

The fields that must stay mutually consistent are `tasks` (the authoritative
per-machine state), `step_task_ids` (the frame-number→task index used to roll
child frames onto their owning task row), `subsystem_aggregate` (a derived
rollup that must track the hidden tasks it summarizes), and the paired
scroll/pin fields that govern whether the feed auto-tails.

### 4.2 Task-row lifecycle and states

Each machine is a `TaskRow` whose lifecycle is a monotonic enum:

```rust
enum TaskState { Queued, Active, Done, Failing, Canceled, Skipped }

struct TaskRow {
    task_id, module_id, depends_on: Vec<String>,
    state: TaskState,
    started_at: Option<Instant>, completed_at: Option<Instant>,
    steps_done: usize, cost_usd: f64,
    last_label: String, severity: Option<String>,
    details: Vec<TaskDetail>,      // nested sub-steps, capped
}
```

Transitions: *Queued → Active* on the first non-terminal frame; *Active →
Failing* on `severity = "danger"` or `kind = "refused"`; *Queued/Active → Done*
on `kind = "done"`; *Queued/Active → Canceled* on a stop request. **Terminal
states (Done, Failing, Canceled, Skipped) are irreversible**, and a late
completion arriving after a cancel is explicitly guarded so a Canceled row stays
Canceled. Nested `TaskDetail` sub-steps carry their own smaller state enum
(`Active, Done, Failing, Canceled`).

### 4.3 Ring-buffered frame feed

The live feed is a `VecDeque<RecordedFrame>` bounded to a fixed capacity
(2000). On each applied frame:

```rust
if self.events.len() >= FEED_RING_CAPACITY { self.events.pop_front(); }
self.events.push_back(RecordedFrame { step: frame, observed_at: Instant::now() });
```

Eviction is FIFO. Critically, **per-task aggregates (`steps_done`, `cost_usd`,
`last_label`) live on the task row, not in the feed**, so they survive ring-
buffer eviction — the feed can forget an old frame while its contribution to the
task totals persists.

### 4.4 Hidden subsystem aggregation

Frames from hidden subsystems (a small allow-listed set of internal namespaces)
do not each get their own task row. They collapse into one `SubsystemAggregate`:

```rust
struct SubsystemAggregate {
    active_count: usize, total_count: usize,
    last_label: String, state: TaskState,
    hidden_task_states: BTreeMap<String, TaskState>,
}
```

The aggregate's rolled-up `state` is computed from all hidden task states with a
severity-priority rule (*Failing > Canceled > Active > Queued/Done*). Unless a
verbose toggle is set, the matrix presents these as a single collapsed row.

### 4.5 Staged-job-to-frame bridge

A staged batch job reports progress as opaque stage strings rather than frames.
A dedicated bridge translates each stage into the frame/task model: it parses a
"running &lt;engine&gt;" stage into a synthetic frame
(`kind = "tool"`, module/verb resolved from a seeded task row or a fallback
`engine:run`), and a "persisting" stage marks still-active tasks *Done*. This
is how a producer that predates the frame model still participates in the same
local state matrix.

### 4.6 Worker-start, completion, and exception application

**Start.** Launch installs receivers, the stop-request handle, and a fresh
session, and sets the liveness flag. A staged job additionally *seeds* the
session with `Queued` task rows from the module registry so the DAG is visible
before any frame arrives.

**Completion.** The terminal-success handler records the run to disk, applies
the serialized result and its side effects, **caches derived outputs** (§6),
forces the owning task row to *Done* (idempotently — no-op if already terminal),
records duration, and advances any dependent queue.

**Exception.** The terminal-failure handler records the failed run, applies a
failure-shaped result, then **synthesizes a terminal frame**
(`kind = "refused"`, `severity = "danger"`) and feeds it through `apply_step`,
which flips the row to *Failing*. This routes failures through the exact same
frame path as success, so the exception branch needs no separate rendering path.

### 4.7 Stop-request behavior

A stop request fans out across every active machine and then flips the session:

```rust
fn request_active_stop(&mut self) -> bool {
    let mut requested = false;
    requested |= self.request_staged_job_stop();
    requested |= self.request_frame_job_stop();
    requested |= self.request_delegated_call_stop();
    requested |= self.request_plan_stop();
    requested |= self.request_derived_output_stop();
    if requested { if let Some(s) = self.session.as_mut() { s.mark_active_tasks_canceled(); } }
    requested
}
```

Each per-machine stop is idempotent (guarded by an `abort_requested` flag),
signals the shared cancellation token, and updates the row to a
"stop requested; waiting" state. The token itself is a small shared struct:

```rust
struct JobCancellation {
    cancelled: Arc<AtomicBool>, paused: Arc<AtomicBool>,
    next_child_id: Arc<AtomicU64>, children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
}
```

`cancel()` sets `cancelled = true`, clears `paused`, and kills any tracked child
processes under `SeqCst` ordering. Only *Queued* and *Active* rows are
cancelable; terminal rows are left untouched, preserving §4.2's irreversibility.

### 4.8 Cached output updates

When a machine finishes, its serialized result is dispatched through an ordered
list of snapshot-cache functions. Each inspects the result's `data` object and,
if it recognizes the producing verb, populates a typed in-memory cache (derived
graphs, path snapshots, etc.). The first matching cache short-circuits the rest.
These caches are also **hydrated from disk on startup**, so derived outputs
survive a restart (§6.2).

---

## 5. Thread-safe local disk serialization

Local durability is a mix of **atomic full-file writes**, **append-only logs**,
**read-modify-write stores**, and **local database files**. The atomicity
guarantee differs by path, which is the most important thing to understand about
this layer.

### 5.1 Atomic writer design

The atomic writer is temp-write-then-rename:

```rust
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    // 1. create_dir_all(parent)
    // 2. temp_sibling: "{name}.tmp-{pid}-{SEQ}-{nanos}"  (SEQ is an AtomicU64)
    // 3. write temp, then file.sync_all()
    // 4. fs::rename(temp, path)         // POSIX atomic overwrite
    // 5. best-effort sync_parent_dir(path)
}
```

Collision-free temp names (per-process `AtomicU64` sequence + nanos) mean
concurrent same-file writers don't clobber each other's temp files; the rename
gives **last-writer-wins** with no torn reads. There are no advisory file locks;
crash-safety rests entirely on the atomic rename plus the pre-rename `sync_all`.
A JSONL variant (`save_jsonl`) serializes all rows and routes through the same
atomic path.

### 5.2 Which writes are atomic

Routed through `write_atomic` (crash-safe, last-writer-wins):

- **serialized local runtime state** — the run summary (`run.json` / legacy
  `summary.json`) and the "latest run" pointer file; the pointer explicitly
  uses the atomic path because a torn write would desync the whole run index.
- the **option store** (global and workspace scopes),
- the **attachment store**, and
- JSONL state written via `save_jsonl`.

### 5.3 Which writes are append-only

- The **append-only frame log** (`trace.jsonl`) — opened
  `create(true).append(true)`, one `write_all` per line, serialized by the
  per-path mutex registry (§2.4). **Multi-writer safe within the process.**
- A second event log (`events.jsonl`) — also `create(true).append(true)` with
  `writeln!`, but **without** the per-path lock. Concurrent appenders to this
  log can interleave lines; it assumes a single writer.

### 5.4 Which writes are direct (non-atomic)

Several paths use a bare `fs::write` (no temp file, no fsync). A crash mid-write
can leave these torn or truncated:

- the **serialized local runtime state** snapshot (`context-snapshot.json`),
- the derived-model documents (`*-model.json` and their normalized artifacts;
  overwrite is guarded by a `userEdited` flag but not by a lock),
- text run artifacts, and
- the **artifact manifest** (`artifacts.json`) — see §5.5.

### 5.5 Read-modify-write boundaries

Two stores are read-modify-write and are the sharpest single-writer assumptions:

- **Artifact manifest.** Every JSON or text artifact write calls
  `record_run_artifact`, which **loads the manifest, upserts one entry by path,
  and rewrites the whole file** — with a non-atomic `fs::write` and no lock.
  Two concurrent artifact writes to the same run can lose an entry or tear the
  file.
- **Option store.** `load_persistent` reads global+workspace files and merges
  by scope; `save_persistent` writes each scope back through `write_atomic`.
  The write is atomic, but the load→mutate→save cycle is not guarded, so
  concurrent mutators still resolve last-writer-wins at file granularity.

### 5.6 Local database-backed state

Several subsystems persist to SQLite files under a workspace state directory:

- a **key/value quantile state** table (`key TEXT PK, value BLOB, updated_at`)
  written with an upsert (`on conflict … do update`); a fresh `Connection` is
  opened per call (no pooling).
- an **evidence/citation** table with an index, also fresh-connection-per-call,
  batch-inserted.
- a **workspace inventory** store (`workspaces / hosts / services / notes` with
  foreign keys and indexes) that holds a single long-lived `Connection` in its
  struct and reuses it across operations.

No explicit `PRAGMA synchronous = FULL` is set, so these rely on SQLite's
default durability and its own page-level write serialization rather than any
application lock.

### 5.7 Crash-safety and single- vs multi-writer summary

- **Crash-safe (atomic):** run summary, latest-run pointer, option store,
  attachment store, JSONL-via-`save_jsonl`.
- **Vulnerable to torn/truncated files on crash:** context snapshot, derived
  model docs, text artifacts, artifact manifest, and `events.jsonl`.
- **Multi-writer safe:** `trace.jsonl` (per-path mutex), all `write_atomic`
  targets (collision-safe temp + rename), SQLite tables (engine-level locking).
- **Single-writer assumed:** artifact manifest, context snapshot, derived model
  docs, text artifacts, `events.jsonl`.

---

## 6. Snapshot caching and artifact publication

Derived outputs are produced once by a machine, cached in memory for the
foreground, and published to disk so later runtime stages (and later process
starts) can consume them.

### 6.1 Generating local snapshots

The context snapshot is a single deterministic JSON document assembled from the
workspace: target root, timestamp, a discovery mode, a repository/inventory
projection, a bounded file index (with a `truncated` flag), an application model
(routes, outbound clients, service boundaries, data stores, background jobs),
and generated/stale slice lists. It is written non-atomically (§5.4) and is
explicitly treated as **deterministic input** for downstream stages.

### 6.2 Refreshing cached outputs

On completion, a machine's serialized result flows through the ordered
snapshot-cache dispatch (§4.8), replacing the corresponding typed in-memory
cache. On process startup, a hydration pass reloads those same caches from their
persisted on-disk artifacts, so the in-memory derived state is reconstructed
without re-running the producing machine.

### 6.3 Making serialized outputs available downstream

Published artifacts are registered in the per-run **artifact manifest** (§5.5),
which maps labels/kinds/paths and is the index later stages read to discover a
run's outputs. Because each artifact write rewrites the manifest through a
non-atomic read-modify-write, the manifest is the single most concurrency-
sensitive publication point in this layer.

---

## Architectural invariants, risks, and open questions

**Invariants the system depends on.**

- Liveness is cleared by the terminal-event handler; receiver teardown only
  reacts to the cleared flag. Reversing this order would reintroduce the
  producer-finished/foreground-reconciled visibility gap (§1.3, §3.5).
- Terminal task-row states are irreversible, and late completions after a stop
  are explicitly guarded (§4.2, §4.7).
- Per-task aggregates live on the row, not in the bounded feed, so ring-buffer
  eviction never loses counters/costs (§4.3).
- One shared, disk-seeded atomic counter per frame log gives continuous frame
  numbering across restarts (§2.5).
- Redraws are driven solely by the dirty flag; no handler renders directly
  (§3.2, §3.6).

**Risks worth flagging (architecture-level, no remediation implied).**

- The artifact manifest is a non-atomic, unlocked read-modify-write invoked on
  *every* artifact write — the clearest multi-writer hazard in the persistence
  layer (§5.5).
- `events.jsonl` appends without the per-path lock that protects the frame log,
  so it silently assumes a single appender (§5.3).
- Context snapshot and derived-model documents use bare `fs::write`; a crash
  mid-write can leave a torn file that downstream stages treat as deterministic
  input (§5.4, §6.1).
- SQLite stores rely on default durability with no explicit synchronous pragma
  and mostly fresh-connection-per-call, so cross-call transactional
  coordination is not expressed at the application layer (§5.6).

**Open questions for a maintainer.**

- Is any producer ever expected to write the same run's manifest or
  `events.jsonl` concurrently (e.g. parallel sub-machines under one run)? The
  code's single-writer assumption there is implicit, not enforced.
- Task-local vs thread-local parent resolution (§2.6) has a documented
  synchronous-only fallback; are there call sites that push parents on the
  thread-local stack and then cross an `.await`, where the fallback would
  mis-parent frames?
```
