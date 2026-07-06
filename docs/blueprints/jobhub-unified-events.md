# Blueprint: `JobHub` + unified `ShellEvent` channel

Status: proposal (sketch). Scope: `crates/kuzushi-tui` only. No change to
`kuzushi-core` dispatch, trace schema, or `.kuzushi` artifacts.

## Problem

`ShellApp` carries seven hand-copied worker plumbing triples
(`{generation, rx, cancel}` for live_run / scan / tool / agent / plan /
threat / trace — ~21 fields in `app/shellapp.rs`), and
`drain_background_events` re-implements the same drain → stale-filter →
disconnect-synthesis → apply → clear sequence once per channel
(`background_events/drain_background_events/runtime_event_drains.rs`, 258
lines for one concept). `LiveRunEvent` already unifies Trace/Scan/Tool onto
one channel for tool and scan runs — this blueprint finishes that
unification and gives the plumbing a home.

## Design

### 1. One event enum, one channel

```rust
// crates/kuzushi-tui/src/app/jobs/event.rs
#[derive(Debug)]
pub(crate) enum ShellEvent {
    Trace(RunTraceStep),
    Scan(ScanEvent),
    Tool(ToolEvent),
    Agent(AgentEvent),
    Plan(PlanEvent),
    Threat(ThreatPatchEvent),
}

/// Which job slot an event belongs to, for stale-generation filtering.
/// Run covers Trace + Scan + Tool: they already share one lifecycle
/// (today's `LiveRunEvent` channel and its joint clear logic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum JobKind { Run, Agent, Plan, Threat }

impl ShellEvent {
    pub(crate) fn kind(&self) -> JobKind {
        match self {
            Self::Trace(_) | Self::Scan(_) | Self::Tool(_) => JobKind::Run,
            Self::Agent(_) => JobKind::Agent,
            Self::Plan(_) => JobKind::Plan,
            Self::Threat(_) => JobKind::Threat,
        }
    }
    pub(crate) fn is_terminal(&self) -> bool { /* Finished/Failed/Answered/Proposed */ }
}
```

The existing payload enums (`ScanEvent`, `ToolEvent`, `AgentEvent`,
`PlanEvent`, `ThreatPatchEvent`) and all `apply_*_event` reducers are
unchanged. `LiveRunEvent` is deleted (subsumed).

### 2. `JobHub` owns the plumbing

```rust
// crates/kuzushi-tui/src/app/jobs/hub.rs
pub(crate) struct JobHub {
    tx: Sender<Stamped>,            // cloned into every JobTicket
    rx: Receiver<Stamped>,          // single receiver, lives as long as the app
    next_generation: u64,
    slots: BTreeMap<JobKind, JobSlot>,
    trace_budget: LiveTraceBudget,  // moves here from ShellApp
}

struct Stamped {
    kind: JobKind,
    generation: WorkerGeneration,
    event: ShellEvent,
}

struct JobSlot {
    generation: WorkerGeneration,
    cancel: ScanCancellation,
    /// Operator-facing label ("scan", tool name, "planner") used to
    /// synthesize a Failed event if the worker dies without reporting.
    label: String,
}

impl JobHub {
    /// Register a job and hand the worker everything it needs.
    pub(crate) fn start(&mut self, kind: JobKind, label: impl Into<String>) -> JobTicket;
    pub(crate) fn is_running(&self, kind: JobKind) -> bool;
    pub(crate) fn cancel(&mut self, kind: JobKind);          // arms ScanCancellation
    pub(crate) fn finish(&mut self, kind: JobKind);          // reducers call on terminal events
    /// Drain up to `limit` events: release trace-budget slots, drop
    /// stale-generation events, return the rest in send order.
    pub(crate) fn drain(&mut self, limit: usize) -> Vec<ShellEvent>;
}
```

`ShellApp` replaces the 21 plumbing fields with:

```rust
pub(crate) jobs: JobHub,
```

(`tool_running` / `ambient_tool` fold into `JobSlot.label` +
`JobHub::running_label(JobKind::Run)`; `tool_abort_requested` and friends
become `JobHub::cancel_requested(kind)`.)

### 3. `JobTicket` replaces `(tx, generation, cancel)` worker args

```rust
pub(crate) struct JobTicket {
    kind: JobKind,
    generation: WorkerGeneration,
    tx: Sender<Stamped>,
    pub(crate) cancel: ScanCancellation,
    guard: PanicGuard,
}

impl JobTicket {
    pub(crate) fn send(&self, event: ShellEvent);
    /// Call after sending the terminal event; disarms the PanicGuard.
    pub(crate) fn complete(self);
}
```

`background_tool_worker(...)`, `scan_worker`, `agent_dispatch`,
`planner_dispatch`, and `worker_dispatch` (threat) take a `JobTicket`
instead of `tx + generation (+ cancel)`. `StampedTraceSink` takes a
cheap clone handle (`ticket.trace_sender()`) that stamps
`ShellEvent::Trace` with the ticket's kind/generation and keeps the
existing `LiveTraceBudget` try_reserve/release behavior.

### 4. `PanicGuard` replaces disconnect inference

Today a dead worker is detected by `TryRecvError::Disconnected`, then
`push_disconnected_live_run_failures` / per-channel equivalents guess
what was running and synthesize `Failed` events. With a single shared
channel the receiver never disconnects, so that signal disappears — and
gets replaced by something more direct:

```rust
struct PanicGuard { /* kind, generation, label, tx */ }

impl Drop for PanicGuard {
    /// If the worker unwinds (or returns) without `ticket.complete()`,
    /// send the synthesized Failed event for this kind — e.g.
    /// ShellEvent::Tool(ToolEvent::Failed { tool_name: label, error:
    /// disconnected_worker_message("tool") }).
    fn drop(&mut self) { ... }
}
```

This deletes `push_disconnected_*`, `disconnected_without_events`, and
all per-channel `clear_finished_*` methods. Slot cleanup happens in
`JobHub::finish`, called from the reducers that already handle terminal
events (`apply_tool_event`, `apply_scan_event`, ...).

### 5. The drain loop collapses

```rust
impl ShellApp {
    pub fn drain_background_events(&mut self) -> bool {
        let events = self.jobs.drain(DRAIN_LIMIT);
        let changed = !events.is_empty();
        for event in events {
            self.apply_shell_event(event);
        }
        changed
    }

    fn apply_shell_event(&mut self, event: ShellEvent) {
        match event {
            ShellEvent::Trace(step) => self.apply_live_trace_step(step),
            ShellEvent::Scan(e)  => self.apply_scan_event(e),
            ShellEvent::Tool(e)  => self.apply_tool_event(e),
            ShellEvent::Agent(e) => self.apply_agent_event(e),
            ShellEvent::Plan(e)  => self.apply_plan_event(e),
            ShellEvent::Threat(e) => self.apply_threat_event(e),
        }
    }
}
```

`drain_trace_before_terminal_events` becomes unnecessary: a single
channel preserves send order, and workers emit trace steps before their
terminal event on the same thread, so traces arrive first by
construction. (Cross-thread child trace steps racing a terminal event
are no worse than today.)

## Invariants preserved

- **Stale-run filtering**: generation stamping is kept, per `JobKind`,
  inside `JobHub::drain`. A relaunched job bumps the slot generation and
  old events are dropped exactly as today.
- **Trace back-pressure**: `LiveTraceBudget` semantics unchanged —
  reserve in the sink, release in drain, disk copy never dropped.
- **Reducer behavior**: `apply_scan_event`, `apply_tool_event`,
  `apply_agent_event`, `apply_plan_event`, `apply_threat_event` are
  untouched; their tests keep passing unmodified.
- **Two-stage Ctrl+C / uppercase `C` cancel**: routes through
  `JobHub::cancel(kind)`; same `ScanCancellation` object reaches the
  worker.
- **Plain mode / headless**: `JobHub` is constructed in `ShellApp::new`,
  no TTY dependency.

## Migration phases (each lands green, CRAP-gated)

1. **Introduce `app/jobs/`** (`event.rs`, `hub.rs`, `ticket.rs`) with
   unit tests: stamping, stale-drop, budget release, PanicGuard
   synthesis, send-order preservation.
2. **Move the Run lifecycle** (tool + scan + trace): port
   `start_background_tool_with_activity` (`tool_runner/run_tool/background.rs:168`)
   and `start_scan` (`scan/start_scan/scan_startup.rs:149`) to
   `jobs.start(JobKind::Run, ...)`. Delete the `live_run_* / scan_* /
   tool_* / trace_*` fields (13) and their drains. `LiveRunEvent` dies here.
3. **Move agent, plan, threat** (`agent_dispatch.rs:143`,
   `planner_dispatch.rs:12`, `worker_dispatch.rs:142`). Delete the
   remaining 9 plumbing fields and `runtime_event_drains.rs`.
4. **Fold status fields**: `tool_running`, `ambient_tool`,
   `tool_abort_requested`, `planner_running`, `threat_worker_running`,
   `plan/threat_abort_requested` → `JobHub` queries. Update
   `ui_view_models/routing.rs` (`has_run_activity`) and status chrome to
   read from `jobs`.

Net: ~27 `ShellApp` fields → 1; one drain implementation instead of
seven; worker death reported by a guard instead of inferred from channel
teardown. Adding an eighth worker kind = one enum variant + one reducer.
