# Port Authority Crane Boundary — Architectural Blueprint

> An abstract, domain-neutral description of the process boundary between a
> native parent coordinator and an asynchronous child runtime. All concepts are
> expressed as port-yard logistics so the control structure can be reasoned
> about independently of the underlying implementation domain.

## 1. Actors

| Blueprint actor | Concrete counterpart | Role |
| --- | --- | --- |
| **Port Authority Crane Controller** (Parent) | Native Rust CLI / TUI controller | Owns the operator surface, holds authoritative state, dispatches missions, and enforces all bounds. |
| **Automated Cargo Stacking Vehicle** (Child) | TypeScript / Node.js runtime + graph agent | A short- or long-lived subordinate process that carries out one dispatched mission and reports back. |
| **Dispatched Cargo Transport Mission** | Subprocess spawn / async execution task | A single unit of delegated work handed from Controller to Vehicle. |
| **Route-Recalculation Overhead** | Iterative graph agent loop / reflective state updates | The Vehicle's internal replanning cycle: re-evaluate, request an assist, replan, repeat. |
| **Auxiliary Yard Equipment** | Optional co-process helper modules | Specialist rigs the Vehicle may request mid-mission; each is a separate attachable unit. |

The Controller is always the *system of record*. The Vehicle owns no durable
state: it receives a mission envelope, executes, streams back a result, and is
expected to terminate. Every authority decision — what to dispatch, how long it
may run, when to recall it — lives with the Controller.

## 2. Dispatch classes

The Controller supports three distinct ways to put a Vehicle on the yard. They
differ only in the *shape of the conversation*, not in ownership or bounds.

### 2.1 One-shot haul (fire-and-collect)

The simplest mission. The Controller starts a Vehicle, optionally pushes a
single loading manifest down the inbound chute, then waits for the Vehicle to
finish and collects everything it produced in one batch.

- Inbound chute (`stdin`): opened only when a manifest is present.
- Outbound chute (`stdout`): captured whole on completion.
- Diagnostic chute (`stderr`): captured whole; surfaced only on a failed run.
- Completion contract: a clean exit code yields the manifest of stacked cargo;
  a non-zero exit is reported to the operator using the trimmed diagnostic
  chute as the reason.

Used for the two stateless mission verbs — *survey the module* (describe) and
*execute a self-contained haul* (execute). No back-and-forth occurs.

### 2.2 Interactive haul with call-backs (bidirectional escort)

A long-lived mission in which the Vehicle is permitted to *radio back* to the
Controller mid-route and cannot proceed until the Controller answers.

1. Controller spawns the Vehicle in escort mode (`execute-runtime`), keeping
   the inbound chute, outbound chute, and diagnostic chute all open for the
   duration.
2. Controller writes an initial **request envelope** (newline-delimited JSON)
   down the inbound chute.
3. Controller enters a read loop on the outbound chute, decoding one framed
   message per line:
   - `runtime.query` — the Vehicle is stuck and requests an authoritative
     recalculation from the Controller. The Controller performs the
     recalculation on its own equipment and writes back a matching
     `runtime.response` (or a `runtime.error`) keyed by the query id.
   - `result` — terminal frame; the mission's finished cargo. The loop exits.
   - any other frame type — treated as a protocol violation and aborts the
     mission.
4. When the loop returns, the Controller closes the inbound chute and reaps the
   Vehicle, confirming a clean exit before trusting the collected result.

Correlation is by monotonically increasing **query id**; the Vehicle refuses a
response whose id does not match the outstanding query, so the escort channel
can never desynchronize.

### 2.3 Primary agent haul (the workhorse)

The main production mission type. The Controller spawns the Vehicle process,
writes a single structured **mission request** down the inbound chute, and
collects a single structured **result** from the outbound chute — but does so
under the full bounds regime described in §5 (deadline, recall, pipe draining,
environment provisioning).

This is the class that carries **Route-Recalculation Overhead** (§4): inside a
single primary haul the Vehicle may loop internally many times and may attach
Auxiliary Yard Equipment, all without the Controller issuing new missions.

## 3. Lifecycle tracking

The Controller tracks each Vehicle through an explicit, observable lifecycle.
There is no "fire and forget" — a spawned Vehicle is always owned by a handle
until it is reaped or killed.

```
 locate ──► spawn ──► provision ──► load ──► supervise ──► settle ──► reap
   │          │           │          │           │            │         │
 resolve   process     inbound    write       drain +      exit      collect
 Vehicle   handle      + env      manifest     poll +       status    cargo /
 binary    acquired    applied                 bound-check           report
```

1. **Locate.** Before any spawn the Controller resolves *which* Vehicle binary
   to launch, searching, in order: an operator-provided override path, the
   in-tree checkout location, then a bounded walk (up to six ancestors) around
   the Controller's own executable. If none resolves, the mission fails
   immediately with an actionable message — the Controller never guesses.
2. **Spawn.** A process handle is acquired. From this instant the Vehicle is
   owned; every downstream branch either reaps it cleanly or kills it.
3. **Provision.** The Controller injects the environment the Vehicle needs:
   default locations for any Auxiliary Yard Equipment binaries that sit beside
   the Controller but are not otherwise on the search path, and per-attachment
   handoff-file locations. Operator-set values are never overwritten.
4. **Load.** The mission manifest is written to the inbound chute. A closed
   inbound chute mid-write (the Vehicle chose to short-circuit and already
   emitted its answer) is treated as *normal*, not as an error — the Controller
   swallows the broken-chute signal and proceeds to collect what the Vehicle
   already produced.
5. **Supervise.** The Controller drains the output and diagnostic chutes on
   dedicated reader threads while polling the Vehicle's exit status on a short
   cadence, checking bounds on every pass (§5).
6. **Settle.** On natural exit, the Controller reads the final status.
7. **Reap.** Cargo is collected and decoded; a clean exit yields the result, a
   dirty exit yields a structured error frame if the Vehicle emitted one, else
   a diagnostic-chute failure report.

## 4. Route-Recalculation Overhead

Within a single primary haul the Vehicle runs an internal replanning cycle. The
Controller does **not** micromanage this cycle; it is the Vehicle's private
overhead, bounded only by the outer mission deadline.

The cycle is a small directed loop:

```
        ┌──────────────┐
 START ─► plan ─► need assist? ──no──► DONE
        └──────────────┘   │
              ▲            yes
              │             ▼
              └──── attach equipment / recalc route
```

- **plan** — the Vehicle evaluates its current state and decides the next move.
- **need assist?** — if the plan calls for specialist handling, the Vehicle
  attaches the relevant **Auxiliary Yard Equipment**, gathers the result, folds
  it back into its state, and returns to *plan*.
- The loop terminates when a plan requires no further assist; the Vehicle then
  frames the final cargo and writes it to the outbound chute.

Two properties matter to the Controller:

1. **Bounded from outside.** However many times the Vehicle recalculates, the
   whole haul lives under one wall-clock ceiling (§5.1). Runaway recalculation
   surfaces to the operator as a single deadline event, not as a hang.
2. **Escort-capable.** In escort mode (§2.2), a recalculation step may require
   authority the Vehicle does not hold; it radios a `runtime.query` back to the
   Controller, which performs the recalculation on Controller-owned equipment
   and returns the answer. The Vehicle cannot invent that authority locally —
   every request must name the equipment class to use, and a request that names
   none is rejected rather than defaulted.

## 5. Execution bounds (current enforcement)

Bounds are enforced entirely on the Controller side. The Vehicle is treated as
untrusted-for-liveness: it may hang, wedge, flood a chute, or exit dirty, and
none of those may compromise the Controller.

### 5.1 Wall-clock deadline

Every mission runs under a hard time ceiling. The Controller computes a
deadline at spawn and, on each supervision pass, kills and reaps the Vehicle
the moment the deadline passes, surfacing a timeout error that names the
elapsed ceiling. The default ceiling is generous (ten minutes) to accommodate a
long haul with many recalculation steps and equipment attachments; an operator
may raise it through a single documented override, and only that.

### 5.2 Cooperative recall (cancellation)

The Controller holds a recall signal shared with the operator surface. On each
supervision pass it checks the signal; if the operator has requested a recall,
the Vehicle is killed and reaped immediately and the mission reports a
"recalled and killed" outcome. Recall is checked *before* the deadline so an
operator abort always wins.

### 5.3 Chute-drain (deadlock immunity)

Both the outbound and diagnostic chutes are drained continuously on dedicated
reader threads for the entire mission. This is a correctness bound, not a
convenience: a Vehicle that fills a chute buffer while the Controller is blocked
elsewhere would otherwise deadlock the pair permanently. Draining guarantees the
Vehicle can always make forward progress and can always be cleanly reaped.

### 5.4 Admission gate (trust)

For the dynamically loaded mission classes, a Vehicle module is admitted only
if its specifier is on the operator's trusted list or the operator has passed an
explicit one-run allowance. An untrusted specifier is refused before any spawn,
with a message pointing at the exact configuration key to amend.

### 5.5 Capability gate (readiness)

A mission verb that declares it *requires* live escort authority is refused up
front if no such authority is configured, rather than being launched into a
state where it would fail deep inside the loop. Readiness is checked at the door.

### 5.6 Reap-on-every-exit

There is no path out of the supervision routine that leaves a Vehicle running:
natural exit is reaped, deadline expiry is killed-then-reaped, recall is
killed-then-reaped, and a kill is always followed by a wait so no zombie
Vehicle is left on the yard.

## 6. Channel summary

| Channel | Direction | Contents | Framing | Managed by |
| --- | --- | --- | --- | --- |
| Inbound chute | Controller → Vehicle | Mission manifest; escort responses | Whole-body JSON (one-shot) or newline-delimited JSON (escort) | Controller writes; tolerates early close |
| Outbound chute | Vehicle → Controller | Finished cargo; escort queries | Whole-body JSON or newline-delimited frames | Drained on a reader thread |
| Diagnostic chute | Vehicle → Controller | Progress notes, failure detail | Free text | Drained on a reader thread; surfaced on failure |
| Environment provisioning | Controller → Vehicle (at spawn) | Equipment locations, handoff-file paths, deadline override | Key/value | Applied at spawn, never over operator values |
| Recall signal | Operator → Controller | Abort request | Boolean flag | Polled each supervision pass |

## 7. Invariants worth preserving

- The Controller is the single source of authority and the single owner of
  every Vehicle handle; the Vehicle holds no durable state.
- No Vehicle outlives its mission: every exit path reaps.
- No missing input is silently defaulted — an unresolved binary, an unnamed
  recalculation target, or an untrusted module is a hard, actionable error.
- Liveness bounds (deadline, recall, chute-drain) are the Controller's
  responsibility alone and never depend on Vehicle cooperation.
- Route-recalculation cost is contained inside a single mission's ceiling, so
  operator-visible time is bounded regardless of internal loop depth.
```
