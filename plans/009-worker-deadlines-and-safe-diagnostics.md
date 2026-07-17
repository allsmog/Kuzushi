# Plan 009: Bound worker brokers by the watchdog and sanitize child diagnostics

> Executor: preserve the KWP wire contract and existing grants. Do not broaden
> worker capabilities, weaken cancellation, or change model selection.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: correctness/security/resource management
- **Planned at**: commit `775a4134f2cb`, Cycle 4

## Why this matters

The worker watchdog is polled only while reading protocol messages. Net, MCP,
and fuzz broker calls then block inline and use request or mount timeouts that
can exceed the remaining worker deadline. Bounded stderr previews also forward
raw terminal controls from untrusted children.

## Current state

- `worker_protocol.rs::apply_worker_message` calls
  `WorkerHostSession::handle_worker_request` inline.
- Runtime queries receive the session deadline, but net, MCP, and fuzz compute
  timeouts without it.
- `worker_protocol/stderr.rs` bounds memory but sends child text directly to
  `eprintln!`.

## Steps

1. Add one pure effective-timeout helper that clamps request, mount/grant, and
   remaining session time and rejects an already-expired deadline.
2. Thread that timeout into net fetch, MCP call, and fuzz execution. Ensure
   timeout/cancellation kills and reaps child processes before returning.
3. Centralize child-diagnostic escaping. Preserve printable Unicode and common
   whitespace, but visibly escape ESC/CSI/OSC, CR, C0/C1 controls, and invalid
   UTF-8 so terminal state cannot be changed.
4. Keep stderr byte/line limits, join behavior, error precedence, and KWP
   response shapes unchanged.

## Verification

- Hanging HTTP, MCP, and fuzz fixtures terminate within a short worker deadline.
- Child PIDs are gone after timeout and cancellation.
- Diagnostic tests cover CSI, OSC 52, CR, C0/C1, Unicode, and invalid UTF-8.
- Run worker-protocol tests, focused Clippy, architecture/model-safety gates,
  and the CRAP-risk gate.

## Done criteria

No synchronous broker call can outlive the worker deadline, and no child-owned
terminal control reaches the operator terminal unescaped.
