# 0004 — Read-only auxiliary Ask authorization

- Status: Accepted
- Date: 2026-08-27
- Owner: `@allsmog`

## Decision

Ordinary inline Ask remains exclusive until context-bound history is shipped.
The later concurrent path permits exactly one active Run plus one auxiliary
Agent. It is not a general concurrency scheduler.

Concurrent Ask uses policy id `ask.concurrent-read-only.v1`. Its complete tool set is
`Read`, `LS`, `Glob`, and `Grep`, confined to the canonical target root. It
mounts no MCP server, write tool, shell tool, or operator-interaction tool.

The bridge has a versioned, side-effect-free authorization handshake. Its
receipt states protocol version, policy id, exact effective tools, canonical
read roots, and explicit write/shell and MCP mounted booleans. Rust validates
that receipt before reserving the auxiliary slot or starting run artifacts;
the subsequently dispatched request carries the same typed tool policy.
Missing, unknown, or mismatched acknowledgement refuses concurrent launch;
ordinary callers remain wire-compatible.

All target/model context and prior assistant output is untrusted data. One
64-KiB budget covers current scene/model context, failure context, and complete
history pairs, in that priority order. `ThreadContextKey` binds canonical
target, target revision, exact threat-model ref, and policy version. A key
change starts a disclosed new conversation.

Run Focus remains owned by the scan. Ask has separate activity and transcript
state. Ctrl+C cancels the Run first; `ask cancel` cancels the auxiliary Ask; a
second Ctrl+C while Run cancellation is pending cancels Ask; quit cancels both.
Auxiliary completion cannot advance the steer queue.

## Consequences

No acknowledgement means no concurrency. MCP-backed Ask, two Agents, and
Agent+Plan/Threat combinations remain unsupported.
