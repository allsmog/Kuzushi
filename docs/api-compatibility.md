# API compatibility notes

Kuzushi's public API surface is mostly CLI commands, module tool names, MCP
bridging, and the optional scan SSE endpoint. This page records compatibility
rules for legacy names and route aliases.

## Module tool names

Canonical module tools use the `<module-id>:<action>` convention documented in
[`modules.md`](./modules.md). The SAST family was split into narrower modules,
so new callers should use the canonical names:

- `semgrep:scan`
- `codeql:scan`
- `agentic-sast:scan`
- `triage:run`
- `verify:finding`
- `patch:finding`
- `findings:list`
- `context:build`
- `threat-hunt:run`
- `taint-iris:hunt`

Legacy `sast:<action>` aliases remain registered for backward compatibility,
but they are compatibility redirects rather than the preferred API surface.
Do not add new docs or tests that introduce `sast:<action>` names unless the
test is explicitly covering alias behavior.

## Streaming SSE routes

The optional scan streaming server exposes:

- `GET /events` — canonical SSE stream for scan events.
- `GET /health` — JSON health check.

`GET /` is a legacy alias for the event stream. It remains functional, but
responses include:

- `Deprecation: true`
- `Link: </events>; rel="successor-version"`

New clients should connect to `/events` directly. Keep the root route as a
compatibility alias until there is a release note and migration window for
removal.

## MCP bridge versioning

MCP tool calls are JSON-RPC method names (`initialize`, `tools/list`,
`tools/call`) rather than HTTP REST routes. Kuzushi currently supports stdio
and streamable HTTP MCP transports. Treat protocol-version changes as API
changes: update `docs/mcp-server-requirements.md`, bridge tests, and release
notes together.
