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
- `offense-review:threat-hunt`
- `taint-iris-next:dataflow-plan`
- `taint-iris-next:source-sink-trace`
- `taint-iris-next:finding-review`

Legacy `sast:<action>` aliases remain registered for backward compatibility,
but they are compatibility redirects rather than the preferred API surface.
Do not add new docs or tests that introduce `sast:<action>` names unless the
test is explicitly covering alias behavior.

`carlini-threat-hunt:run` remains registered as a compatibility alias for the
same threat-model-scoped offensive review executor. New product-facing scripts
and docs should use `offense-review:threat-hunt`.

The 2026 surface cut keeps exact-name compatibility while reducing discovery
noise:

- The shell `home`, `/home`, and `/` routes now open the phase Workbench.
  `modules` opens the phase-native Capabilities overlay; use `tools` for the
  exhaustive engine inventory.
- `bounty:import-har` and `bounty:import-burp` are exact-only compatibility
  entries. Use `recon:import {"tool":"har","path":"..."}` or
  `recon:import {"tool":"burp-xml","path":"..."}`.
- `randori:pasta` is exact-only; use
  `threat-model:build {"methodology":"pasta"}`.
- `module-recommender:recommend`, `catalog:modules`, and `catalog:tools` remain
  exact-only while callers move to phase capability projection and direct
  registry queries.

- `taint-iris:hunt` dispatches to the `taint-iris-next:hunt` executor shape.
  New workflows should use the visible `taint-iris-next:*` evidence helpers or
  the SAST/journey path that invokes the hunt stage.
- `full-mode:hunt` is exact-only; use
  `agentic-sast:scan {"strategy":"chunked"}` for the same chunked whole-repo
  strategy.
- `deep-audit:run` is exact-only; use
  `triage:run {"strategy":"deep"}`. The cheap classifier gate is exposed as
  `triage:run {"strategy":"gate-deep"}`.
- `verify:exploit` is exact-only; use
  `verify:finding {"mode":"empirical"}`.
- `shinsa:quick-check` and `shinsa:nist-quick-check` are exact-only; use
  `shinsa:scan {"depth":"quick"}` or
  `shinsa:nist-scan {"depth":"quick"}` when the plugin is installed.
- `randori:threat-model` is exact-only; prefer `threat-model:build` and
  `threat-model:read` for PASTA artifacts.
- `android-apk:scan` is the catalog-visible APK entry point. Granular
  `android-apk:*` phase tools remain exact-only for debugging and scripted
  recovery.
- `smoke:next-step` was a hidden runtime smoke-test helper and is removed.

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
