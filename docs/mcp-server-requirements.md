# Kuzushi MCP server requirements

Kuzushi can load tools from any server that speaks the Model Context Protocol
(MCP) 2025-03-26 spec or newer. This page lists the minimum surface your
server must implement to load cleanly under `--load 'mcp:<spec>'`.

## 1. Required server capabilities

Your server must implement the standard MCP RPCs:

- `initialize` — responds with `{ protocolVersion, capabilities, serverInfo }`.
  Kuzushi negotiates `protocolVersion: "2025-03-26"` over HTTP and
  `"2024-11-05"` over stdio.
- `notifications/initialized` — Kuzushi sends this after initialize; handle
  or ignore.
- `tools/list` — returns `{ tools: Tool[] }`. Each `Tool` follows the
  `ToolSchema` in `@modelcontextprotocol/sdk`.
- `tools/call` — returns `{ content: ContentBlock[], isError?: boolean }`.
  Kuzushi renders `content[].text` for text blocks and JSON-stringifies other
  block types.

Transports supported: streamable HTTP (`http://` / `https://` specifier) and
stdio (`npx …` / `node …` / `python …` specifier). Plain SSE-only transports
are not supported.

## 2. Tool schema requirements (MCP-5)

Every tool's `inputSchema` MUST be a JSON Schema object with `type: "object"`
at the top level. Kuzushi preserves the schema verbatim — `required`,
`additionalProperties`, nested `properties`, `enum`, defaults — and uses it
for LLM tool dispatch in shell mode.

Tools whose schema fails validation are substituted with an empty object
schema and **forced non-headless** (they can't be scheduled in `kuzushi run`
/ pipeline mode). Get the schema right.

## 3. Optional tool annotations

Kuzushi reads the standard `ToolAnnotationsSchema` hints:

- `readOnlyHint: true` — the tool only reads state. Required to be marked
  headless automatically (see §5 below).
- `destructiveHint: true` — the tool may destroy state. Forces non-headless
  even if `readOnlyHint` is also set under the non-trust default.
- `idempotentHint` / `openWorldHint` — accepted but not currently consulted.

Per the MCP spec these are advisory; Kuzushi does not treat them as security
guarantees.

## 4. Auth

The HTTP transport sends `Authorization: Bearer <token>` on every request
when a token is available. Token source order:

1. `CreateMcpModuleOptions.authToken` passed programmatically.
2. `KUZUSHI_MCP_TOKEN` environment variable.

Stdio transport inherits the operator's `process.env` unchanged — embed any
secrets the child needs in the spawn env.

## 5. Timeouts

Per-call timeout defaults to **60 seconds** and covers both the transport
request and the bridged `tools/call`. Override via
`CreateMcpModuleOptions.timeoutMs` (ms). Set `0` to disable the bridge-level
timeout (the underlying transport still applies its own).

## 6. `headless` default (MCP-7)

Kuzushi does **not** mark MCP-bridged tools as `headless` by default. Only
tools that advertise `annotations.readOnlyHint: true` (without
`destructiveHint: true`) are auto-headless. Operators who trust their MCP
server can opt back into the legacy default-all-headless behaviour by
passing `trustHeadless: true` to `createMcpModule`.

## 7. Minimal compliant server (Node.js)

```ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "example", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler({ method: "tools/list" } as never, async () => ({
  tools: [
    {
      name: "echo",
      description: "Echo back a string.",
      inputSchema: {
        type: "object",
        properties: { message: { type: "string" } },
        required: ["message"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
    },
  ],
}));

server.setRequestHandler({ method: "tools/call" } as never, async (req) => {
  const { name, arguments: args } = (req as { params: { name: string; arguments: { message: string } } }).params;
  if (name !== "echo") throw new Error(`unknown tool: ${name}`);
  return { content: [{ type: "text", text: args.message }] };
});

await server.connect(new StdioServerTransport());
```

Load it into Kuzushi:

```bash
kuzushi shell --load 'mcp:node path/to/server.js'
```

The bridged tool appears as `<slug>:echo` (slug derived from the spec, with a
`-2` / `-3` suffix if multiple servers collide).
