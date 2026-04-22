/**
 * Unit tests for the MCP bridge (`src/modules/mcp-bridge.ts`) and the
 * collision-safe ID derivation in `src/copilot/core.ts`.
 *
 * These are pure unit tests — no real MCP server is spawned. `bridgeTool`,
 * `normalizeInputSchema`, and `decideHeadless` are exported from the bridge
 * specifically so we can test them against a mock `McpClient`.
 */

import { describe, expect, it, vi } from "vitest";
import { deriveUniqueMcpModuleId } from "../../src/copilot/core.js";
import {
  bridgeTool,
  type CreateMcpModuleOptions,
  decideHeadless,
  type McpClient,
  normalizeInputSchema,
} from "../../src/modules/mcp-bridge.js";

// ---------------------------------------------------------------------------
// normalizeInputSchema — MCP-5 schema fidelity
// ---------------------------------------------------------------------------

describe("normalizeInputSchema", () => {
  it("preserves required / additionalProperties / nested schemas verbatim", () => {
    const warn = vi.fn();
    const input = {
      type: "object",
      properties: {
        target: { type: "string", minLength: 1 },
        depth: { type: "integer", enum: [1, 2, 3], default: 1 },
        filters: {
          type: "object",
          properties: {
            include: { type: "array", items: { type: "string" } },
          },
          required: ["include"],
        },
      },
      required: ["target"],
      additionalProperties: false,
    };

    const { schema, schemaValid } = normalizeInputSchema(input, "m:t", { warn });

    expect(schemaValid).toBe(true);
    expect(schema).toEqual(input);
    expect(warn).not.toHaveBeenCalled();
  });

  it("deep-clones so downstream callers cannot mutate the source", () => {
    const source = {
      type: "object",
      properties: { a: { type: "string" } },
      required: ["a"],
    };
    const { schema } = normalizeInputSchema(source, "m:t", { warn: () => {} });
    (schema.properties as Record<string, unknown>).evil = { type: "number" };
    expect((source.properties as Record<string, unknown>).evil).toBeUndefined();
  });

  it("substitutes an empty object schema when `type` is not `object` and warns", () => {
    const warn = vi.fn();
    const { schema, schemaValid } = normalizeInputSchema({ type: "string" }, "m:bad", { warn });
    expect(schemaValid).toBe(false);
    expect(schema).toEqual({ type: "object", properties: {} });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain("m:bad");
  });

  it("treats missing / null / array schemas as invalid (no warn for missing)", () => {
    const warn = vi.fn();
    expect(normalizeInputSchema(undefined, "m:t", { warn }).schemaValid).toBe(false);
    expect(normalizeInputSchema(null, "m:t", { warn }).schemaValid).toBe(false);
    // Missing is tolerated silently (many MCP tools omit the field).
    expect(warn).not.toHaveBeenCalled();
    // Array/scalar IS anomalous — should warn.
    normalizeInputSchema([], "m:t", { warn });
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// decideHeadless — MCP-7 trust default
// ---------------------------------------------------------------------------

describe("decideHeadless", () => {
  it("defaults to false when no annotations are provided", () => {
    expect(decideHeadless({ schemaValid: true, trustHeadless: false })).toBe(false);
  });

  it("is true when readOnlyHint=true and destructiveHint!=true", () => {
    expect(
      decideHeadless({
        schemaValid: true,
        trustHeadless: false,
        annotations: { readOnlyHint: true },
      }),
    ).toBe(true);
  });

  it("is false when readOnlyHint=true but destructiveHint=true", () => {
    expect(
      decideHeadless({
        schemaValid: true,
        trustHeadless: false,
        annotations: { readOnlyHint: true, destructiveHint: true },
      }),
    ).toBe(false);
  });

  it("trustHeadless: true forces headless unless destructiveHint=true (and not read-only)", () => {
    expect(decideHeadless({ schemaValid: true, trustHeadless: true })).toBe(true);
    expect(
      decideHeadless({
        schemaValid: true,
        trustHeadless: true,
        annotations: { destructiveHint: true },
      }),
    ).toBe(false);
    // If the server claims both read-only AND destructive (contradictory),
    // respect the opt-in — read-only wins.
    expect(
      decideHeadless({
        schemaValid: true,
        trustHeadless: true,
        annotations: { readOnlyHint: true, destructiveHint: true },
      }),
    ).toBe(true);
  });

  it("is always false when the schema is invalid, regardless of hints or trust", () => {
    expect(
      decideHeadless({
        schemaValid: false,
        trustHeadless: true,
        annotations: { readOnlyHint: true },
      }),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// bridgeTool — end-to-end over a mock McpClient
// ---------------------------------------------------------------------------

function mockClient(
  impl: (name: string, args: Record<string, unknown>) => Promise<unknown>,
): Pick<McpClient, "callTool"> {
  return {
    callTool: async (name, args) => {
      const result = await impl(name, args);
      return result as never;
    },
  };
}

const baseOpts = {
  timeoutMs: 5_000,
  trustHeadless: false,
  logger: { warn: () => {} },
};

describe("bridgeTool", () => {
  it("forwards call to the MCP client and renders text content", async () => {
    const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
    const client = mockClient(async (name, args) => {
      calls.push({ name, args });
      return {
        content: [
          { type: "text", text: "line 1" },
          { type: "text", text: "line 2" },
        ],
      };
    });
    const tool = bridgeTool(
      {
        name: "scan",
        description: "Scan a target",
        inputSchema: { type: "object", properties: { target: { type: "string" } } },
      },
      "mcp-srv",
      client,
      baseOpts,
    );

    expect(tool.name).toBe("mcp-srv:scan");
    const result = await tool.execute({ target: "example.com" }, {} as never);
    expect(result.ok).toBe(true);
    expect(result.output).toBe("line 1\nline 2");
    expect(calls).toEqual([{ name: "scan", args: { target: "example.com" } }]);
  });

  it("treats isError=true as ok=false", async () => {
    const client = mockClient(async () => ({
      content: [{ type: "text", text: "boom" }],
      isError: true,
    }));
    const tool = bridgeTool({ name: "t", inputSchema: { type: "object" } }, "m", client, baseOpts);
    const result = await tool.execute({}, {} as never);
    expect(result.ok).toBe(false);
    expect(result.output).toBe("boom");
  });

  it("stringifies non-text content chunks as JSON fallback", async () => {
    const client = mockClient(async () => ({
      content: [
        { type: "image", data: "base64…", mimeType: "image/png" },
        { type: "text", text: "ok" },
      ],
    }));
    const tool = bridgeTool({ name: "t", inputSchema: { type: "object" } }, "m", client, baseOpts);
    const result = await tool.execute({}, {} as never);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("image");
    expect(result.output).toContain("ok");
  });

  it("catches client errors and returns ok=false with the message", async () => {
    const client = mockClient(async () => {
      throw new Error("server exploded");
    });
    const tool = bridgeTool({ name: "t", inputSchema: { type: "object" } }, "m", client, baseOpts);
    const result = await tool.execute({}, {} as never);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("server exploded");
  });

  it("times out slow calls and returns an ok=false result", async () => {
    const client = mockClient(
      () =>
        new Promise((resolve) => {
          setTimeout(() => resolve({ content: [{ type: "text", text: "late" }] }), 100);
        }),
    );
    const tool = bridgeTool({ name: "t", inputSchema: { type: "object" } }, "m", client, {
      ...baseOpts,
      timeoutMs: 10,
    });
    const result = await tool.execute({}, {} as never);
    expect(result.ok).toBe(false);
    expect(result.output).toMatch(/timed out/);
  });

  it("propagates MCP input schema fidelity (MCP-5)", () => {
    const richSchema = {
      type: "object",
      properties: {
        host: { type: "string" },
        ports: {
          type: "array",
          items: { type: "integer", minimum: 1, maximum: 65535 },
          minItems: 1,
        },
        mode: { type: "string", enum: ["fast", "deep"] },
      },
      required: ["host", "ports"],
      additionalProperties: false,
    };
    const client = mockClient(async () => ({ content: [] }));
    const tool = bridgeTool({ name: "scan", inputSchema: richSchema }, "mcp", client, baseOpts);
    expect(tool.inputSchema).toEqual(richSchema);
    // must be a clone, not the same reference
    expect(tool.inputSchema).not.toBe(richSchema);
  });

  it("defaults headless=false when no annotations are present (MCP-7)", () => {
    const client = mockClient(async () => ({ content: [] }));
    const tool = bridgeTool({ name: "t", inputSchema: { type: "object" } }, "m", client, baseOpts);
    expect(tool.headless).toBe(false);
  });

  it("honours readOnlyHint=true → headless=true", () => {
    const client = mockClient(async () => ({ content: [] }));
    const tool = bridgeTool(
      {
        name: "ls",
        inputSchema: { type: "object" },
        annotations: { readOnlyHint: true },
      },
      "m",
      client,
      baseOpts,
    );
    expect(tool.headless).toBe(true);
  });

  it("trustHeadless: true opts in to the legacy default-all-headless behaviour", () => {
    const client = mockClient(async () => ({ content: [] }));
    const tool = bridgeTool({ name: "t", inputSchema: { type: "object" } }, "m", client, {
      ...baseOpts,
      trustHeadless: true,
    });
    expect(tool.headless).toBe(true);
  });

  it("marks malformed-schema tools as non-headless even under trustHeadless", () => {
    const client = mockClient(async () => ({ content: [] }));
    const tool = bridgeTool(
      { name: "t", inputSchema: { type: "string" } as Record<string, unknown> },
      "m",
      client,
      { ...baseOpts, trustHeadless: true },
    );
    expect(tool.headless).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// deriveUniqueMcpModuleId — MCP-6 collision avoidance
// ---------------------------------------------------------------------------

describe("deriveUniqueMcpModuleId", () => {
  it("produces the base slug when unused", () => {
    expect(deriveUniqueMcpModuleId("http://localhost:3000", () => false)).toBe("localhost-3000");
  });

  it("appends -2, -3, ... on collision", () => {
    const taken = new Set<string>(["localhost-3000", "localhost-3000-2"]);
    expect(deriveUniqueMcpModuleId("http://localhost:3000", (id) => taken.has(id))).toBe(
      "localhost-3000-3",
    );
  });

  it("strips npx / node / python prefixes from stdio specs", () => {
    // `@` is stripped by the non-alphanumeric filter; leading/trailing
    // dashes from the collapse step are then trimmed.
    expect(deriveUniqueMcpModuleId("npx @acme/mcp-server", () => false)).toBe("acme-mcp-server");
    // `_` and `.` are non-alphanumeric-and-not-dash → both become `-`.
    expect(deriveUniqueMcpModuleId("python mcp_server.py", () => false)).toBe("mcp-server-py");
    expect(deriveUniqueMcpModuleId("node ./server.js", () => false)).toBe("server-js");
  });

  it("falls back to 'mcp' when the slug is empty", () => {
    expect(deriveUniqueMcpModuleId("!!!", () => false)).toBe("mcp");
  });

  it("keeps two servers with identical slugs distinct", () => {
    // Simulate the core.ts flow: registry starts empty, first load claims
    // the base slug, second load must get a -2 suffix.
    const registry = new Set<string>();
    const first = deriveUniqueMcpModuleId("http://localhost:3000/mcp", (id) => registry.has(id));
    registry.add(first);
    const second = deriveUniqueMcpModuleId("http://localhost:3000/mcp", (id) => registry.has(id));
    expect(first).not.toBe(second);
    expect(second.endsWith("-2")).toBe(true);
  });

  it("throws if it cannot find a free slot within 1000 tries", () => {
    const always = () => true;
    expect(() => deriveUniqueMcpModuleId("foo", always)).toThrow(/unique module ID/);
  });
});

// ---------------------------------------------------------------------------
// Type smoke tests — options are optional
// ---------------------------------------------------------------------------

describe("CreateMcpModuleOptions", () => {
  it("allows omitting every field", () => {
    const opts: CreateMcpModuleOptions = {};
    expect(opts).toBeDefined();
  });
});
