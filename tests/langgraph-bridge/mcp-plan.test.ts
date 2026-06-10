import { describe, expect, it } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import { mcpServerConfig } from "../../scripts/langgraph-bridge/mcp.mjs";

type ServerConfig = Record<
  string,
  { transport: string; command: string; cwd: string; env: Record<string, string> }
>;

function requestWithPlan(plan: unknown): unknown {
  return { cwd: process.cwd(), toolPolicy: { profile: "default", mcps: true, mcpsAttached: plan } };
}

describe("bridge MCP attachment plan", () => {
  it("attaches exactly the planned servers with artifact env", () => {
    const config = mcpServerConfig(
      requestWithPlan([
        { name: "context", artifactPath: "/repo/.kuzushi/context-snapshot.json" },
        { name: "entry-points", artifactPath: "/repo/.kuzushi/entry-points.json" },
        { name: "joern", artifactPath: "/repo/.kuzushi/cpg.bin" },
        { name: "treesitter" },
      ]),
    ) as ServerConfig;

    expect(Object.keys(config).sort()).toEqual(["context", "entry-points", "joern", "treesitter"]);
    expect(config.context.command).toBe("kuzushi-mcp-context");
    expect(config.context.env.KUZUSHI_MCP_CONTEXT_ARTIFACT).toBe(
      "/repo/.kuzushi/context-snapshot.json",
    );
    expect(config["entry-points"].env.KUZUSHI_MCP_ENTRY_POINTS_ARTIFACT).toBe(
      "/repo/.kuzushi/entry-points.json",
    );
    expect(config.joern.env.KUZUSHI_JOERN_CPG).toBe("/repo/.kuzushi/cpg.bin");
    expect(config.treesitter.env.KUZUSHI_MCP_TREESITTER_ARTIFACT).toBeUndefined();
  });

  it("never attaches unplanned servers when a plan is present", () => {
    const config = mcpServerConfig(
      requestWithPlan([{ name: "treesitter" }, { name: "context", artifactPath: "/a" }]),
    ) as ServerConfig;

    expect(config.joern).toBeUndefined();
    expect(config.codeql).toBeUndefined();
  });

  it("honors KUZUSHI_MCP_<NAME>_BIN overrides for planned servers", () => {
    process.env.KUZUSHI_MCP_THREAT_MODEL_BIN = "/opt/custom/threat-model";
    try {
      const config = mcpServerConfig(
        requestWithPlan([
          { name: "threat-model", artifactPath: "/repo/.kuzushi/threat-model.json" },
        ]),
      ) as ServerConfig;
      expect(config["threat-model"].command).toBe("/opt/custom/threat-model");
    } finally {
      delete process.env.KUZUSHI_MCP_THREAT_MODEL_BIN;
    }
  });

  it("accepts snake_case plans from older policy serializers", () => {
    const config = mcpServerConfig({
      cwd: process.cwd(),
      toolPolicy: {
        profile: "default",
        mcps: true,
        mcps_attached: [{ name: "codeql", artifact_path: "/repo/.kuzushi/codeql-db" }],
      },
    }) as ServerConfig;

    expect(Object.keys(config)).toEqual(["codeql"]);
    expect(config.codeql.env.KUZUSHI_MCP_CODEQL_ARTIFACT).toBe("/repo/.kuzushi/codeql-db");
  });

  it("falls back to the legacy trio when no plan is supplied", () => {
    const config = mcpServerConfig({
      cwd: process.cwd(),
      toolPolicy: { profile: "default", mcps: true },
    }) as ServerConfig;

    expect(Object.keys(config).sort()).toEqual(["codeql", "joern", "treesitter"]);
  });
});
