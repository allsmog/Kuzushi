import { mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import { mcpServerConfig } from "../../scripts/langgraph-bridge/mcp.mjs";

type ServerConfig = Record<
  string,
  { transport: string; command: string; cwd?: string; env: Record<string, string> }
>;

const repoRoot = realpathSync(process.cwd());
const repoArtifact = realpathSync(join(repoRoot, "Cargo.toml"));

function requestWithPlan(plan: unknown): unknown {
  return {
    cwd: process.cwd(),
    toolPolicy: {
      profile: "default",
      mcps: true,
      mcpsAttached: plan,
      mcpReadRoots: [process.cwd()],
    },
  };
}

describe("bridge MCP attachment plan", () => {
  it("attaches exactly the planned servers with artifact env", () => {
    const config = mcpServerConfig(
      requestWithPlan([
        { name: "context", artifactPath: repoArtifact },
        { name: "entry-points", artifactPath: repoArtifact },
        { name: "joern", artifactPath: repoArtifact },
        { name: "treesitter" },
      ]),
    ) as ServerConfig;

    expect(Object.keys(config).sort()).toEqual(["context", "entry-points", "joern", "treesitter"]);
    expect(config.context.command).toBe("kuzushi-mcp-context");
    expect(config.context.env.KUZUSHI_MCP_CONTEXT_ARTIFACT).toBe(repoArtifact);
    expect(config["entry-points"].env.KUZUSHI_MCP_ENTRY_POINTS_ARTIFACT).toBe(repoArtifact);
    expect(config.joern.env.KUZUSHI_JOERN_CPG).toBe(repoArtifact);
    expect(JSON.parse(config.joern.env.KUZUSHI_MCP_READ_ROOTS)).toEqual([
      realpathSync(process.cwd()),
    ]);
    expect(JSON.parse(config.treesitter.env.KUZUSHI_MCP_READ_ROOTS)).toEqual([
      realpathSync(process.cwd()),
    ]);
    expect(JSON.parse(config.context.env.KUZUSHI_MCP_READ_ROOTS)).toEqual([repoRoot]);
    expect(config.context.cwd).toBe(realpathSync(process.cwd()));
    expect(config.treesitter.env.KUZUSHI_MCP_TREESITTER_ARTIFACT).toBeUndefined();
  });

  it("never attaches unplanned servers when a plan is present", () => {
    const config = mcpServerConfig(
      requestWithPlan([{ name: "treesitter" }, { name: "context", artifactPath: repoArtifact }]),
    ) as ServerConfig;

    expect(config.joern).toBeUndefined();
    expect(config.codeql).toBeUndefined();
  });

  it("honors KUZUSHI_MCP_<NAME>_BIN overrides for planned servers", () => {
    process.env.KUZUSHI_MCP_THREAT_MODEL_BIN = "/opt/custom/threat-model";
    try {
      const config = mcpServerConfig(
        requestWithPlan([{ name: "threat-model", artifactPath: repoArtifact }]),
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
        mcps_attached: [{ name: "codeql", artifact_path: repoArtifact }],
        mcp_read_roots: [process.cwd()],
      },
    }) as ServerConfig;

    expect(Object.keys(config)).toEqual(["codeql"]);
    expect(config.codeql.env.KUZUSHI_MCP_CODEQL_ARTIFACT).toBe(repoArtifact);
    expect(JSON.parse(config.codeql.env.KUZUSHI_MCP_READ_ROOTS)).toEqual([
      realpathSync(process.cwd()),
    ]);
  });

  it("falls back to the legacy trio when no plan is supplied", () => {
    const config = mcpServerConfig({
      cwd: process.cwd(),
      toolPolicy: { profile: "default", mcps: true, mcpReadRoots: [process.cwd()] },
    }) as ServerConfig;

    expect(Object.keys(config).sort()).toEqual(["codeql", "joern", "treesitter"]);
    expect(config.codeql.env.KUZUSHI_MCP_READ_ROOTS).toBe(
      config.treesitter.env.KUZUSHI_MCP_READ_ROOTS,
    );
  });

  it("does not spread ambient secrets and keeps server env allowlists separate", () => {
    process.env.KUZUSHI_TEST_AMBIENT_SECRET = "must-not-reach-child";
    process.env.JOERN_SERVER_URL = "http://127.0.0.1:9999";
    process.env.KUZUSHI_CODEQL_PREWARM = "1";
    try {
      const config = mcpServerConfig(
        requestWithPlan([{ name: "treesitter" }, { name: "joern" }, { name: "codeql" }]),
      ) as ServerConfig;

      expect(config.treesitter.env.KUZUSHI_TEST_AMBIENT_SECRET).toBeUndefined();
      expect(config.joern.env.KUZUSHI_TEST_AMBIENT_SECRET).toBeUndefined();
      expect(config.codeql.env.KUZUSHI_TEST_AMBIENT_SECRET).toBeUndefined();
      expect(config.joern.env.JOERN_SERVER_URL).toBe("http://127.0.0.1:9999");
      expect(config.joern.env.KUZUSHI_CODEQL_PREWARM).toBeUndefined();
      expect(config.codeql.env.KUZUSHI_CODEQL_PREWARM).toBe("1");
      expect(config.codeql.env.JOERN_SERVER_URL).toBeUndefined();
    } finally {
      delete process.env.KUZUSHI_TEST_AMBIENT_SECRET;
      delete process.env.JOERN_SERVER_URL;
      delete process.env.KUZUSHI_CODEQL_PREWARM;
    }
  });

  it("refuses to attach any child without an explicit read root", () => {
    const config = mcpServerConfig({
      cwd: "/definitely/missing/kuzushi-target",
      toolPolicy: { profile: "default", mcps: true, mcpsAttached: [{ name: "treesitter" }] },
    }) as ServerConfig;

    expect(config).toEqual({});
  });

  it("uses an authorized root when the requested child cwd is missing or outside", () => {
    for (const cwd of ["/definitely/missing/kuzushi-target", "/"]) {
      const config = mcpServerConfig({
        cwd,
        toolPolicy: {
          profile: "default",
          mcps: true,
          mcpsAttached: [{ name: "treesitter" }],
          mcpReadRoots: [process.cwd()],
        },
      }) as ServerConfig;

      expect(config.treesitter.cwd).toBe(realpathSync(process.cwd()));
      expect(JSON.parse(config.treesitter.env.KUZUSHI_MCP_READ_ROOTS)).toEqual([
        realpathSync(process.cwd()),
      ]);
    }
  });

  it("rejects planned artifacts outside the read roots", () => {
    const outsideRoot = mkdtempSync(join(tmpdir(), "kuzushi-mcp-outside-"));
    const outsideArtifact = join(outsideRoot, "artifact.json");
    writeFileSync(outsideArtifact, "{}");
    try {
      expect(() =>
        mcpServerConfig(requestWithPlan([{ name: "context", artifactPath: outsideArtifact }])),
      ).toThrow(/outside the read roots/);
    } finally {
      rmSync(outsideRoot, { recursive: true, force: true });
    }
  });

  it("rejects a planned symlink that escapes the read roots", () => {
    const outsideRoot = mkdtempSync(join(tmpdir(), "kuzushi-mcp-outside-"));
    const outsideArtifact = join(outsideRoot, "artifact.json");
    const link = join(repoRoot, `.kuzushi-mcp-test-link-${process.pid}`);
    writeFileSync(outsideArtifact, "{}");
    symlinkSync(outsideArtifact, link);
    try {
      expect(() =>
        mcpServerConfig(requestWithPlan([{ name: "context", artifactPath: link }])),
      ).toThrow(/outside the read roots/);
    } finally {
      rmSync(link, { force: true });
      rmSync(outsideRoot, { recursive: true, force: true });
    }
  });
});
