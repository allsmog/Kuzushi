import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";
import {
  isMcpToolTimeoutError,
  McpToolTimeoutError,
  mcpConnectionFailureMessage,
  mcpServerConfig,
  mcpToolsForRequest,
  mcpToolTimeoutForRequest,
  normalizeMcpToolError,
  withMcpClientCleanup,
} from "./mcp.mjs";

const TIMEOUT_MESSAGE = "MCP tool timeout must be a positive safe integer in milliseconds";

function temporaryDirectory(t) {
  const directory = mkdtempSync(join(tmpdir(), "kuzushi-mcp-test-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function createSymlinkOrSkip(t, target, path, type) {
  try {
    symlinkSync(target, path, type);
    return true;
  } catch (error) {
    if (["EACCES", "EPERM", "ENOSYS"].includes(error?.code)) {
      t.skip(`symbolic links are unavailable on this platform: ${error.code}`);
      return false;
    }
    throw error;
  }
}

function requestForRoot(root, overrides = {}) {
  return {
    toolPolicy: { mcpReadRoots: [root] },
    ...overrides,
  };
}

test("MCP tool timeout accepts canonical option forms and safe integer strings", () => {
  assert.equal(mcpToolTimeoutForRequest({}), 60_000);
  assert.equal(mcpToolTimeoutForRequest({ runtimeOptions: { mcpToolTimeoutMs: 25 } }), 25);
  assert.equal(
    mcpToolTimeoutForRequest({ runtime_options: { mcp_tool_timeout_ms: "2500" } }),
    2_500,
  );
  assert.equal(
    mcpToolTimeoutForRequest({
      runtimeOptions: { mcpToolTimeoutMs: Number.MAX_SAFE_INTEGER },
    }),
    Number.MAX_SAFE_INTEGER,
  );
});

test("MCP tool timeout rejects non-positive and unsafe values", () => {
  for (const raw of [0, -1, 1.5, "", "not-a-number", Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => mcpToolTimeoutForRequest({ runtimeOptions: { mcpToolTimeoutMs: raw } }),
      new RegExp(TIMEOUT_MESSAGE),
    );
  }
  assert.throws(
    () =>
      mcpToolTimeoutForRequest({
        runtimeOptions: { mcpToolTimeoutMs: Number.MAX_SAFE_INTEGER + 1 },
      }),
    new RegExp(TIMEOUT_MESSAGE),
  );
});

test("nested MCP timeout signals normalize once and preserve the original chain", () => {
  const timeoutCause = Object.assign(new Error("adapter deadline"), {
    code: "KUZUSHI_MCP_TOOL_TIMEOUT",
  });
  const nested = new Error("request failed", {
    cause: new Error("tool wrapper failed", { cause: timeoutCause }),
  });

  assert.equal(isMcpToolTimeoutError(nested), true);
  const normalized = normalizeMcpToolError(nested);
  assert.ok(normalized instanceof McpToolTimeoutError);
  assert.equal(normalized.name, "McpToolTimeoutError");
  assert.equal(normalized.code, "KUZUSHI_MCP_TOOL_TIMEOUT");
  assert.equal(normalized.cause, nested);
  assert.equal(normalizeMcpToolError(normalized), normalized);

  const ordinary = new Error("ordinary failure");
  assert.equal(isMcpToolTimeoutError(ordinary), false);
  assert.equal(normalizeMcpToolError(ordinary), ordinary);
});

test("MCP timeout inspection is bounded by chain depth and field length", () => {
  const atFourthLevel = new Error("one", {
    cause: new Error("two", {
      cause: new Error("three", { cause: { code: "transport_timeout" } }),
    }),
  });
  const belowFourthLevel = new Error("zero", { cause: atFourthLevel });
  const signalAfterFieldLimit = new Error(`${"x".repeat(512)} timed out`);

  assert.equal(isMcpToolTimeoutError(atFourthLevel), true);
  assert.equal(isMcpToolTimeoutError(belowFourthLevel), false);
  assert.equal(isMcpToolTimeoutError(signalAfterFieldLimit), false);
});

test("MCP cleanup cannot replace an operation result or primary failure", async () => {
  let closeCalls = 0;
  const value = await withMcpClientCleanup(
    async () => "primary result",
    async () => {
      closeCalls += 1;
      throw new Error("close failed");
    },
  );
  assert.equal(value, "primary result");
  assert.equal(closeCalls, 1);

  const primary = new Error("primary failed");
  await assert.rejects(
    () =>
      withMcpClientCleanup(
        async () => {
          throw primary;
        },
        async () => {
          closeCalls += 1;
          throw new Error("close also failed");
        },
      ),
    (error) => error === primary,
  );
  assert.equal(closeCalls, 2);
});

test("MCP cleanup bounds a close operation that never settles", async () => {
  const value = await withMcpClientCleanup(
    async () => "complete",
    () => new Promise(() => {}),
    1,
  );
  assert.equal(value, "complete");
});

test("an explicitly disabled MCP request never creates a live client", async (t) => {
  const prior = process.env.KUZUSHI_AGENT_MCPS;
  process.env.KUZUSHI_AGENT_MCPS = "0";
  t.after(() => {
    if (prior === undefined) delete process.env.KUZUSHI_AGENT_MCPS;
    else process.env.KUZUSHI_AGENT_MCPS = prior;
  });

  const result = await mcpToolsForRequest({ toolPolicy: { mcps: true } });
  assert.deepEqual(result.tools, []);
  await result.close();
});

test("an authorized query cannot gain MCP tools from the compatibility switch", async (t) => {
  const prior = process.env.KUZUSHI_AGENT_MCPS;
  process.env.KUZUSHI_AGENT_MCPS = "1";
  t.after(() => {
    if (prior === undefined) delete process.env.KUZUSHI_AGENT_MCPS;
    else process.env.KUZUSHI_AGENT_MCPS = prior;
  });
  let clientCreated = false;
  const result = await mcpToolsForRequest(
    { authorization: {}, toolPolicy: { mcps: false, mcpReadRoots: [temporaryDirectory(t)] } },
    () => {
      clientCreated = true;
      return { getTools: async () => [{ name: "Write" }] };
    },
  );

  assert.equal(clientCreated, false);
  assert.deepEqual(result.tools, []);
});

test("MCP discovery failure closes the partial client and becomes permanently typed", async (t) => {
  const root = temporaryDirectory(t);
  let closeCalls = 0;
  const createClient = () => ({
    getTools: async () => {
      throw new Error("spawn kuzushi-mcp-treesitter ENOENT");
    },
    close: async () => {
      closeCalls += 1;
    },
  });

  await assert.rejects(
    () =>
      mcpToolsForRequest(
        requestForRoot(root, { toolPolicy: { mcps: true, mcpReadRoots: [root] } }),
        createClient,
      ),
    (error) =>
      error.errorClass === "mcp_unavailable" &&
      error.message.includes("cargo build --workspace") &&
      !error.message.includes("ENOENT"),
  );
  assert.equal(closeCalls, 1);
});

test("MCP client construction failures are typed before provider work", async (t) => {
  const root = temporaryDirectory(t);
  const createClient = () => {
    throw new Error("invalid MCP startup configuration");
  };

  await assert.rejects(
    () =>
      mcpToolsForRequest(
        requestForRoot(root, { toolPolicy: { mcps: true, mcpReadRoots: [root] } }),
        createClient,
      ),
    (error) => error.errorClass === "mcp_unavailable",
  );
});

test("connection failures select bounded diagnostics and survive circular causes", () => {
  const message = mcpConnectionFailureMessage(
    { server: { name: "cpg" }, config: { command: "ignored-command" } },
    { cause: { message: "permission denied" } },
    { cpg: { command: "configured-cpg" } },
  );
  assert.equal(
    message,
    "requested MCP server cpg failed to start (command: configured-cpg): permission denied",
  );

  const circular = {};
  circular.self = circular;
  assert.equal(
    mcpConnectionFailureMessage({}, circular),
    "requested MCP server unknown failed to start (command: unknown): connection failed without a reported cause",
  );
});

test("read roots and cwd are canonicalized, deduplicated, and environment-filtered", (t) => {
  const temporary = temporaryDirectory(t);
  const root = join(temporary, "allowed");
  const cwd = join(root, "nested");
  const rootAlias = join(temporary, "allowed-link");
  mkdirSync(cwd, { recursive: true });
  if (!createSymlinkOrSkip(t, root, rootAlias, "dir")) return;

  const config = mcpServerConfig({
    cwd,
    runtimeOptions: {
      mcpEnvironment: {
        HOME: "/controlled-home",
        PATH: "/controlled-bin",
        SECRET_TOKEN: "must-not-cross-boundary",
      },
    },
    toolPolicy: { mcpReadRoots: [rootAlias, root] },
  });
  const canonicalRoot = realpathSync(root);
  const canonicalCwd = realpathSync(cwd);

  assert.deepEqual(Object.keys(config), ["treesitter", "cpg", "codeql"]);
  for (const server of Object.values(config)) {
    assert.equal(server.cwd, canonicalCwd);
    assert.equal(server.env.PATH, "/controlled-bin");
    assert.deepEqual(JSON.parse(server.env.KUZUSHI_MCP_READ_ROOTS), [canonicalRoot]);
    assert.equal(Object.hasOwn(server.env, "SECRET_TOKEN"), false);
  }
  assert.equal(config.treesitter.env.HOME, undefined);
  assert.equal(config.cpg.env.HOME, undefined);
  assert.equal(config.codeql.env.HOME, "/controlled-home");
});

test("cwd outside a read root, including a symlink escape, falls back to that root", (t) => {
  const temporary = temporaryDirectory(t);
  const root = join(temporary, "scope");
  const outside = join(temporary, "scope-sibling");
  const escapePath = join(root, "escape");
  mkdirSync(root);
  mkdirSync(outside);
  const canonicalRoot = realpathSync(root);

  assert.equal(mcpServerConfig(requestForRoot(root, { cwd: outside })).treesitter.cwd, canonicalRoot);
  if (!createSymlinkOrSkip(t, outside, escapePath, "dir")) return;
  assert.equal(
    mcpServerConfig(requestForRoot(root, { cwd: escapePath })).treesitter.cwd,
    canonicalRoot,
  );
});

test("planned artifacts resolve only inside read roots and preserve authenticated identity", (t) => {
  const temporary = temporaryDirectory(t);
  const root = join(temporary, "allowed");
  const artifact = join(root, "cpg.bin");
  mkdirSync(root);
  writeFileSync(artifact, "authenticated artifact");

  const config = mcpServerConfig({
    cwd: root,
    runtime_options: { mcp_environment: { PATH: "/controlled-bin" } },
    toolPolicy: {
      mcp_read_roots: [root],
      mcps_attached: [
        {
          name: "cpg",
          artifact_path: artifact,
          artifact_identity: "sha256:trusted",
        },
        {
          name: "threat-model",
          artifact_path: artifact,
          artifact_identity: "sha256:selected-context",
        },
      ],
    },
  });

  assert.deepEqual(Object.keys(config), ["cpg", "threat-model"]);
  assert.equal(config.cpg.cwd, realpathSync(root));
  assert.equal(config.cpg.env.KUZUSHI_MCP_CPG_ARTIFACT, realpathSync(artifact));
  assert.equal(config.cpg.env.KUZUSHI_MCP_CPG_ARTIFACT_IDENTITY, "sha256:trusted");
  assert.equal(config["threat-model"].env.KUZUSHI_MCP_THREAT_MODEL_ARTIFACT_IDENTITY, "sha256:selected-context");
  assert.equal(config["threat-model"].env.KUZUSHI_MCP_THREAT_MODEL_ARTIFACT, realpathSync(artifact));
  assert.deepEqual(JSON.parse(config.cpg.env.KUZUSHI_MCP_READ_ROOTS), [realpathSync(root)]);
});

test("planned artifacts reject sibling paths, missing paths, and symlink escapes", (t) => {
  const temporary = temporaryDirectory(t);
  const root = join(temporary, "artifact-root");
  const sibling = join(temporary, "artifact-root-sibling");
  const outsideArtifact = join(sibling, "outside.bin");
  const escapePath = join(root, "escape.bin");
  mkdirSync(root);
  mkdirSync(sibling);
  writeFileSync(outsideArtifact, "outside");

  const configForArtifact = (artifactPath) => ({
    toolPolicy: {
      mcpReadRoots: [root],
      mcpsAttached: [{ name: "cpg", artifactPath }],
    },
  });

  assert.throws(
    () => mcpServerConfig(configForArtifact(outsideArtifact)),
    /planned MCP artifact is outside the read roots/,
  );
  assert.throws(
    () => mcpServerConfig(configForArtifact(join(root, "missing.bin"))),
    /planned MCP artifact is unavailable/,
  );

  if (!createSymlinkOrSkip(t, outsideArtifact, escapePath, "file")) return;
  assert.throws(
    () => mcpServerConfig(configForArtifact(escapePath)),
    /planned MCP artifact is outside the read roots/,
  );
});

test("invalid or absent read roots fail closed before server attachment", (t) => {
  const temporary = temporaryDirectory(t);
  const file = join(temporary, "not-a-directory");
  writeFileSync(file, "file");

  assert.deepEqual(mcpServerConfig({ toolPolicy: { mcpsAttached: [{ name: "cpg" }] } }), {});
  assert.throws(
    () => mcpServerConfig({ toolPolicy: { mcpReadRoots: [""] } }),
    /MCP read roots must be non-empty path strings/,
  );
  assert.throws(
    () => mcpServerConfig({ toolPolicy: { mcpReadRoots: [join(temporary, "missing")] } }),
    /MCP read root is unavailable/,
  );
  assert.throws(
    () => mcpServerConfig({ toolPolicy: { mcpReadRoots: [file] } }),
    /MCP read root is not a directory/,
  );
});
