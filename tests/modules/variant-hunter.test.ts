import { afterEach, describe, expect, it, vi } from "vitest";
import type { ExecutionContext } from "../../src/modules/types.js";
import { createVariantHunterModule } from "../../src/modules/variant-hunter.js";
import type { KuzushiConfig } from "../../src/types.js";

const { analyzeVariantsMock, resolveRepoMock, getStoredFindingMock, initDbMock, dbCloseMock } =
  vi.hoisted(() => ({
    analyzeVariantsMock: vi.fn(),
    resolveRepoMock: vi.fn(() => ({ root: "/tmp/repo", name: "repo" })),
    getStoredFindingMock: vi.fn(),
    initDbMock: vi.fn(),
    dbCloseMock: vi.fn(),
  }));

vi.mock("../../src/agents/tasks/variant-analysis.js", () => ({
  analyzeVariants: analyzeVariantsMock,
}));

vi.mock("../../src/cli/shared.js", () => ({
  resolveRepo: resolveRepoMock,
}));

vi.mock("../../src/store.js", () => ({
  defaultDbPath: (root: string) => `${root}/.kuzushi/findings.sqlite3`,
  initDb: initDbMock,
  getStoredFinding: getStoredFindingMock,
}));

function createConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 5,
    triageConcurrency: 2,
    scanMode: "parallel",
    tasks: [],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
  };
}

interface MockRuntime {
  id: string;
  query: (...args: unknown[]) => AsyncGenerator<unknown>;
}

function createRuntimeWithStructuredReply(output: unknown, cost = 0.01): MockRuntime {
  return {
    id: "mock-runtime",
    async *query() {
      yield {
        type: "result",
        subtype: "success",
        result: JSON.stringify(output),
        structuredOutput: output,
        totalCostUsd: cost,
      };
    },
  };
}

function createContext(runtime: MockRuntime, config = createConfig()): ExecutionContext {
  return {
    cwd: "/tmp/repo",
    runtime: runtime as unknown as ExecutionContext["runtime"],
    bus: {} as ExecutionContext["bus"],
    config,
    target: "/tmp/repo",
  };
}

const storedFingerprint = "fp-confirmed-tp";
const storedFinding = {
  taskId: "semgrep",
  fingerprint: storedFingerprint,
  repo: "repo",
  ref: "main",
  ruleId: "javascript.express.command-injection",
  filePath: "src/api/admin.ts",
  startLine: 42,
  severity: "ERROR",
  message: "Command injection via child_process.exec",
  verdict: "tp",
  confidence: 0.9,
  rationale: "User input reaches exec without validation.",
  verificationSteps: [],
  fixPatch: null,
  triageDetails: null,
  verifyExploitable: null,
  verifyPocPayload: null,
  verifyPocDescription: null,
  verifyAttackVector: null,
  verifyPreconditions: [],
  verifyConfidence: null,
  verifyCostUsd: null,
  pocHarnessPath: null,
  pocHarnessLanguage: null,
  pocHarnessParsed: null,
  pocHarnessParseError: null,
  pocHarnessSkipped: null,
  pocHarnessSkipReason: null,
  pocHarnessCostUsd: null,
  pocRunExitCode: null,
  pocRunStdout: null,
  pocRunStderr: null,
  pocRunVerdict: null,
  pocRunDurationMs: null,
  adjustedScore: null,
  taintPath: undefined,
  proofState: undefined,
  engineProvenance: undefined,
  findingMetadata: undefined,
  corroboratingSignals: [],
  suppressionReasons: [],
  codeCitations: undefined,
  attackPath: undefined,
  assumptions: undefined,
  controls: undefined,
  blindspots: undefined,
  sourceThreatIds: undefined,
};

afterEach(() => {
  vi.clearAllMocks();
  initDbMock.mockReturnValue({ close: dbCloseMock });
});

describe("createVariantHunterModule", () => {
  it("exposes variant:lift-pattern and variant:hunt tools", () => {
    const module = createVariantHunterModule();
    const names = module.tools.map((t) => t.name).sort();
    expect(names).toEqual(["variant:hunt", "variant:lift-pattern"]);
    expect(module.id).toBe("variant");
    expect(module.category).toBe("offense");
  });

  it("variant:hunt refuses when verdict is not a confirmed TP", async () => {
    initDbMock.mockReturnValue({ close: dbCloseMock });
    getStoredFindingMock.mockReturnValue({ ...storedFinding, verdict: "needs_review" });

    const module = createVariantHunterModule();
    const tool = module.tools.find((t) => t.name === "variant:hunt")!;
    const ctx = createContext(createRuntimeWithStructuredReply({ variants: [] }));

    const result = await tool.execute({ fingerprint: storedFingerprint }, ctx);

    expect(result.ok).toBe(false);
    expect(result.output).toContain("verdict");
    expect(analyzeVariantsMock).not.toHaveBeenCalled();
    expect(dbCloseMock).toHaveBeenCalled();
  });

  it("variant:hunt delegates to analyzeVariants with extended vendored scope by default", async () => {
    initDbMock.mockReturnValue({ close: dbCloseMock });
    getStoredFindingMock.mockReturnValue(storedFinding);
    analyzeVariantsMock.mockResolvedValue({
      findings: [
        {
          taskId: "variant-analysis",
          fingerprint: "variant-fp-1",
          ruleId: "variant/javascript.express.command-injection",
          filePath: "packages/billing/src/cli.ts",
          startLine: 17,
          severity: "ERROR",
          message: "Variant: child_process.exec with unvalidated input",
          scannerConfidence: "HIGH",
          subcategory: ["vuln"],
          likelihood: "HIGH",
          impact: "HIGH",
          cwe: ["CWE-78"],
          score: 30,
        },
      ],
      costUsd: 0.42,
    });

    const module = createVariantHunterModule();
    const tool = module.tools.find((t) => t.name === "variant:hunt")!;
    const ctx = createContext(createRuntimeWithStructuredReply({ variants: [] }));

    const result = await tool.execute({ fingerprint: storedFingerprint }, ctx);

    expect(result.ok).toBe(true);
    expect(result.output).toContain("Variants found: 1");
    expect(result.output).toContain("repo + vendored");
    expect(analyzeVariantsMock).toHaveBeenCalledTimes(1);
    const callArgs = analyzeVariantsMock.mock.calls[0];
    const augmentedTriage = callArgs[1] as { rationale: string };
    expect(augmentedTriage.rationale).toContain("Extended hunt scope");
    expect(augmentedTriage.rationale).toContain("node_modules/");
    expect(augmentedTriage.rationale).toContain("vendor/");
    const resultData = result.data as { variants: unknown[] };
    expect(resultData.variants).toHaveLength(1);
  });

  it("variant:hunt omits vendored scope when includeVendored is false", async () => {
    initDbMock.mockReturnValue({ close: dbCloseMock });
    getStoredFindingMock.mockReturnValue(storedFinding);
    analyzeVariantsMock.mockResolvedValue({ findings: [], costUsd: 0 });

    const module = createVariantHunterModule();
    const tool = module.tools.find((t) => t.name === "variant:hunt")!;
    const ctx = createContext(createRuntimeWithStructuredReply({ variants: [] }));

    const result = await tool.execute(
      { fingerprint: storedFingerprint, includeVendored: false },
      ctx,
    );

    expect(result.ok).toBe(true);
    expect(result.output).toContain("repo only");
    const callArgs = analyzeVariantsMock.mock.calls[0];
    const augmentedTriage = callArgs[1] as { rationale: string };
    expect(augmentedTriage.rationale).not.toContain("Extended hunt scope");
  });

  it("variant:hunt respects custom vendorPaths override", async () => {
    initDbMock.mockReturnValue({ close: dbCloseMock });
    getStoredFindingMock.mockReturnValue(storedFinding);
    analyzeVariantsMock.mockResolvedValue({ findings: [], costUsd: 0 });

    const module = createVariantHunterModule();
    const tool = module.tools.find((t) => t.name === "variant:hunt")!;
    const ctx = createContext(createRuntimeWithStructuredReply({ variants: [] }));

    await tool.execute(
      { fingerprint: storedFingerprint, vendorPaths: ["packages", "subprojects"] },
      ctx,
    );

    const callArgs = analyzeVariantsMock.mock.calls[0];
    const augmentedTriage = callArgs[1] as { rationale: string };
    expect(augmentedTriage.rationale).toContain("packages/");
    expect(augmentedTriage.rationale).toContain("subprojects/");
    expect(augmentedTriage.rationale).not.toContain("node_modules/");
  });

  it("variant:lift-pattern returns a structured signature", async () => {
    initDbMock.mockReturnValue({ close: dbCloseMock });
    getStoredFindingMock.mockReturnValue(storedFinding);

    const signature = {
      source: "HTTP request body",
      sink: "child_process.exec",
      missingGuard: "no allowlist on command string",
      languages: ["typescript", "javascript"],
      keywords: ["exec", "spawn", "child_process"],
      description: "Untrusted input concatenated into a shell command without validation.",
    };

    const module = createVariantHunterModule();
    const tool = module.tools.find((t) => t.name === "variant:lift-pattern")!;
    const ctx = createContext(createRuntimeWithStructuredReply(signature, 0.03));

    const result = await tool.execute({ fingerprint: storedFingerprint }, ctx);

    expect(result.ok).toBe(true);
    expect(result.output).toContain("HTTP request body");
    expect(result.output).toContain("child_process.exec");
    expect(result.costUsd).toBe(0.03);
    const resultData = result.data as { signature: Record<string, unknown> };
    expect(resultData.signature).toMatchObject(signature);
  });

  it("returns an error when the fingerprint is missing from the DB", async () => {
    initDbMock.mockReturnValue({ close: dbCloseMock });
    getStoredFindingMock.mockReturnValue(undefined);

    const module = createVariantHunterModule();
    const tool = module.tools.find((t) => t.name === "variant:hunt")!;
    const ctx = createContext(createRuntimeWithStructuredReply({ variants: [] }));

    const result = await tool.execute({ fingerprint: "does-not-exist" }, ctx);

    expect(result.ok).toBe(false);
    expect(result.output).toContain("does-not-exist");
    expect(analyzeVariantsMock).not.toHaveBeenCalled();
  });
});
