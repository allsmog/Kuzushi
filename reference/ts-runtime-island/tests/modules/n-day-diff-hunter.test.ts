import { afterEach, describe, expect, it, vi } from "vitest";
import {
  __nDayInternals,
  createNDayDiffHunterModule,
} from "../../src/modules/n-day-diff-hunter.js";
import type { ExecutionContext } from "../../src/modules/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const { fetchCveOrAdvisoryMock, fetchPatchTextMock, resolveRepoMock } = vi.hoisted(() => ({
  fetchCveOrAdvisoryMock: vi.fn(),
  fetchPatchTextMock: vi.fn(),
  resolveRepoMock: vi.fn(() => ({ root: "/tmp/repo", name: "repo" })),
}));

vi.mock("../../src/intel/cve-feed.js", async () => {
  const actual = await vi.importActual<typeof import("../../src/intel/cve-feed.js")>(
    "../../src/intel/cve-feed.js",
  );
  return {
    ...actual,
    fetchCveOrAdvisory: fetchCveOrAdvisoryMock,
    fetchPatchText: fetchPatchTextMock,
    choosePrimaryPatchUrl: actual.choosePrimaryPatchUrl,
  };
});

vi.mock("../../src/cli/shared.js", () => ({
  resolveRepo: resolveRepoMock,
}));

function createConfig(overrides?: Partial<KuzushiConfig>): KuzushiConfig {
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
    ...overrides,
  } as KuzushiConfig;
}

interface MockRuntime {
  id: string;
  query: (...args: unknown[]) => AsyncGenerator<unknown>;
}

function createRuntime(output: unknown, cost = 0.02): MockRuntime {
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

const sampleCveRecord = {
  id: "CVE-2024-1234",
  description: "Missing bounds check allows OOB write.",
  cwes: ["CWE-787"],
  severity: "HIGH" as const,
  cvssScore: 7.8,
  affected: ["cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"],
  patches: [{ url: "https://github.com/o/r/commit/abc1234", kind: "nvd" }],
  publishedAt: "2024-01-15T00:00:00.000",
  source: "nvd" as const,
  raw: {},
};

const samplePattern = {
  fixShape: "adds `if (len > cap) return -EINVAL;` before memcpy",
  vulnerableShape: "memcpy(dst, src, attacker_len) with no size check",
  cwe: ["CWE-787"],
  languages: ["c", "cpp"],
  keywords: ["memcpy", "len", "cap", "bounds"],
  detectionQuery: "rg 'memcpy\\(' -A 2 | grep -v 'if.*len'",
  description: "Classic bounds-check-before-copy n-day pattern.",
  confidence: "HIGH" as const,
};

afterEach(() => {
  vi.clearAllMocks();
});

describe("createNDayDiffHunterModule — tool surface", () => {
  it("exposes all three tools and the correct metadata", () => {
    const module = createNDayDiffHunterModule();
    expect(module.id).toBe("ndiff");
    expect(module.category).toBe("intel");
    expect(module.tools.map((t) => t.name).sort()).toEqual([
      "ndiff:extract-fix-pattern",
      "ndiff:fetch-cve",
      "ndiff:hunt-variants",
    ]);
  });
});

describe("ndiff:fetch-cve", () => {
  it("fetches a CVE record and returns a formatted summary", async () => {
    fetchCveOrAdvisoryMock.mockResolvedValue(sampleCveRecord);
    const module = createNDayDiffHunterModule();
    const tool = module.tools.find((t) => t.name === "ndiff:fetch-cve")!;
    const ctx = createContext(createRuntime({}));

    const result = await tool.execute({ id: "CVE-2024-1234" }, ctx);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("CVE-2024-1234");
    expect(result.output).toContain("CWE-787");
    expect(result.output).toContain("HIGH");
    const data = result.data as { record: unknown; primaryPatchUrl: string };
    expect(data.primaryPatchUrl).toBe("https://github.com/o/r/commit/abc1234");
  });

  it("returns ok=false when the advisory is not found", async () => {
    fetchCveOrAdvisoryMock.mockResolvedValue(null);
    const module = createNDayDiffHunterModule();
    const tool = module.tools.find((t) => t.name === "ndiff:fetch-cve")!;
    const ctx = createContext(createRuntime({}));

    const result = await tool.execute({ id: "CVE-1999-0001" }, ctx);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("No advisory");
  });

  it("propagates offline mode from taskConfig.ndiff-fetch.offline", async () => {
    fetchCveOrAdvisoryMock.mockResolvedValue(null);
    const module = createNDayDiffHunterModule();
    const tool = module.tools.find((t) => t.name === "ndiff:fetch-cve")!;
    const ctx = createContext(
      createRuntime({}),
      createConfig({
        taskConfig: { "ndiff-fetch": { offline: true, githubToken: "t" } },
      }),
    );

    await tool.execute({ id: "CVE-2024-1234" }, ctx);
    const [, opts] = fetchCveOrAdvisoryMock.mock.calls[0];
    expect(opts).toMatchObject({ offline: true, githubToken: "t" });
  });
});

describe("ndiff:extract-fix-pattern", () => {
  it("fetches patch text when only an id is supplied and returns pattern output", async () => {
    fetchCveOrAdvisoryMock.mockResolvedValue(sampleCveRecord);
    fetchPatchTextMock.mockResolvedValue("--- a\n+++ b\n@@ +if (len > cap) return -1;");

    const module = createNDayDiffHunterModule();
    const tool = module.tools.find((t) => t.name === "ndiff:extract-fix-pattern")!;
    const ctx = createContext(createRuntime(samplePattern, 0.11));

    const result = await tool.execute({ id: "CVE-2024-1234" }, ctx);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("Fix shape:");
    expect(result.output).toContain(samplePattern.fixShape);
    expect(result.costUsd).toBe(0.11);
    expect(fetchPatchTextMock).toHaveBeenCalledWith(
      "https://github.com/o/r/commit/abc1234",
      expect.any(Object),
    );
    const data = result.data as { pattern: typeof samplePattern };
    expect(data.pattern).toMatchObject(samplePattern);
  });

  it("uses inline patchText without fetching when supplied", async () => {
    const module = createNDayDiffHunterModule();
    const tool = module.tools.find((t) => t.name === "ndiff:extract-fix-pattern")!;
    const ctx = createContext(createRuntime(samplePattern));

    const result = await tool.execute({ patchText: "--- a\n+++ b\n+safe_check();\n" }, ctx);
    expect(result.ok).toBe(true);
    expect(fetchPatchTextMock).not.toHaveBeenCalled();
    expect(fetchCveOrAdvisoryMock).not.toHaveBeenCalled();
  });

  it("returns ok=false when neither id, patchText, nor patchUrl is supplied", async () => {
    const module = createNDayDiffHunterModule();
    const tool = module.tools.find((t) => t.name === "ndiff:extract-fix-pattern")!;
    const ctx = createContext(createRuntime({}));

    const result = await tool.execute({}, ctx);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("at least one of");
  });

  it("returns ok=false when patch fetching fails", async () => {
    fetchCveOrAdvisoryMock.mockResolvedValue(sampleCveRecord);
    fetchPatchTextMock.mockResolvedValue(null);
    const module = createNDayDiffHunterModule();
    const tool = module.tools.find((t) => t.name === "ndiff:extract-fix-pattern")!;
    const ctx = createContext(createRuntime({}));

    const result = await tool.execute({ id: "CVE-2024-1234" }, ctx);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("Could not fetch patch content");
  });
});

describe("ndiff:hunt-variants", () => {
  it("returns structured Findings for reported variants", async () => {
    const module = createNDayDiffHunterModule();
    const tool = module.tools.find((t) => t.name === "ndiff:hunt-variants")!;
    const runtime = createRuntime(
      {
        variants: [
          {
            filePath: "packages/parser/src/decode.c",
            startLine: 123,
            severity: "ERROR",
            message: "memcpy without bounds check",
            confidence: "HIGH",
            rationale: "copy size comes from untrusted header length",
            cwe: ["CWE-787"],
          },
          {
            filePath: "tests/fixtures/x.c",
            startLine: 5,
            severity: "WARNING",
            message: "low-confidence duplicate",
            confidence: "LOW",
            rationale: "probably false positive",
          },
        ],
      },
      0.2,
    );
    const ctx = createContext(runtime);

    const result = await tool.execute(
      { pattern: samplePattern, advisoryId: "CVE-2024-1234", includeVendored: true },
      ctx,
    );

    expect(result.ok).toBe(true);
    const data = result.data as {
      findings: Array<{ fingerprint: string; severity: string; cwe: string[] }>;
    };
    expect(data.findings).toHaveLength(1); // LOW confidence is skipped
    expect(data.findings[0].fingerprint).toContain("ndiff/CVE-2024-1234");
    expect(data.findings[0].severity).toBe("ERROR");
    expect(data.findings[0].cwe).toEqual(["CWE-787"]);
    expect(result.output).toContain("Variants:   1");
    expect(result.output).toContain("repo + vendored");
    expect(result.costUsd).toBe(0.2);
  });

  it("returns ok=false when pattern is missing", async () => {
    const module = createNDayDiffHunterModule();
    const tool = module.tools.find((t) => t.name === "ndiff:hunt-variants")!;
    const ctx = createContext(createRuntime({}));

    const result = await tool.execute({}, ctx);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("requires a pattern");
  });

  it("normalizeHuntResults scores findings and dedupes by fingerprint shape", () => {
    const findings = __nDayInternals.normalizeHuntResults(
      {
        variants: [
          {
            filePath: "a.c",
            startLine: 1,
            severity: "ERROR",
            message: "x",
            confidence: "HIGH",
            rationale: "r",
          },
          {
            filePath: "a.c",
            startLine: 1,
            severity: "ERROR",
            message: "y",
            confidence: "MEDIUM",
            rationale: "r2",
          },
        ],
      },
      "CVE-X",
      samplePattern,
      "repo-name",
      5,
    );
    expect(findings).toHaveLength(2);
    expect(findings[0].score).toBeGreaterThan(0);
    expect(findings[0].fingerprint.startsWith("repo-name:ndiff/CVE-X")).toBe(true);
  });
});
