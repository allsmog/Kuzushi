import { beforeEach, describe, expect, it, vi } from "vitest";
import type { TaskContext } from "../../../src/agents/types.js";
import { getTaskOutputMeta } from "../../../src/task-output-meta.js";
import type { KuzushiConfig } from "../../../src/types.js";

const { generateCryptoBehavioralHarnessMock, createPocExecutorMock } = vi.hoisted(() => ({
  generateCryptoBehavioralHarnessMock: vi.fn(),
  createPocExecutorMock: vi.fn(),
}));

vi.mock("../../../src/crypto-behavioral/harness-generator.js", () => ({
  generateCryptoBehavioralHarness: generateCryptoBehavioralHarnessMock,
  CryptoBehavioralHarnessExecutionError: class CryptoBehavioralHarnessExecutionError extends Error {
    costUsd: number;

    constructor(message: string, costUsd = 0) {
      super(message);
      this.costUsd = costUsd;
    }
  },
}));

vi.mock("../../../src/poc-executor/index.js", () => ({
  createPocExecutor: createPocExecutorMock,
}));

import {
  __cryptoBehavioralTestInternals,
  cryptoBehavioralTestTask,
} from "../../../src/agents/tasks/crypto-behavioral-test.js";

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 10,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: [],
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {
      "crypto-behavioral-test": {
        model: "anthropic:claude-haiku-4-5",
        timingIterations: 10_000,
      },
    },
    cryptoBehavioralTestEnabled: true,
    cryptoBehavioralTimeoutMs: 120_000,
    cryptoBehavioralMaxFindings: 10,
    cryptoBehavioralPerFindingBudgetUsd: 1,
    ...overrides,
  };
}

function makeFinding(ruleId = "crypto-misuse/timing-attack", fingerprint = "fp-1") {
  return {
    taskId: "crypto-misuse-detect",
    fingerprint,
    ruleId,
    filePath: "src/auth.ts",
    startLine: 12,
    severity: "WARNING",
    message: "Potential crypto misuse",
    evidence: "Potentially vulnerable behavior",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-208"],
    score: 70,
  };
}

function makeContext(
  findings: ReturnType<typeof makeFinding>[],
  configOverrides: Partial<KuzushiConfig> = {},
): TaskContext {
  return {
    runId: "run-1",
    repoRoot: "/tmp/repo",
    repoName: "repo",
    scanPath: "/tmp/repo",
    config: makeConfig(configOverrides),
    runtime: {} as TaskContext["runtime"],
    bus: {} as TaskContext["bus"],
    upstreamOutputs: new Map([
      ["secrets-crypto-detect", findings],
      [
        "context-gatherer",
        {
          repoContext: {
            languages: ["TypeScript"],
            frameworks: ["Express"],
            authPatterns: [],
            sanitizationLibs: [],
            ormOrDb: [],
            entryPoints: [],
          },
        },
      ],
    ]),
  };
}

describe("cryptoBehavioralTestTask", () => {
  beforeEach(() => {
    generateCryptoBehavioralHarnessMock.mockReset();
    createPocExecutorMock.mockReset();
    createPocExecutorMock.mockResolvedValue({
      execute: vi.fn().mockResolvedValue({
        exitCode: 0,
        stdout: "",
        stderr: "",
        timedOut: false,
        durationMs: 10,
        verdict: "PASS",
      }),
    });
  });

  it("has correct metadata and condition gating", () => {
    expect(cryptoBehavioralTestTask.id).toBe("crypto-behavioral-test");
    expect(cryptoBehavioralTestTask.outputKind).toBe("findings");
    expect(cryptoBehavioralTestTask.dependsOn).toEqual(["secrets-crypto-detect"]);

    const upstream = new Map<string, unknown>([["secrets-crypto-detect", [makeFinding()]]]);
    expect(cryptoBehavioralTestTask.condition!(upstream, makeConfig())).toBe(true);
    expect(
      cryptoBehavioralTestTask.condition!(
        upstream,
        makeConfig({ cryptoBehavioralTestEnabled: false }),
      ),
    ).toBe(false);
  });

  it("maps current crypto misuse categories to behavioral test types", () => {
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(
        makeFinding("crypto-misuse/timing-attack"),
      ),
    ).toBe("timing");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(makeFinding("crypto-misuse/ecb-mode")),
    ).toBe("ecb-mode");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(
        makeFinding("crypto-misuse/hash-for-auth"),
      ),
    ).toBe("weak-hash");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(
        makeFinding("crypto-misuse/password-storage"),
      ),
    ).toBe("weak-hash");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(
        makeFinding("crypto-misuse/insecure-prng"),
      ),
    ).toBe("weak-prng");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(
        makeFinding("crypto-misuse/key-generation"),
      ),
    ).toBe("weak-prng");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(makeFinding("crypto-misuse/key-length")),
    ).toBe("key-length");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(
        makeFinding("crypto-misuse/symmetric-cipher", "fp-ecb"),
      ),
    ).toBe("edge-case");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType({
        ...makeFinding("crypto-misuse/symmetric-cipher", "fp-ecb"),
        message: "AES-ECB mode confirmed",
      }),
    ).toBe("ecb-mode");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(makeFinding("crypto-misuse/tls-config")),
    ).toBe("edge-case");
    expect(
      __cryptoBehavioralTestInternals.mapFindingToTestType(
        makeFinding("crypto-misuse/cert-validation"),
      ),
    ).toBe("edge-case");
  });

  it("escalates proof state, appends provenance, and tracks cost", async () => {
    generateCryptoBehavioralHarnessMock.mockResolvedValue({
      costUsd: 0.25,
      result: {
        fingerprint: "fp-1",
        testType: "timing",
        scriptPath: "/tmp/repo/.kuzushi/crypto-behavioral/fp-1-timing.mjs",
        language: "javascript",
        scriptContent: "console.log('test')",
        parsed: true,
        parseError: null,
        skipped: false,
        skipReason: null,
      },
    });
    createPocExecutorMock.mockResolvedValue({
      execute: vi.fn().mockResolvedValue({
        exitCode: 0,
        stdout:
          'CRYPTO_RESULT:{"fingerprint":"fp-1","testType":"timing","verdict":"vulnerable","summary":"timing leak observed","timing":{"constantTime":false,"tStatistic":4.2,"pValue":0.001,"meanANs":101,"meanBNs":84,"iterations":10000}}',
        stderr: "",
        timedOut: false,
        durationMs: 15,
        verdict: "PASS",
      }),
    });

    const output = await cryptoBehavioralTestTask.run(undefined, makeContext([makeFinding()]));

    expect(output).toHaveLength(1);
    expect(output[0].proofState).toBe("execution_confirmed");
    expect(output[0].engineProvenance).toEqual([
      expect.objectContaining({
        kind: "dynamic",
        detail: expect.stringContaining("crypto-behavioral/timing"),
      }),
    ]);
    expect(output[0].engineProvenance?.[0]?.detail).toContain("t=4.2000");
    expect(output[0].engineProvenance?.[0]?.detail).toContain("p=0.0010");
    expect(getTaskOutputMeta(output)?.costUsd).toBeCloseTo(0.25);
  });

  it("stops later findings when a finding reaches the per-finding budget", async () => {
    generateCryptoBehavioralHarnessMock
      .mockResolvedValueOnce({
        costUsd: 1.2,
        result: {
          fingerprint: "fp-1",
          testType: "timing",
          scriptPath: null,
          language: "javascript",
          scriptContent: null,
          parsed: false,
          parseError: "parse failed",
          skipped: true,
          skipReason: "too expensive",
        },
      })
      .mockResolvedValueOnce({
        costUsd: 0.2,
        result: {
          fingerprint: "fp-2",
          testType: "weak-hash",
          scriptPath: "/tmp/repo/.kuzushi/crypto-behavioral/fp-2-weak-hash.mjs",
          language: "javascript",
          scriptContent: "console.log('test')",
          parsed: true,
          parseError: null,
          skipped: false,
          skipReason: null,
        },
      });

    const output = await cryptoBehavioralTestTask.run(
      undefined,
      makeContext([
        makeFinding("crypto-misuse/timing-attack", "fp-1"),
        makeFinding("crypto-misuse/hash-for-auth", "fp-2"),
      ]),
    );

    expect(generateCryptoBehavioralHarnessMock).toHaveBeenCalledTimes(1);
    expect(output).toHaveLength(1);
    expect(output[0].proofState).toBe("execution_attempted");
    expect(getTaskOutputMeta(output)?.costUsd).toBeCloseTo(1.2);
  });
});
