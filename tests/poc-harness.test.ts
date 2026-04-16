import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AgentMessage, AgentQueryRequest, AgentRuntime } from "../src/agent-runtime/types.js";
import {
  buildPocHarnessPrompt,
  generatePocHarness,
  POC_HARNESS_RESULT_SCHEMA,
  PocHarnessExecutionError,
  parsePocHarnessOutput,
  pocHarnessSystemPromptPrefix,
} from "../src/poc-harness.js";
import type { Finding } from "../src/scanners/types.js";
import type { TriageResult, VerificationResult } from "../src/types.js";

const tempDirs: string[] = [];

function makeFinding(): Finding {
  return {
    taskId: "semgrep",
    fingerprint: "poc-fp-1",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 10,
    severity: "ERROR",
    message: "Possible SQL injection",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 88,
  };
}

function makeTriageResult(verdict: TriageResult["verdict"] = "tp"): TriageResult {
  return {
    fingerprint: "poc-fp-1",
    verdict,
    confidence: 0.93,
    rationale: "User input appears attacker-controlled at sink.",
    verificationSteps: ["Trace source to sink", "Check sanitization"],
    fixPatch: null,
  };
}

function makeVerificationResult(exploitable = true): VerificationResult {
  return {
    fingerprint: "poc-fp-1",
    exploitable,
    pocPayload: "' OR 1=1 --",
    pocDescription: "Inject payload into query path.",
    attackVector: "query string",
    preconditions: ["Endpoint is reachable"],
    confidence: 0.9,
  };
}

function stream(messages: AgentMessage[]): AsyncIterable<AgentMessage> {
  return (async function* () {
    for (const message of messages) {
      yield message;
    }
  })();
}

function makeRuntime(
  messages: AgentMessage[],
  requests: AgentQueryRequest[],
  id = "test-runtime",
): AgentRuntime {
  return {
    id,
    query(request) {
      requests.push(request);
      return stream(messages);
    },
  };
}

function makeTempRepo(): string {
  const repo = mkdtempSync(path.join(os.tmpdir(), "kuzushi-poc-test-"));
  tempDirs.push(repo);
  return repo;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("buildPocHarnessPrompt", () => {
  it("includes finding and verification context but not static directives (moved to system prompt)", () => {
    const prompt = buildPocHarnessPrompt(
      makeFinding(),
      makeTriageResult(),
      makeVerificationResult(),
      "repo",
    );

    expect(prompt).toContain("security PoC harness generator");
    expect(prompt).toContain("BEFORE generating code, use Read");
    expect(prompt).not.toContain("Import the REAL function");
    expect(prompt).not.toContain("SQL injection (CWE-89)");
    expect(prompt).toContain("PoC payload: ' OR 1=1 --");
    expect(prompt).toContain("Fingerprint: poc-fp-1");
  });

  it("pocHarnessSystemPromptPrefix includes harness strategy templates and anti-hallucination constraints", () => {
    const prefix = pocHarnessSystemPromptPrefix();

    expect(prefix).toContain("Import the REAL function");
    expect(prefix).toContain("SQL injection (CWE-89)");
    expect(prefix).toContain("Anti-hallucination constraints");
    expect(prefix).toContain("Do NOT simulate the vulnerable function");
    expect(prefix).toContain("Harness strategy templates");
  });
});

describe("parsePocHarnessOutput", () => {
  it("parses structured object output", () => {
    const parsed = parsePocHarnessOutput(
      {
        fingerprint: "poc-fp-1",
        script_content: "console.log('PASS');",
        language: "javascript",
        skipped: false,
        skip_reason: null,
      },
      "fallback",
    );

    expect(parsed.fingerprint).toBe("poc-fp-1");
    expect(parsed.scriptContent).toContain("PASS");
    expect(parsed.language).toBe("javascript");
    expect(parsed.skipped).toBe(false);
  });

  it("parses string output and skipped cases", () => {
    const parsed = parsePocHarnessOutput(
      JSON.stringify({
        script_content: null,
        language: "typescript",
        skipped: true,
        skip_reason: "Function cannot be isolated safely.",
      }),
      "fallback-fp",
    );

    expect(parsed.fingerprint).toBe("fallback-fp");
    expect(parsed.skipped).toBe(true);
    expect(parsed.skipReason).toContain("cannot be isolated");
  });

  it("throws a clear error for malformed JSON", () => {
    expect(() => parsePocHarnessOutput("not-json", "fallback-fp")).toThrow(
      "Invalid PoC harness JSON response",
    );
  });
});

describe("generatePocHarness", () => {
  it("captures total cost and passes schema/tools to runtime", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [
        {
          type: "result",
          subtype: "success",
          result: "{}",
          structuredOutput: {
            fingerprint: "poc-fp-1",
            script_content: null,
            language: "typescript",
            skipped: true,
            skip_reason: "Cannot isolate vulnerable function from runtime dependencies.",
          },
          totalCostUsd: 0.0112,
        },
      ],
      requests,
    );

    const repoRoot = makeTempRepo();
    const output = await generatePocHarness(
      makeFinding(),
      makeTriageResult(),
      makeVerificationResult(),
      repoRoot,
      "repo",
      "claude-haiku-4-5-20251001",
      { runtime },
    );

    expect(output.result.skipped).toBe(true);
    expect(output.result.scriptPath).toBeNull();
    expect(output.costUsd).toBe(0.0112);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.options?.allowedTools).toEqual([
      "Read",
      "Glob",
      "Grep",
      "GetCallers",
      "GetCallees",
      "GetFunctionBody",
      "GoToDefinition",
      "FindReferences",
      "TypeAtPosition",
    ]);
    expect(requests[0]?.options?.outputFormat?.schema).toBe(POC_HARNESS_RESULT_SCHEMA);
  });

  it("uses semantic navigation tools when the runtime is pi-ai", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [
        {
          type: "result",
          subtype: "success",
          result: "{}",
          structuredOutput: {
            fingerprint: "poc-fp-1",
            script_content: null,
            language: "typescript",
            skipped: true,
            skip_reason: "skip",
          },
        },
      ],
      requests,
      "pi-ai",
    );

    await generatePocHarness(
      makeFinding(),
      makeTriageResult(),
      makeVerificationResult(),
      makeTempRepo(),
      "repo",
      "claude-haiku-4-5-20251001",
      { runtime },
    );

    expect(requests[0]?.options?.allowedTools).toEqual([
      "Read",
      "Glob",
      "Grep",
      "GetCallers",
      "GetCallees",
      "GetFunctionBody",
      "GoToDefinition",
      "FindReferences",
      "TypeAtPosition",
    ]);
  }, 15_000);

  it("writes generated scripts and validates syntax", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [
        {
          type: "result",
          subtype: "success",
          result: "{}",
          structuredOutput: {
            fingerprint: "poc-fp-1",
            script_content: "console.log('PASS');\nprocess.exit(0);\n",
            language: "javascript",
            skipped: false,
            skip_reason: null,
          },
          totalCostUsd: 0.0042,
        },
      ],
      requests,
    );

    const repoRoot = makeTempRepo();
    const output = await generatePocHarness(
      makeFinding(),
      makeTriageResult(),
      makeVerificationResult(),
      repoRoot,
      "repo",
      "claude-haiku-4-5-20251001",
      { runtime },
    );

    expect(output.result.skipped).toBe(false);
    expect(output.result.scriptPath).toContain(path.join(".kuzushi", "poc"));
    expect(path.basename(output.result.scriptPath as string)).toMatch(/^poc-fp-1-cwe89\./);
    expect(existsSync(output.result.scriptPath as string)).toBe(true);
    expect(output.result.parsed).toBe(true);
    expect(readFileSync(output.result.scriptPath as string, "utf-8")).toContain("PASS");
  }, 15_000);

  it("throws PocHarnessExecutionError with cost on parse failure", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [
        {
          type: "result",
          subtype: "success",
          result: "not-json",
          totalCostUsd: 0.009,
        },
      ],
      requests,
    );

    const repoRoot = makeTempRepo();

    try {
      await generatePocHarness(
        makeFinding(),
        makeTriageResult(),
        makeVerificationResult(),
        repoRoot,
        "repo",
        "claude-haiku-4-5-20251001",
        { runtime },
      );
      expect.unreachable("Expected poc harness generation to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(PocHarnessExecutionError);
      expect((error as PocHarnessExecutionError).costUsd).toBe(0.009);
      expect((error as Error).message).toContain("poc harness output parse failed");
    }
  });

  it("throws PocHarnessExecutionError for non-success agent result subtype", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [
        {
          type: "result",
          subtype: "error_max_turns",
          errors: ["max turns exceeded"],
          totalCostUsd: 0.003,
        },
      ],
      requests,
    );

    const repoRoot = makeTempRepo();

    await expect(() =>
      generatePocHarness(
        makeFinding(),
        makeTriageResult(),
        makeVerificationResult(),
        repoRoot,
        "repo",
        "claude-haiku-4-5-20251001",
        { runtime },
      ),
    ).rejects.toMatchObject({
      name: "PocHarnessExecutionError",
      costUsd: 0.003,
    });
  });

  it("fills default skip reason when agent omits it", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [
        {
          type: "result",
          subtype: "success",
          result: "{}",
          structuredOutput: {
            fingerprint: "poc-fp-1",
            script_content: null,
            language: "typescript",
            skipped: true,
            skip_reason: null,
          },
        },
      ],
      requests,
    );

    const repoRoot = makeTempRepo();
    const output = await generatePocHarness(
      makeFinding(),
      makeTriageResult(),
      makeVerificationResult(),
      repoRoot,
      "repo",
      "claude-haiku-4-5-20251001",
      { runtime },
    );

    expect(output.result.skipped).toBe(true);
    expect(output.result.skipReason).toContain("without a reason");
  });
});
