import { describe, expect, it } from "vitest";
import type { AgentMessage, AgentQueryRequest, AgentRuntime } from "../src/agent-runtime/types.js";
import type { Finding } from "../src/scanners/types.js";
import type { TriageResult } from "../src/types.js";
import {
  buildVerificationPrompt,
  parseVerificationOutput,
  VERIFICATION_RESULT_SCHEMA,
  VerificationExecutionError,
  verificationSystemPromptPrefix,
  verifyFindingsBatch,
  verifyFindingWithAgent,
} from "../src/verify.js";

function makeFinding(): Finding {
  return {
    scanner: "semgrep",
    fingerprint: "verify-fp",
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
    fingerprint: "verify-fp",
    verdict,
    confidence: 0.93,
    rationale: "User input appears attacker-controlled at sink.",
    verificationSteps: ["Trace source to sink", "Check sanitization"],
    fixPatch: null,
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

describe("buildVerificationPrompt", () => {
  it("includes finding details and triage context", () => {
    const prompt = buildVerificationPrompt(makeFinding(), makeTriageResult(), "repo");

    expect(prompt).toContain("exploit engineer");
    expect(prompt).toContain("Repo: repo");
    expect(prompt).toContain("Rule: test.rule");
    expect(prompt).toContain("Fingerprint: verify-fp");
    expect(prompt).toContain("Verdict: tp");
    expect(prompt).toContain("User input appears attacker-controlled");
  });

  it("does not include repository context in user prompt (moved to system prompt)", () => {
    const prompt = buildVerificationPrompt(makeFinding(), makeTriageResult(), "repo");

    expect(prompt).not.toContain("## Repository Context");
  });

  it("verificationSystemPromptPrefix includes repository context when provided", () => {
    const prefix = verificationSystemPromptPrefix({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      authPatterns: ["JWT"],
      sanitizationLibs: ["helmet"],
      ormOrDb: ["Prisma"],
      entryPoints: ["src/pages/api/*"],
    });

    expect(prefix).toContain("## Repository Context");
    expect(prefix).toContain("Languages: TypeScript");
    expect(prefix).toContain("ORM/DB: Prisma");
  });

  it("does not include Proof Level Framework and Bypass Exhaustion Protocol in user prompt (moved to system prompt)", () => {
    const prompt = buildVerificationPrompt(makeFinding(), makeTriageResult(), "repo");

    expect(prompt).not.toContain("Proof Level Framework");
    expect(prompt).not.toContain("Bypass Exhaustion Protocol");
  });

  it("verificationSystemPromptPrefix includes Proof Level Framework and Bypass Exhaustion Protocol", () => {
    const prefix = verificationSystemPromptPrefix();

    expect(prefix).toContain("Proof Level Framework");
    expect(prefix).toContain("Level 1: Theoretical weakness identified");
    expect(prefix).toContain("Level 4: Account takeover demonstrated");
    expect(prefix).toContain("Bypass Exhaustion Protocol");
    expect(prefix).toContain("Direct exploitation with obvious payload");
    expect(prefix).toContain("Encoding bypass");
  });

  it("includes bypass techniques for SQLi CWE", () => {
    const prompt = buildVerificationPrompt(makeFinding(), makeTriageResult(), "repo");

    expect(prompt).toContain("Category-Specific Bypass Techniques");
    expect(prompt).toContain("SQL Injection");
    expect(prompt).toContain("Comment injection");
    expect(prompt).toContain("Wide-byte injection");
  });

  it("does not include Confidence Escalation Protocol in user prompt (moved to system prompt)", () => {
    const prompt = buildVerificationPrompt(makeFinding(), makeTriageResult(), "repo");

    expect(prompt).not.toContain("Confidence Escalation Protocol");
  });

  it("verificationSystemPromptPrefix includes Confidence Escalation Protocol for verification", () => {
    const prefix = verificationSystemPromptPrefix();

    expect(prefix).toContain("Confidence Escalation Protocol");
    expect(prefix).toContain("Start at 0.1");
  });

  it("verificationSystemPromptPrefix appends extraPromptContext when provided", () => {
    const extra = "## CWE-89 Knowledge\nSQL injection in parameterized queries requires unescaped interpolation.";
    const prefix = verificationSystemPromptPrefix(undefined, undefined, extra);

    expect(prefix).toContain(extra);
    // Also still includes standard modules
    expect(prefix).toContain("Proof Level Framework");
  });

  it("verificationSystemPromptPrefix omits extra block when extraPromptContext is undefined", () => {
    const withExtra = verificationSystemPromptPrefix(undefined, undefined, "extra context");
    const without = verificationSystemPromptPrefix(undefined, undefined, undefined);

    expect(withExtra).toContain("extra context");
    expect(without).not.toContain("extra context");
  });
});

describe("parseVerificationOutput", () => {
  it("parses structured object output", () => {
    const parsed = parseVerificationOutput({
      fingerprint: "verify-fp",
      exploitable: true,
      poc_payload: "' OR 1=1 --",
      poc_description: "Inject payload into login form.",
      attack_vector: "HTTP body",
      preconditions: ["Attacker can reach login endpoint"],
      confidence: 0.87,
    }, "fallback");

    expect(parsed.fingerprint).toBe("verify-fp");
    expect(parsed.exploitable).toBe(true);
    expect(parsed.pocPayload).toBe("' OR 1=1 --");
    expect(parsed.attackVector).toBe("HTTP body");
    expect(parsed.preconditions).toEqual(["Attacker can reach login endpoint"]);
    expect(parsed.confidence).toBe(0.87);
  });

  it("parses string output and clamps confidence", () => {
    const parsed = parseVerificationOutput(
      JSON.stringify({
        exploitable: false,
        poc_payload: null,
        poc_description: "Input is sanitized before sink.",
        attack_vector: null,
        preconditions: [],
        confidence: 3,
      }),
      "fallback-fp",
    );

    expect(parsed.fingerprint).toBe("fallback-fp");
    expect(parsed.exploitable).toBe(false);
    expect(parsed.pocPayload).toBeNull();
    expect(parsed.confidence).toBe(1);
  });

  it("throws for malformed JSON instead of synthesizing a conservative result", () => {
    expect(() => parseVerificationOutput("not-json", "fallback-fp"))
      .toThrow("Invalid verification JSON response");
  });

  it("parses proof_level and proof_verdict from output", () => {
    const parsed = parseVerificationOutput({
      fingerprint: "verify-fp",
      exploitable: true,
      poc_payload: "payload",
      poc_description: "desc",
      attack_vector: "network",
      preconditions: [],
      confidence: 0.9,
      proof_level: 3,
      proof_verdict: "exploited",
      bypass_attempts: ["Direct injection", "Encoding bypass"],
    }, "fallback");

    expect(parsed.proofLevel).toBe(3);
    expect(parsed.proofVerdict).toBe("exploited");
    expect(parsed.bypassAttempts).toEqual(["Direct injection", "Encoding bypass"]);
  });

  it("handles missing proof fields gracefully", () => {
    const parsed = parseVerificationOutput({
      fingerprint: "verify-fp",
      exploitable: false,
      poc_payload: null,
      poc_description: "not exploitable",
      attack_vector: null,
      preconditions: [],
      confidence: 0.3,
    }, "fallback");

    expect(parsed.proofLevel).toBeUndefined();
    expect(parsed.proofVerdict).toBeUndefined();
    expect(parsed.bypassAttempts).toBeUndefined();
  });

  it("normalizes invalid proof_verdict to undefined", () => {
    const parsed = parseVerificationOutput({
      fingerprint: "verify-fp",
      exploitable: false,
      poc_payload: null,
      poc_description: "desc",
      attack_vector: null,
      preconditions: [],
      confidence: 0.5,
      proof_level: 5,
      proof_verdict: "invalid_verdict",
    }, "fallback");

    expect(parsed.proofLevel).toBeUndefined(); // 5 is out of range
    expect(parsed.proofVerdict).toBeUndefined();
  });
});

describe("verifyFindingWithAgent", () => {
  it("captures total cost and passes schema/tools to runtime", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [{
        type: "result",
        subtype: "success",
        result: "{}",
        structuredOutput: {
          fingerprint: "verify-fp",
          exploitable: true,
          poc_payload: "' OR 1=1 --",
          poc_description: "Inject payload in username",
          attack_vector: "Form input",
          preconditions: ["Reachable endpoint"],
          confidence: 0.9,
        },
        totalCostUsd: 0.0142,
      }],
      requests,
    );

    const output = await verifyFindingWithAgent(
      makeFinding(),
      makeTriageResult(),
      "/tmp/repo",
      "repo",
      "claude-haiku-4-5-20251001",
      { runtime },
    );

    expect(output.result.exploitable).toBe(true);
    expect(output.costUsd).toBe(0.0142);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.options?.allowedTools).toEqual(["Read", "Glob", "Grep", "GetCallers", "GetCallees", "GetFunctionBody", "GoToDefinition", "FindReferences", "TypeAtPosition"]);
    expect(requests[0]?.options?.outputFormat?.schema).toBe(VERIFICATION_RESULT_SCHEMA);

  });

  it("uses semantic navigation tools when the runtime is pi-ai", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [{
        type: "result",
        subtype: "success",
        result: "{}",
        structuredOutput: {
          fingerprint: "verify-fp",
          exploitable: true,
          poc_payload: "payload",
          poc_description: "desc",
          attack_vector: "network",
          preconditions: [],
          confidence: 0.9,
        },
      }],
      requests,
      "pi-ai",
    );

    await verifyFindingWithAgent(
      makeFinding(),
      makeTriageResult(),
      "/tmp/repo",
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
  });

  it("throws VerificationExecutionError with cost on parse failure", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [{
        type: "result",
        subtype: "success",
        result: "not-json",
        totalCostUsd: 0.009,
      }],
      requests,
    );

    await expect(
      verifyFindingWithAgent(
        makeFinding(),
        makeTriageResult(),
        "/tmp/repo",
        "repo",
        "claude-haiku-4-5-20251001",
        { runtime },
      ),
    ).rejects.toMatchObject({
      name: "VerificationExecutionError",
      message: expect.stringContaining("verification output parse failed"),
      costUsd: 0.009,
    });
  });
});

describe("verifyFindingsBatch", () => {
  it("reports missing findings without synthesizing not-exploitable results", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [{
        type: "result",
        subtype: "success",
        result: "{}",
        structuredOutput: {
          results: [{
            fingerprint: "verify-fp",
            exploitable: true,
            poc_payload: "payload",
            poc_description: "desc",
            attack_vector: "query",
            preconditions: [],
            confidence: 0.9,
          }],
        },
        durationMs: 100,
        numTurns: 1,
        totalCostUsd: 0.02,
      }],
      requests,
      "mock-batch-runtime",
    );

    const output = await verifyFindingsBatch(
      [
        { finding: makeFinding(), triageResult: makeTriageResult() },
        {
          finding: { ...makeFinding(), fingerprint: "verify-fp-2" },
          triageResult: { ...makeTriageResult(), fingerprint: "verify-fp-2" },
        },
      ],
      "/tmp/repo",
      "repo",
      "model",
      undefined,
      { runtime },
    );

    expect(output.results.size).toBe(1);
    expect(output.results.get("verify-fp")?.exploitable).toBe(true);
    expect(output.results.has("verify-fp-2")).toBe(false);
    expect(output.incomplete).toBe(true);
    expect(output.missingFingerprints).toEqual(["verify-fp-2"]);
    expect(output.recoveredByRetry).toEqual([]);
  });
});
